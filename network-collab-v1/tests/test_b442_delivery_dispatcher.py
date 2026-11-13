"""B4.4.2: application callback bridge, strict consumption and lifecycle."""
from __future__ import annotations

from collections import deque
import socket
import threading
import time
import unittest

from common.constants import DATA, REGISTER, REGISTER_OK, WINDOW_UPDATE
from common.streams import StreamDelivery
from common.udp_packet import decode_packet, decode_window_update_body, encode_data_body, encode_packet
from server.reliable_dispatcher import (
    APPLICATION_EXCEPTION, APPLICATION_REJECTED, CONSUMPTION_CONFIRM_FAILED,
    ReliableDeliveryDispatcher, bind_application_bridge,
)
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService

C2S = b'C' * 32
S2C = b'D' * 32


def eventually(predicate, timeout=1.0):
    limit = time.monotonic() + timeout
    while time.monotonic() < limit:
        if predicate():
            return True
        time.sleep(0.005)
    return bool(predicate())


class FakeTransport:
    """Enforces the public adapter ABI, without any real network."""

    def __init__(self):
        self.lock = threading.Lock()
        self.queues: dict[int, deque[StreamDelivery]] = {}
        self.living: set[int] = set()
        self.confirmations: list[tuple[int, int, int]] = []
        self.enqueued: list[tuple[int, int, bytes]] = []
        self.confirm_error: Exception | None = None

    def add(self, cid, *deliveries):
        with self.lock:
            self.living.add(cid)
            self.queues[cid] = deque(deliveries)

    def connection_ids(self):
        with self.lock:
            return set(self.living)

    def is_delivery_connection_active(self, cid):
        with self.lock:
            return cid in self.living

    def pop_reliable_delivery(self, cid):
        with self.lock:
            q = self.queues.get(cid)
            return q.popleft() if cid in self.living and q else None

    def confirm_consumed(self, cid, stream_id, offset):
        with self.lock:
            if cid not in self.living:
                raise RuntimeError('closed')
            if self.confirm_error is not None:
                raise self.confirm_error
            self.confirmations.append((cid, stream_id, offset))
            return True

    def queue_reliable_bytes(self, cid, stream_id, frame):
        with self.lock:
            if cid not in self.living:
                raise RuntimeError('closed')
            self.enqueued.append((cid, stream_id, frame))

    def remove_connection(self, cid):
        with self.lock:
            self.living.discard(cid)


class DispatcherUnitTests(unittest.TestCase):
    def setUp(self):
        self.udp = FakeTransport()
        self.callbacks = []
        self.failures = []
        self.dispatchers = []

    def tearDown(self):
        for dispatcher in self.dispatchers:
            dispatcher.stop()

    def start(self, callback, *, worker_count=2):
        dispatcher = ReliableDeliveryDispatcher(
            self.udp, callback, worker_count=worker_count,
            poll_interval_s=0.005, on_reliable_delivery_failed=lambda cid, sid, off, code: self.failures.append((cid, sid, off, code)),
        )
        self.dispatchers.append(dispatcher)
        dispatcher.start()
        return dispatcher

    def test_true_confirm_exclusive_offset_and_order(self):
        self.udp.add(42, StreamDelivery(1, 0, b'ab'), StreamDelivery(1, 2, b'cde'))
        d = self.start(lambda cid, sid, off, data, fin: self.callbacks.append((off, data)) or True)
        self.assertTrue(eventually(lambda: len(self.udp.confirmations) == 2))
        self.assertEqual(self.callbacks, [(0, b'ab'), (2, b'cde')])
        self.assertEqual(self.udp.confirmations, [(42, 1, 2), (42, 1, 5)])
        self.assertIsNone(d.pending_status(42))

    def test_false_pauses_without_credit_or_automatic_callback_retry(self):
        self.udp.add(5, StreamDelivery(0, 0, b'A'), StreamDelivery(0, 1, b'B'))
        calls = []
        d = self.start(lambda *a: calls.append(a) or False)
        self.assertTrue(eventually(lambda: d.pending_status(5) == 'rejected'))
        time.sleep(0.045)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.udp.confirmations, [])
        self.assertEqual(self.failures, [(5, 0, 0, APPLICATION_REJECTED)])
        self.assertEqual(len(self.udp.queues[5]), 1)

    def test_rejection_cannot_be_explicitly_retried_in_this_contract(self):
        self.udp.add(5, StreamDelivery(1, 0, b'abc'))
        calls = []
        d = self.start(lambda *args: calls.append(args) or False)
        self.assertTrue(eventually(lambda: d.pending_status(5) == 'rejected'))
        self.assertFalse(hasattr(d, 'resume_rejected'))
        time.sleep(0.05)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.failures, [(5, 1, 0, APPLICATION_REJECTED)])
        self.assertEqual(self.udp.confirmations, [])

    def test_exception_is_fail_stop_even_with_side_effects(self):
        self.udp.add(3, StreamDelivery(0, 0, b'auth'))
        side_effects = []
        def cb(*args):
            side_effects.append('committed')
            raise OSError('sender failed after app side effect')
        d = self.start(cb)
        self.assertTrue(eventually(lambda: d.pending_status(3) == 'failed'))
        time.sleep(0.04)
        self.assertEqual(side_effects, ['committed'])
        self.assertEqual(self.udp.confirmations, [])
        self.assertEqual(self.failures, [(3, 0, 0, APPLICATION_EXCEPTION)])
        self.assertFalse(hasattr(d, 'resume_rejected'))

    def test_finite_delivery_does_not_credit_new_bytes(self):
        self.udp.add(8, StreamDelivery(1, 8, b'', True))
        self.start(lambda *args: self.callbacks.append(args) or True)
        self.assertTrue(eventually(lambda: self.udp.confirmations == [(8, 1, 8)]))
        self.assertTrue(self.callbacks[0][-1])

    def test_session_closed_by_callback_before_confirm_drops_pending(self):
        self.udp.add(8, StreamDelivery(0, 0, b'x'))
        def cb(cid, *args):
            self.udp.remove_connection(cid)
            return True
        d = self.start(cb)
        self.assertTrue(eventually(lambda: not self.udp.connection_ids()))
        self.assertTrue(eventually(lambda: d.pending_status(8) is None))
        self.assertEqual(self.udp.confirmations, [])

    def test_close_after_callback_before_confirmation(self):
        self.udp.add(11, StreamDelivery(1, 0, b'x'))
        callback_entered = threading.Event()
        callback_release = threading.Event()
        def cb(*a):
            callback_entered.set()
            callback_release.wait(1)
            return True
        d = self.start(cb)
        self.assertTrue(callback_entered.wait(1))
        self.udp.remove_connection(11)
        callback_release.set()
        self.assertTrue(eventually(lambda: d.pending_status(11) is None))
        self.assertEqual(self.udp.confirmations, [])

    def test_confirm_failure_is_terminal_and_not_replayed(self):
        self.udp.add(4, StreamDelivery(1, 10, b'abc'))
        self.udp.confirm_error = ValueError('offset mismatch')
        count = [0]
        d = self.start(lambda *a: count.__setitem__(0, count[0] + 1) or True)
        self.assertTrue(eventually(lambda: d.pending_status(4) == 'failed'))
        time.sleep(0.035)
        self.assertEqual(count, [1])
        self.assertEqual(self.failures, [(4, 1, 10, CONSUMPTION_CONFIRM_FAILED)])

    def test_callback_runs_outside_transport_lock_in_worker_thread(self):
        self.udp.add(7, StreamDelivery(0, 0, b'hello'))
        checked = []
        def cb(*args):
            got = self.udp.lock.acquire(blocking=False)
            if got:
                self.udp.lock.release()
            checked.append((got, threading.current_thread().name))
            return True
        self.start(cb)
        self.assertTrue(eventually(lambda: self.udp.confirmations))
        self.assertEqual(checked[0][0], True)
        self.assertTrue(checked[0][1].startswith('reliable-delivery-'))

    def test_per_conn_order_with_two_shards(self):
        self.udp.add(6, *(StreamDelivery(1, x, bytes([x])) for x in range(12)))
        self.udp.add(7, *(StreamDelivery(1, x, bytes([x])) for x in range(12)))
        seen = {6: [], 7: []}
        lock = threading.Lock()
        def cb(cid, sid, off, data, fin):
            with lock:
                seen[cid].append(off)
            return True
        self.start(cb, worker_count=2)
        self.assertTrue(eventually(lambda: len(self.udp.confirmations) == 24))
        self.assertEqual(seen[6], list(range(12)))
        self.assertEqual(seen[7], list(range(12)))

    def test_stopping_or_removed_conn_does_not_leave_pending(self):
        self.udp.add(9, StreamDelivery(1, 0, b'x'))
        d = self.start(lambda *a: False)
        self.assertTrue(eventually(lambda: d.pending_status(9) == 'rejected'))
        self.udp.remove_connection(9)
        self.assertTrue(eventually(lambda: d.pending_status(9) is None))
        d.stop()
        self.assertIsNone(d.pending_status(9))

    def test_failure_handler_exception_does_not_kill_shared_worker(self):
        self.udp.add(6, StreamDelivery(1, 0, b'x'))
        self.udp.add(8, StreamDelivery(1, 0, b'y'))
        def cb(cid, *a):
            return cid == 8
        d = ReliableDeliveryDispatcher(self.udp, cb, worker_count=1,
                                        poll_interval_s=.005,
                                        on_reliable_delivery_failed=lambda *_: (_ for _ in ()).throw(RuntimeError()))
        self.dispatchers.append(d)
        d.start()
        self.assertTrue(eventually(lambda: (8, 1, 1) in self.udp.confirmations))
        self.assertEqual(d.pending_status(6), 'rejected')

    def test_bind_application_bridge_maps_streams_without_raw_sendto(self):
        self.udp.add(5)
        class ServerStub:
            def __init__(self, udp):
                self.udp_service = udp
                self.auth_service = None
                self.chat_service = None
            def attach_reliable_control(self, fn):
                assert self.auth_service is None
                self.auth_service = fn
            def attach_reliable_chat(self, fn):
                assert self.auth_service is not None
                self.chat_service = fn
            def on_reliable_stream_data(self, *args):
                return True
        a = ServerStub(self.udp)
        d = bind_application_bridge(a, worker_count=1)
        self.assertIsInstance(d, ReliableDeliveryDispatcher)
        a.auth_service(5, b'control frame')
        a.chat_service(5, b'chat frame')
        self.assertEqual(self.udp.enqueued, [(5, 0, b'control frame'), (5, 1, b'chat frame')])
        prev = (a.auth_service, a.chat_service)
        bind_application_bridge(a)
        self.assertEqual((a.auth_service, a.chat_service), prev)
        d.stop()

    def test_failure_hook_has_original_stream_and_nonzero_offset(self):
        self.udp.add(16, StreamDelivery(3, 2048, b'file-part'))
        d = self.start(lambda *_: False)
        self.assertTrue(eventually(lambda: self.failures))
        self.assertEqual(self.failures, [(16, 3, 2048, APPLICATION_REJECTED)])
        self.assertEqual(d.pending_status(16), 'rejected')
        self.assertEqual(self.udp.confirmations, [])

    def test_business_rejection_can_return_true_and_grant_credit(self):
        # AUTH_FAIL/CHAT_ERROR is a valid business response, not necessarily
        # a failure to safely accept and buffer application bytes.
        self.udp.add(16, StreamDelivery(0, 4, b'bad-password'))
        self.start(lambda *_: True)
        self.assertTrue(eventually(lambda: self.udp.confirmations))
        self.assertEqual(self.udp.confirmations, [(16, 0, 16)])
        self.assertEqual(self.failures, [])

    def test_truthy_non_boolean_result_does_not_confirm(self):
        self.udp.add(16, StreamDelivery(1, 0, b'a'))
        d = self.start(lambda *_: 1)
        self.assertTrue(eventually(lambda: d.pending_status(16) == 'rejected'))
        self.assertEqual(self.failures, [(16, 1, 0, APPLICATION_REJECTED)])
        self.assertEqual(self.udp.confirmations, [])

    def test_failure_notification_not_under_state_or_transport_lock(self):
        self.udp.add(20, StreamDelivery(1, 10, b'hi'))
        lock_status = []
        def failure(cid, sid, off, code):
            a = self.udp.lock.acquire(blocking=False)
            if a:
                self.udp.lock.release()
            b = d._state_lock.acquire(blocking=False)
            if b:
                d._state_lock.release()
            lock_status.append((a, b, cid, sid, off, code))
        d = ReliableDeliveryDispatcher(
            self.udp, lambda *_: False,
            on_reliable_delivery_failed=failure, poll_interval_s=.005,
        )
        self.dispatchers.append(d)
        d.start()
        self.assertTrue(eventually(lambda: lock_status))
        self.assertEqual(lock_status, [(True, True, 20, 1, 10, APPLICATION_REJECTED)])

    def test_sender_failure_after_side_effect_not_replayed_and_reports_coordinates(self):
        self.udp.add(21, StreamDelivery(0, 7, b'auth-data'),
                     StreamDelivery(0, 16, b'later'))
        seen = []
        def callback(cid, sid, off, data, fin):
            seen.append((off, data))
            raise OSError('send failed after application accepted and acted')
        d = self.start(callback)
        self.assertTrue(eventually(lambda: d.pending_status(21) == 'failed'))
        time.sleep(.035)
        self.assertEqual(seen, [(7, b'auth-data')])
        self.assertEqual(self.failures, [(21, 0, 7, APPLICATION_EXCEPTION)])
        self.assertEqual(self.udp.confirmations, [])
        self.assertEqual(len(self.udp.queues[21]), 1)

    def test_validation(self):
        for kwargs in [{'worker_count': 0}, {'worker_count': 17},
                       {'poll_interval_s': 0}, {'poll_interval_s': .3},
                       {'max_callbacks_per_poll': 0}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ReliableDeliveryDispatcher(self.udp, lambda *a: True, **kwargs)


class RealUdpDispatchTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(bootstrap_timeout_s=10, auth_timeout_s=10,
                                        idle_timeout_s=10,
                                        password_verifier=lambda u, p: False)
        s = self.registry.create_bootstrap(tcp_ip='127.0.0.1', c2s_key=C2S, s2c_key=S2C)
        self.cid = s.conn_id
        self.server = UDPTransportService(self.registry, host='127.0.0.1', port=0,
                                          logger=None, auto_drive=False)
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(('127.0.0.1', 0))
        self.peer.settimeout(.25)
        self.peer.sendto(encode_packet(C2S, REGISTER, self.cid, 0), ('127.0.0.1', self.server.port))
        self.server.serve_once()
        reply, _ = self.peer.recvfrom(1201)
        self.assertEqual(decode_packet(S2C, reply)[0], REGISTER_OK)
        self.dispatcher = None

    def tearDown(self):
        if self.dispatcher is not None:
            self.dispatcher.stop()
        self.server.stop()
        self.peer.close()

    def send(self, pn, stream_id, off, data):
        datagram = encode_packet(C2S, DATA, self.cid, pn,
                                 encode_data_body(stream_id, off, 0, data))
        self.peer.sendto(datagram, ('127.0.0.1', self.server.port))
        self.server.serve_once()

    def test_real_udp_callback_true_window_update_on_wire_and_no_duplicate(self):
        calls = []
        def cb(cid, sid, off, data, fin):
            calls.append((cid, sid, off, data))
            return True
        self.dispatcher = ReliableDeliveryDispatcher(self.server, cb, poll_interval_s=.005)
        self.dispatcher.start()
        self.send(1, 1, 0, b'hello')
        self.assertTrue(eventually(lambda: len(calls) == 1))
        rx = self.server.get_reliable_receiver(self.cid)
        assert rx is not None
        self.assertTrue(eventually(lambda: rx.flow.pending_stream_ids == (1,)))
        self.send(2, 1, 0, b'hello')  # unique packet number, duplicate stream offset
        time.sleep(.04)
        self.assertEqual(len(calls), 1)
        sent_window = False
        for _ in range(4):
            plan = self.server.send_reliable_once(self.cid)
            if plan is None:
                break
            packet, _ = self.peer.recvfrom(1201)
            kind, _, _, payload = decode_packet(S2C, packet)
            if kind == WINDOW_UPDATE:
                self.assertEqual(decode_window_update_body(payload), (1, 65541))
                sent_window = True
                break
        self.assertTrue(sent_window)

    def test_real_udp_reassembly_split_and_no_credit_until_true(self):
        entered = threading.Event()
        release = threading.Event()
        callback_deliveries = []
        def cb(cid, sid, off, data, fin):
            callback_deliveries.append((off, data))
            entered.set()
            release.wait(.8)
            return True
        self.dispatcher = ReliableDeliveryDispatcher(self.server, cb, poll_interval_s=.005)
        self.dispatcher.start()
        # Out of order: offset=3 buffered until missing prefix arrives.
        self.send(1, 0, 3, b'def')
        self.assertFalse(entered.wait(.03))
        self.send(2, 0, 0, b'abc')
        self.assertTrue(entered.wait(1))
        rx = self.server.get_reliable_receiver(self.cid)
        assert rx is not None
        self.assertEqual(rx.flow.pending_stream_ids, ())
        release.set()
        self.assertTrue(eventually(lambda: rx.flow.pending_stream_ids == (0,)))
        self.assertEqual(callback_deliveries, [(0, b'abcdef')])

    def test_real_udp_false_reports_4_fields_and_A_coordinator_closes(self):
        fail_events = []
        delivered = []
        def on_failed(cid, sid, off, code):
            fail_events.append((cid, sid, off, code))
            # A-only policy; B's dispatcher itself NEVER invokes Registry.close.
            self.registry.close(cid, reason='app_delivery_failure')
        self.dispatcher = ReliableDeliveryDispatcher(
            self.server,
            lambda *args: delivered.append(args) or False,
            on_reliable_delivery_failed=on_failed, poll_interval_s=.005,
        )
        self.dispatcher.start()
        rx = self.server.get_reliable_receiver(self.cid)
        assert rx is not None
        self.send(1, 0, 0, b'auth-failure')
        self.assertTrue(eventually(lambda: fail_events))
        self.assertEqual(fail_events, [(self.cid, 0, 0, APPLICATION_REJECTED)])
        self.assertEqual(len(delivered), 1)
        self.assertIsNone(self.registry.get(self.cid))
        self.assertEqual(rx.flow.pending_stream_ids, ())
        events = self.registry.drain_closed_events()  # A coordinator owns this.
        self.assertTrue(any(e.conn_id == self.cid for e in events))
        for event in events:
            self.server.remove_connection(event.conn_id)
        self.assertTrue(eventually(lambda: self.dispatcher.pending_status(self.cid) is None))
        self.assertIsNone(self.server.get_reliable_receiver(self.cid))

    def test_real_udp_false_pauses_without_A_coordinator_intervention(self):
        failed = []
        delivered = []
        self.dispatcher = ReliableDeliveryDispatcher(
            self.server,
            lambda *args: delivered.append(args) or False,
            on_reliable_delivery_failed=lambda *args: failed.append(args),
            poll_interval_s=.005,
        )
        self.dispatcher.start()
        rx = self.server.get_reliable_receiver(self.cid)
        assert rx is not None
        self.send(1, 1, 0, b'hello')
        self.assertTrue(eventually(lambda: self.dispatcher.pending_status(self.cid) == 'rejected'))
        self.send(2, 1, 5, b'world')
        time.sleep(.045)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0], (self.cid, 1, 0, APPLICATION_REJECTED))
        self.assertEqual(rx.flow.pending_stream_ids, ())

    def test_real_udp_close_during_callback_without_confirm(self):
        def cb(cid, sid, off, data, fin):
            self.registry.close(cid, reason='app_closed')
            return True
        self.dispatcher = ReliableDeliveryDispatcher(self.server, cb, poll_interval_s=.005)
        self.dispatcher.start()
        self.send(1, 1, 0, b'x')
        self.assertTrue(eventually(lambda: self.registry.get(self.cid) is None))
        rx = self.server.get_reliable_receiver(self.cid)
        assert rx is not None
        self.assertEqual(rx.flow.pending_stream_ids, ())
        self.server.remove_connection(self.cid)
        self.assertTrue(eventually(lambda: self.dispatcher.pending_status(self.cid) is None))


if __name__ == '__main__':
    unittest.main()
