"""B4.4.1: application delivery handoff, consumption and WINDOW_UPDATE.

Production B does not parse AUTH/chat/file payloads or invoke A callbacks.
These tests verify a deliberately small, locked application/transport ABI.
"""
from __future__ import annotations

import socket
import threading
import unittest

from client.core.udp_connection import UDPRegistrationClient
from common.constants import DATA, REGISTER, REGISTER_OK, WINDOW_UPDATE
from common.reliable_receive import ReliableReceiveState
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    decode_packet, decode_window_update_body, encode_data_body, encode_packet,
)
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService

C2S = b'C' * 32
S2C = b'D' * 32
ENDPOINT = ('127.0.0.1', 12345)


class PureDeliveryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.cid = 4321
        self.rx = ReliableReceiveState(TransportConnectionState(self.cid))
        self.pn = 0

    def data(self, *, stream_id=1, offset=0, data=b'hello', fin=False):
        pn = self.pn
        self.pn += 1
        p = encode_packet(C2S, DATA, self.cid, pn,
                          encode_data_body(stream_id, offset, int(fin), data))
        return self.rx.accept(p, key=C2S, endpoint=ENDPOINT,
                              bound_endpoint=ENDPOINT, now_ms=1000.0 + pn)

    def test_receive_does_not_auto_grant_credit(self):
        self.data()
        self.assertEqual(self.rx.delivery_count, 1)
        self.assertEqual(self.rx.flow.pending_stream_ids, ())
        self.assertEqual(self.rx.streams._receive_state(1).advertised_max_offset, 65536)

    def test_cannot_confirm_bytes_still_in_delivery_queue(self):
        self.data()
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.rx.confirm_consumed(1, 5)
        self.assertEqual(self.rx.flow.pending_stream_ids, ())

    def test_pop_is_not_consumption_and_full_confirm_queues_credit(self):
        self.data()
        d = self.rx.pop_delivery()
        assert d is not None
        self.assertEqual(d.data, b'hello')
        self.assertEqual(self.rx.flow.pending_stream_ids, ())
        self.assertEqual(self.rx.streams._receive_state(1).advertised_max_offset, 65536)
        self.assertTrue(self.rx.confirm_consumed(1, d.offset + len(d.data)))
        self.assertEqual(self.rx.streams._receive_state(1).advertised_max_offset, 65541)
        self.assertEqual(self.rx.flow.pending_stream_ids, (1,))

    def test_partial_confirmation_advances_credit_incrementally(self):
        self.data()
        self.rx.pop_delivery()
        self.assertTrue(self.rx.confirm_consumed(1, 2))
        self.assertEqual(self.rx.streams._receive_state(1).advertised_max_offset, 65538)
        self.assertTrue(self.rx.confirm_consumed(1, 5))
        self.assertEqual(self.rx.streams._receive_state(1).advertised_max_offset, 65541)

    def test_cannot_confirm_next_delivery_before_popping_it(self):
        self.data(data=b'abc')
        self.data(offset=3, data=b'def')
        first = self.rx.pop_delivery()
        assert first is not None
        self.assertEqual(first.data, b'abc')
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.rx.confirm_consumed(1, 6)
        self.assertTrue(self.rx.confirm_consumed(1, 3))
        second = self.rx.pop_delivery()
        assert second is not None
        self.assertEqual(second.offset, 3)
        self.assertTrue(self.rx.confirm_consumed(1, 6))

    def test_handoff_is_per_stream(self):
        self.data(stream_id=0, data=b'auth')
        self.data(stream_id=1, data=b'chat')
        d = self.rx.pop_delivery()
        assert d is not None
        self.assertEqual(d.stream_id, 0)
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.rx.confirm_consumed(1, 4)
        self.assertTrue(self.rx.confirm_consumed(0, 4))
        self.assertEqual(self.rx.flow.pending_stream_ids, (0,))

    def test_duplicate_idempotent_and_backward_offset_rejected(self):
        self.data()
        self.rx.pop_delivery()
        self.assertTrue(self.rx.confirm_consumed(1, 5))
        self.assertFalse(self.rx.confirm_consumed(1, 5))
        with self.assertRaisesRegex(ValueError, 'backwards'):
            self.rx.confirm_consumed(1, 3)

    def test_bad_offsets_and_stream_ids_rejected(self):
        for sid, offset in [(True, 1), (-1, 1), (1, -1), (1, 1.5), (1, True),
                            (1 << 32, 0), (1, 1 << 64)]:
            with self.subTest(sid=sid, offset=offset), self.assertRaises(ValueError):
                self.rx.confirm_consumed(sid, offset)

    def test_replay_duplicate_does_not_create_second_delivery(self):
        self.data(data=b'once')
        d = self.rx.pop_delivery()
        assert d is not None
        repeat = encode_packet(C2S, DATA, self.cid, 0,
                               encode_data_body(1, 0, 0, b'once'))
        result = self.rx.accept(repeat, key=C2S, endpoint=ENDPOINT,
                                bound_endpoint=ENDPOINT, now_ms=1001)
        assert result is not None
        self.assertTrue(result.duplicate)
        self.assertIsNone(self.rx.pop_delivery())
        self.assertTrue(self.rx.confirm_consumed(1, 4))
        self.assertFalse(self.rx.confirm_consumed(1, 4))

    def test_out_of_order_data_not_confirmable_before_gap_closes(self):
        result = self.data(offset=3, data=b'def')
        assert result is not None
        self.assertFalse(result.delivery_enqueued)
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.rx.confirm_consumed(1, 6)
        self.data(offset=0, data=b'abc')
        d = self.rx.pop_delivery()
        assert d is not None
        self.assertEqual(d.data, b'abcdef')
        self.assertTrue(self.rx.confirm_consumed(1, 6))

    def test_fin_only_does_not_grant_new_byte_credit(self):
        self.data(data=b'', fin=True)
        d = self.rx.pop_delivery()
        assert d is not None
        self.assertTrue(d.fin)
        self.assertEqual(d.data, b'')
        self.assertFalse(self.rx.confirm_consumed(1, 0))
        self.assertEqual(self.rx.flow.pending_stream_ids, ())

    def test_unopened_file_stream_cannot_be_credited(self):
        with self.assertRaisesRegex(ValueError, 'not open'):
            self.rx.confirm_consumed(2, 0)

    def test_delivery_byte_count_remains_bounded_and_pop_releases_it(self):
        self.data(data=b'bounded')
        self.assertEqual(self.rx.delivery_bytes, 7)
        self.rx.pop_delivery()
        self.assertEqual(self.rx.delivery_bytes, 0)
        self.assertEqual(self.rx.flow.pending_stream_ids, ())


class ServerDeliveryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(bootstrap_timeout_s=8,
                                        auth_timeout_s=8, idle_timeout_s=8,
                                        password_verifier=lambda _u, _p: False)
        session = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                                 c2s_key=C2S, s2c_key=S2C)
        self.cid = session.conn_id
        self.server = UDPTransportService(self.registry, host='127.0.0.1', port=0,
                                          logger=None, auto_drive=False)
        self.peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.peer.bind(('127.0.0.1', 0))
        self.peer.settimeout(0.25)
        register = encode_packet(C2S, REGISTER, self.cid, 0)
        self.peer.sendto(register, ('127.0.0.1', self.server.port))
        self.server.serve_once()
        reply, _ = self.peer.recvfrom(1201)
        self.assertEqual(decode_packet(S2C, reply)[0], REGISTER_OK)

    def tearDown(self):
        self.server.stop()
        self.peer.close()

    def send_data(self, pn=1, data=b'server-app'):
        p = encode_packet(C2S, DATA, self.cid, pn,
                          encode_data_body(1, 0, 0, data))
        self.peer.sendto(p, ('127.0.0.1', self.server.port))
        self.server.serve_once()

    def test_server_handoff_and_confirmation_sends_real_window_update(self):
        self.send_data(data=b'abc')
        r = self.server.get_reliable_receiver(self.cid)
        assert r is not None
        self.assertEqual(r.flow.pending_stream_ids, ())
        delivery = self.server.pop_reliable_delivery(self.cid)
        assert delivery is not None
        self.assertEqual((delivery.stream_id, delivery.offset, delivery.data), (1, 0, b'abc'))
        self.assertEqual(r.flow.pending_stream_ids, ())
        self.assertTrue(self.server.confirm_consumed(self.cid, 1, 3))
        self.assertEqual(r.flow.pending_stream_ids, (1,))
        plan = self.server.send_reliable_once(self.cid)
        assert plan is not None
        self.assertEqual(plan.kind, 'window_update')
        wire, _ = self.peer.recvfrom(1201)
        kind, cid, _, body = decode_packet(S2C, wire)
        self.assertEqual((kind, cid), (WINDOW_UPDATE, self.cid))
        self.assertEqual(decode_window_update_body(body), (1, 65539))

    def test_server_cannot_confirm_before_pop(self):
        self.send_data()
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.server.confirm_consumed(self.cid, 1, 10)
        self.assertEqual(self.server.get_reliable_receiver(self.cid).flow.pending_stream_ids, ())

    def test_server_close_tombstone_cancels_bridge(self):
        self.send_data()
        self.assertTrue(self.server.remove_connection(self.cid))
        self.assertIsNone(self.server.pop_reliable_delivery(self.cid))
        with self.assertRaises(RuntimeError):
            self.server.confirm_consumed(self.cid, 1, 10)

    def test_registry_close_blocks_handoff_without_waiting_for_coordinator(self):
        self.send_data()
        self.registry.close(self.cid, reason='logout')
        self.assertIsNone(self.server.pop_reliable_delivery(self.cid))
        with self.assertRaises(RuntimeError):
            self.server.confirm_consumed(self.cid, 1, 10)

    def test_server_confirmation_rejects_overshoot_and_keeps_credit(self):
        self.send_data(data=b'abc')
        self.server.pop_reliable_delivery(self.cid)
        with self.assertRaises(ValueError):
            self.server.confirm_consumed(self.cid, 1, 5)
        self.assertTrue(self.server.confirm_consumed(self.cid, 1, 3))


class ClientDeliveryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(bootstrap_timeout_s=8,
                                        auth_timeout_s=8, idle_timeout_s=8,
                                        password_verifier=lambda _u, _p: False)
        session = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                                 c2s_key=C2S, s2c_key=S2C)
        self.cid = session.conn_id
        self.server = UDPTransportService(self.registry, host='127.0.0.1', port=0,
                                          logger=None, auto_drive=False)
        self.client = UDPRegistrationClient(host='127.0.0.1', udp_port=self.server.port,
                                            conn_id=self.cid, c2s_key=C2S,
                                            s2c_key=S2C, bind_host='127.0.0.1')
        server_once = threading.Thread(target=self.server.serve_once, daemon=True)
        server_once.start()
        self.client.register(attempts=2, wait_s=0.2)
        server_once.join(timeout=1)
        self.assertFalse(server_once.is_alive())

    def tearDown(self):
        self.client.close()
        self.server.stop()

    def send_server_data(self, data=b'client-app'):
        self.server.queue_reliable_bytes(self.cid, 1, data)
        plan = self.server.send_reliable_once(self.cid)
        assert plan is not None
        self.assertEqual(plan.kind, 'new_data')
        outcome = self.client.receive_reliable_once(timeout_s=0.25)
        assert outcome is not None
        self.assertTrue(outcome.delivery_enqueued)

    def test_client_handoff_and_confirmation_advertises_credit_over_udp(self):
        self.send_server_data(b'xyz')
        r = self.client.reliable_receiver
        assert r is not None
        self.assertEqual(r.flow.pending_stream_ids, ())
        d = self.client.pop_reliable_delivery()
        assert d is not None
        self.assertEqual(d.data, b'xyz')
        self.assertEqual(r.flow.pending_stream_ids, ())
        self.assertTrue(self.client.confirm_consumed(d.stream_id, d.offset + len(d.data)))
        self.assertEqual(r.flow.pending_stream_ids, (1,))
        plan = self.client.send_reliable_once()
        assert plan is not None
        self.assertEqual(plan.kind, 'window_update')
        self.server.serve_once()
        srv = self.server.get_reliable_receiver(self.cid)
        assert srv is not None
        self.assertEqual(srv.streams._send_state(1).advertised_max_offset, 65539)

    def test_client_cannot_confirm_before_pop(self):
        self.send_server_data(b'xyz')
        with self.assertRaisesRegex(ValueError, 'not handed off'):
            self.client.confirm_consumed(1, 3)

    def test_client_can_ack_partial_progress_after_pop(self):
        self.send_server_data(b'abcde')
        self.client.pop_reliable_delivery()
        self.assertTrue(self.client.confirm_consumed(1, 2))
        self.assertTrue(self.client.confirm_consumed(1, 5))
        self.assertFalse(self.client.confirm_consumed(1, 5))

    def test_client_closed_disallows_consumption(self):
        self.send_server_data(b'abc')
        self.client.pop_reliable_delivery()
        self.client.close()
        with self.assertRaises(RuntimeError):
            self.client.confirm_consumed(1, 3)


if __name__ == '__main__':
    unittest.main()
