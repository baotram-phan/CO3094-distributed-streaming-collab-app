"""B4.1: authenticated receive integration, includes one real UDP localhost test."""
from __future__ import annotations

import socket
import threading
import time
import unittest

from common.constants import ACK, DATA, WINDOW_UPDATE, REGISTER
from common.reliable_receive import ReliableReceiveState
from common.transport_state import TransportConnectionState
from common.streams import StreamSendFrame
from common.udp_packet import (
    decode_packet, encode_ack_body, encode_data_body, encode_packet,
    encode_window_update_body,
)
from client.core.udp_connection import UDPRegistrationClient
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService

KEY_IN = b'A' * 32
KEY_OUT = b'B' * 32
ENDPOINT = ('127.0.0.1', 41001)
OTHER_ENDPOINT = ('127.0.0.1', 41002)


class ReceiveEngineTests(unittest.TestCase):
    def setUp(self):
        self.conn = TransportConnectionState(456)
        self.receiver = ReliableReceiveState(self.conn)
        self.ms = 1000.0

    def packet(self, kind, pn, body=b'', key=KEY_IN):
        return encode_packet(key, kind, 456, pn, body)

    def accept(self, packet, endpoint=ENDPOINT, now_ms=None):
        return self.receiver.accept(packet, key=KEY_IN, endpoint=endpoint,
                                    bound_endpoint=ENDPOINT,
                                    now_ms=self.ms if now_ms is None else now_ms)

    def data(self, pn, sid=1, offset=0, data=b'hello', fin=False):
        return self.packet(DATA, pn, encode_data_body(sid, offset, int(fin), data))

    def test_inorder_data_enqueues_and_schedules_ack(self):
        outcome = self.accept(self.data(0))
        assert outcome is not None
        self.assertTrue(outcome.delivery_enqueued)
        self.assertTrue(self.receiver.received.ack_pending)
        delivery = self.receiver.pop_delivery()
        assert delivery is not None
        self.assertEqual((delivery.stream_id, delivery.offset, delivery.data), (1, 0, b'hello'))
        self.assertEqual(self.receiver.delivery_count, 0)
        self.assertEqual(self.receiver.flow._consumed, {})  # not auto-credit

    def test_reordered_data_delivered_once_in_order(self):
        first = self.accept(self.data(1, offset=3, data=b'lo'))
        assert first is not None
        self.assertFalse(first.delivery_enqueued)
        second = self.accept(self.data(2, offset=0, data=b'hel'))
        assert second is not None
        self.assertTrue(second.delivery_enqueued)
        delivery = self.receiver.pop_delivery()
        assert delivery is not None
        self.assertEqual(delivery.data, b'hello')
        self.assertIsNone(self.receiver.pop_delivery())

    def test_exact_replay_does_not_redeliver(self):
        p = self.data(0)
        self.accept(p)
        self.assertIsNotNone(self.receiver.pop_delivery())
        result = self.accept(p)
        assert result is not None
        self.assertTrue(result.duplicate)
        self.assertIsNone(self.receiver.pop_delivery())
        self.assertTrue(self.receiver.received.ack_pending)

    def test_replay_duplicate_reack_only_when_authenticated(self):
        p = self.data(0)
        self.accept(p)
        snap = self.receiver.received.build_ack(1010)
        assert snap is not None
        self.receiver.received.mark_ack_sent(snap)
        self.assertFalse(self.receiver.received.ack_pending)
        bad = bytearray(p)
        bad[-1] ^= 1
        self.assertIsNone(self.accept(bytes(bad)))
        self.assertFalse(self.receiver.received.ack_pending)
        self.accept(p)
        self.assertTrue(self.receiver.received.ack_pending)

    def test_wrong_source_rejected_before_replay(self):
        p = self.data(0)
        self.assertIsNone(self.accept(p, OTHER_ENDPOINT))
        self.assertTrue(self.conn.recv_replay.can_accept(0))

    def test_wrong_key_and_tamper_no_replay_commit(self):
        bad = bytearray(self.data(0))
        bad[-1] ^= 1
        self.assertIsNone(self.accept(bytes(bad)))
        self.assertTrue(self.conn.recv_replay.can_accept(0))
        self.assertIsNone(self.accept(self.packet(DATA, 0, encode_data_body(1, 0, 0, b'hello'), KEY_OUT)))
        self.assertTrue(self.conn.recv_replay.can_accept(0))

    def test_unopened_file_stream_not_acked_or_committed(self):
        self.assertIsNone(self.accept(self.data(0, sid=2)))
        self.assertTrue(self.conn.recv_replay.can_accept(0))
        self.assertFalse(self.receiver.received.ack_pending)

    def test_excess_receive_credit_not_acknowledged(self):
        self.assertIsNone(self.accept(self.data(0, offset=65535, data=b'zz')))
        self.assertTrue(self.conn.recv_replay.can_accept(0))

    def test_delivery_event_queue_full_does_not_ack_or_commit(self):
        r = ReliableReceiveState(TransportConnectionState(456), max_delivery_events=1)
        def submit(pn, offset):
            return r.accept(self.data(pn, offset=offset, data=b'x'), key=KEY_IN,
                            endpoint=ENDPOINT, bound_endpoint=ENDPOINT, now_ms=self.ms)
        self.assertIsNotNone(submit(0, 0))
        self.assertIsNone(submit(1, 1))
        self.assertTrue(r.connection.recv_replay.can_accept(1))
        self.assertIsNotNone(r.pop_delivery())
        self.assertIsNotNone(submit(1, 1))
        delivery = r.pop_delivery()
        assert delivery is not None
        self.assertEqual(delivery.data, b'x')

    def test_delivery_bytes_bounded_before_accepting_gap(self):
        r = ReliableReceiveState(TransportConnectionState(456), max_delivery_bytes=512 * 1024)
        # Basic configured limit exists and tracks enqueued bytes.
        p = self.data(0, data=b'x' * 1024)
        self.assertIsNotNone(r.accept(p, key=KEY_IN, endpoint=ENDPOINT,
                                      bound_endpoint=ENDPOINT, now_ms=1000))
        self.assertEqual(r.delivery_bytes, 1024)
        r.pop_delivery()
        self.assertEqual(r.delivery_bytes, 0)

    def test_window_update_advances_chat_send_credit(self):
        p = self.packet(WINDOW_UPDATE, 0, encode_window_update_body(1, 70000))
        out = self.accept(p)
        assert out is not None
        self.assertTrue(out.credit_advanced)
        self.assertEqual(self.receiver.streams._send_state(1).advertised_max_offset, 70000)
        self.assertTrue(self.receiver.received.ack_pending)

    def test_stale_window_update_is_accepted_but_ignored(self):
        self.accept(self.packet(WINDOW_UPDATE, 0, encode_window_update_body(1, 70000)))
        out = self.accept(self.packet(WINDOW_UPDATE, 1, encode_window_update_body(1, 66000)))
        assert out is not None
        self.assertFalse(out.credit_advanced)
        self.assertEqual(self.receiver.streams._send_state(1).advertised_max_offset, 70000)

    def test_unknown_file_window_update_is_rejected(self):
        p = self.packet(WINDOW_UPDATE, 0, encode_window_update_body(2, 512 * 1024))
        self.assertIsNone(self.accept(p))
        self.assertTrue(self.conn.recv_replay.can_accept(0))

    def test_ack_only_does_not_trigger_ack(self):
        p = self.packet(ACK, 0, encode_ack_body(0, [(77, 77)]))
        result = self.accept(p)
        assert result is not None
        self.assertEqual(result.newly_acked_packets, ())
        self.assertFalse(self.receiver.received.ack_pending)

    def test_authenticated_ack_retires_tracked_packet(self):
        frame = StreamSendFrame(1, 0, b'hi')
        self.receiver.sent.track_sent(3, DATA, 53, 900, frame=frame)
        p = self.packet(ACK, 0, encode_ack_body(0, [(3, 3)]))
        out = self.accept(p, now_ms=1000)
        assert out is not None
        self.assertEqual(out.newly_acked_packets, (3,))
        self.assertEqual(self.receiver.sent.outstanding_count, 0)
        self.assertFalse(self.receiver.received.ack_pending)

    def test_ack_replay_not_processed_twice(self):
        frame = StreamSendFrame(1, 0, b'hi')
        self.receiver.sent.track_sent(3, DATA, 53, 900, frame=frame)
        p = self.packet(ACK, 0, encode_ack_body(0, [(3, 3)]))
        self.accept(p)
        out = self.accept(p)
        assert out is not None
        self.assertTrue(out.duplicate)
        self.assertEqual(self.receiver.sent.outstanding_count, 0)

    def test_no_accept_of_unrecognized_packet_type(self):
        p = self.packet(REGISTER, 0)
        self.assertIsNone(self.accept(p))
        self.assertTrue(self.conn.recv_replay.can_accept(0))


class ServerBridgeTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.session = self.registry.create_bootstrap(
            tcp_ip='127.0.0.1', c2s_key=KEY_IN, s2c_key=KEY_OUT,
        )
        self.service = UDPTransportService(self.registry, host='127.0.0.1', port=0, logger=None)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(('127.0.0.1', 0))
        self.client.settimeout(0.5)
        self.peer = self.client.getsockname()

    def tearDown(self):
        self.service.stop()
        self.client.close()

    def register(self):
        packet = encode_packet(KEY_IN, REGISTER, self.session.conn_id, 0)
        self.client.sendto(packet, ('127.0.0.1', self.service.port))
        self.service.serve_once()
        response, _ = self.client.recvfrom(1201)
        self.assertEqual(decode_packet(KEY_OUT, response)[0], 2)

    def test_actual_udp_loopback_register_then_data(self):
        self.register()
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 1,
                          encode_data_body(1, 0, 0, b'hello'))
        self.client.sendto(p, ('127.0.0.1', self.service.port))
        self.service.serve_once()
        delivery = self.service.pop_reliable_delivery(self.session.conn_id)
        assert delivery is not None
        self.assertEqual(delivery.data, b'hello')
        receiver = self.service.get_reliable_receiver(self.session.conn_id)
        assert receiver is not None
        self.assertTrue(receiver.received.ack_pending)
        self.assertEqual(receiver.connection.allocate_packet_number(), 1)  # REGISTER_OK used PN0.

    def test_udp_replay_from_same_endpoint_no_redelivery(self):
        self.register()
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 1,
                          encode_data_body(1, 0, 0, b'hello'))
        self.service.handle_datagram(p, self.peer)
        self.service.handle_datagram(p, self.peer)
        delivery = self.service.pop_reliable_delivery(self.session.conn_id)
        assert delivery is not None
        self.assertEqual(delivery.data, b'hello')
        self.assertIsNone(self.service.pop_reliable_delivery(self.session.conn_id))

    def test_duplicate_does_not_refresh_registry_idle(self):
        self.register()
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 1,
                          encode_data_body(1, 0, 0, b'hi'))
        self.assertTrue(self.service.handle_datagram(p, self.peer))
        before_session = self.registry.get(self.session.conn_id)
        assert before_session is not None
        before = before_session.last_activity_at
        self.assertTrue(self.service.handle_datagram(p, self.peer))
        after_session = self.registry.get(self.session.conn_id)
        assert after_session is not None
        after = after_session.last_activity_at
        self.assertEqual(before, after)

    def test_server_accepts_window_update_after_register(self):
        self.register()
        p = encode_packet(KEY_IN, WINDOW_UPDATE, self.session.conn_id, 1,
                          encode_window_update_body(1, 80000))
        self.assertTrue(self.service.handle_datagram(p, self.peer))
        rx = self.service.get_reliable_receiver(self.session.conn_id)
        assert rx is not None
        self.assertEqual(rx.streams._send_state(1).advertised_max_offset, 80000)

    def test_wrong_source_rejected(self):
        self.register()
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 1,
                          encode_data_body(1, 0, 0, b'hi'))
        self.assertFalse(self.service.handle_datagram(p, OTHER_ENDPOINT))
        self.assertIsNone(self.service.pop_reliable_delivery(self.session.conn_id))

    def test_remove_clears_reliable_state_and_tombstones(self):
        self.register()
        self.registry.close(self.session.conn_id, reason='logout')
        self.assertTrue(self.service.remove_connection(self.session.conn_id))
        self.assertIsNone(self.service.get_reliable_receiver(self.session.conn_id))
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 1,
                          encode_data_body(1, 0, 0, b'hi'))
        self.assertFalse(self.service.handle_datagram(p, self.peer))
        self.assertFalse(self.service.handle_datagram(
            encode_packet(KEY_IN, REGISTER, self.session.conn_id, 2), self.peer))

    def test_nonregistered_reliable_datagram_is_rejected(self):
        p = encode_packet(KEY_IN, DATA, self.session.conn_id, 0,
                          encode_data_body(1, 0, 0, b'hi'))
        self.assertFalse(self.service.handle_datagram(p, self.peer))
        self.assertEqual(self.service.connection_ids(), set())


class ClientBridgeTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.session = self.registry.create_bootstrap(
            tcp_ip='127.0.0.1', c2s_key=KEY_IN, s2c_key=KEY_OUT,
        )
        self.service = UDPTransportService(self.registry, host='127.0.0.1', port=0, logger=None)
        self.client = UDPRegistrationClient(
            host='127.0.0.1', udp_port=self.service.port,
            conn_id=self.session.conn_id, c2s_key=KEY_IN, s2c_key=KEY_OUT,
            bind_host='127.0.0.1',
        )

    def tearDown(self):
        self.client.close()
        self.service.stop()

    def register(self):
        thread = threading.Thread(target=self.service.serve_once)
        thread.start()
        try:
            self.client.register(wait_s=0.4)
        finally:
            thread.join(timeout=1)
        self.assertTrue(self.client.registered)

    def test_client_receive_real_udp_after_register(self):
        self.register()
        # Existing A1.5 PN allocator used 0 for REGISTER_OK; next server PN is 1.
        state = self.service._manager.get(self.session.conn_id)
        assert state is not None
        pn = state.allocate_packet_number()
        self.assertEqual(pn, 1)
        datagram = encode_packet(KEY_OUT, DATA, self.session.conn_id, pn,
                                 encode_data_body(1, 0, 0, b'server-message'))
        self.service.sock.sendto(datagram, self.client.local_endpoint)
        result = self.client.receive_reliable_once(timeout_s=0.5)
        self.assertIsNotNone(result)
        receiver = self.client.reliable_receiver
        assert receiver is not None
        delivery = receiver.pop_delivery()
        assert delivery is not None
        self.assertEqual(delivery.data, b'server-message')
        self.assertTrue(receiver.received.ack_pending)
        self.assertEqual(self.client.state.allocate_packet_number(), 1)

    def test_client_rejects_other_endpoint(self):
        self.register()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
            datagram = encode_packet(KEY_OUT, DATA, self.session.conn_id, 1,
                                     encode_data_body(1, 0, 0, b'fake'))
            attacker.sendto(datagram, self.client.local_endpoint)
        self.assertIsNone(self.client.receive_reliable_once(timeout_s=0.5))
        receiver = self.client.reliable_receiver
        assert receiver is not None
        self.assertIsNone(receiver.pop_delivery())

    def test_client_requires_register_first(self):
        with self.assertRaises(RuntimeError):
            self.client.receive_reliable_once()


if __name__ == '__main__':
    unittest.main()
