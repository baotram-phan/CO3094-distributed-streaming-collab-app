"""B5.2 — real encrypted UDP PING/PONG and A-owned timeout/cleanup.

All crypto/packet-number/endpoint cases go through B's actual UDP codecs and
real localhost sockets. Fake clock is used only for deterministic A Registry
expiry, NOT for bypassing packet verification or replay.
"""
from __future__ import annotations

import socket
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeVar, cast

from client.core.udp_connection import UDPRegistrationClient
from common.constants import PING, PONG, REGISTER
from common.crypto import encrypt_payload
from common.udp_packet import (
    decode_heartbeat_body, decode_packet, encode_header, encode_heartbeat_body,
    encode_packet,
)
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionRegistry, SessionState
from server.udp_service import UDPTransportService


_T = TypeVar("_T")


def require_not_none(value: _T | None) -> _T:
    if value is None:
        raise AssertionError("Expected an existing registered session")
    return value


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestHeartbeatBody(unittest.TestCase):
    def test_timestamp_uint64_round_trip(self) -> None:
        for value in (0, 2000, (1 << 64) - 1):
            with self.subTest(value=value):
                body = encode_heartbeat_body(value)
                self.assertEqual(len(body), 8)
                self.assertEqual(decode_heartbeat_body(body), value)

    def test_invalid_heartbeat_length_and_range_rejected(self) -> None:
        for value in (-1, 1 << 64, 1.2, True, '2000', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                encode_heartbeat_body(cast(int, value))
        for body in (b'', b'\x00' * 7, b'\x00' * 9):
            with self.subTest(body=body), self.assertRaises(ValueError):
                decode_heartbeat_body(body)


class TestEncryptedHeartbeat(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.registry = SessionRegistry(clock=self.clock, password_verifier=lambda u, p: True)
        self.session = self.registry.create_bootstrap(
            tcp_ip='127.0.0.1', c2s_key=b'C' * 32, s2c_key=b'S' * 32,
        )
        self.service = UDPTransportService(self.registry, host='127.0.0.1', port=0, logger=None)
        self.client = UDPRegistrationClient(
            host='127.0.0.1', udp_port=self.service.port,
            conn_id=self.session.conn_id,
            c2s_key=self.session.c2s_key, s2c_key=self.session.s2c_key,
        )
        t = threading.Thread(target=self.service.serve_once)
        t.start()
        try:
            self.client.register(attempts=2, wait_s=0.3)
        finally:
            t.join(timeout=2)
        self.assertFalse(t.is_alive(), 'REGISTER service loop deadlocked')
        self.cid = self.session.conn_id
        bound = self.registry.get(self.cid)
        assert bound is not None and bound.udp_endpoint is not None
        self.endpoint = bound.udp_endpoint  # actual source IP from recvfrom, not 0.0.0.0 bind

    def tearDown(self) -> None:
        self.client.close()
        self.service.stop()

    def _send_ping(self, *, pn: int | None = None, timestamp: int = 2000) -> bytes:
        if pn is None:
            pn = self.client.state.allocate_packet_number()
        packet = encode_packet(self.session.c2s_key, PING, self.cid, pn, encode_heartbeat_body(timestamp))
        self.client.sock.sendto(packet, self.client.server_endpoint)
        self.service.serve_once()
        return packet

    def _read_pong(self) -> tuple[int, int]:
        pkt, endpoint = self.client.sock.recvfrom(1201)
        self.assertEqual(endpoint, self.client.server_endpoint)
        kind, conn, pn, body = decode_packet(self.session.s2c_key, pkt)
        self.assertEqual((kind, conn), (PONG, self.cid))
        return pn, decode_heartbeat_body(body)

    def test_due_ping_uses_same_keys_and_echoes_timestamp(self) -> None:
        self.clock.now = 2.0
        due = self.client._next_ping_due_ms
        self.assertIsNotNone(due)
        assert due is not None
        self.assertFalse(self.client.send_ping_once(now_ms=due - 1))
        self.assertTrue(self.client.send_ping_once(now_ms=due))
        self.assertFalse(self.client.send_ping_once(now_ms=due + 5))
        self.service.serve_once()
        result = self.client.receive_reliable_once(timeout_s=0.1)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.packet_type, PONG)
        self.assertEqual(self.client._last_pong_timestamp_ms, int(due))
        self.assertAlmostEqual(require_not_none(self.registry.get(self.cid)).last_activity_at, 2.0)
        # PONG is control, not an acknowledged reliable DATA frame.
        receiver = self.client.reliable_receiver
        self.assertIsNotNone(receiver)
        assert receiver is not None
        self.assertEqual(receiver.sent.bytes_in_flight, 0)

    def test_unbound_unknown_and_wrong_endpoint_ping_are_rejected(self) -> None:
        self.clock.now = 2.0
        payload = encode_packet(self.session.c2s_key, PING, self.cid, 15, encode_heartbeat_body(2000))
        self.assertFalse(self.service.handle_datagram(payload, ('127.0.0.1', 22222)))
        self.assertFalse(self.service.handle_datagram(payload, ('127.0.0.1', 11111)))
        self.assertAlmostEqual(require_not_none(self.registry.get(self.cid)).last_activity_at, 0.0)
        # Also reject an unsolicited PONG in the client-to-server direction.
        pong = encode_packet(self.session.c2s_key, PONG, self.cid, 16, encode_heartbeat_body(2000))
        self.assertFalse(self.service.handle_datagram(pong, self.endpoint))

    def test_tampered_ping_does_not_touch_or_consume_replay_pn(self) -> None:
        self.clock.now = 2.0
        pn = self.client.state.allocate_packet_number()
        valid = encode_packet(self.session.c2s_key, PING, self.cid, pn, encode_heartbeat_body(2000))
        bad = valid[:-1] + bytes([valid[-1] ^ 0x01])
        self.assertFalse(self.service.handle_datagram(bad, self.endpoint))
        self.assertAlmostEqual(require_not_none(self.registry.get(self.cid)).last_activity_at, 0.0)
        self.assertTrue(self.service.handle_datagram(valid, self.endpoint))
        _, echo = self._read_pong()
        self.assertEqual(echo, 2000)

    def test_correctly_encrypted_malformed_body_does_not_consume_pn(self) -> None:
        self.clock.now = 2.0
        pn = self.client.state.allocate_packet_number()
        header = encode_header(PING, self.cid, pn)
        invalid = header + encrypt_payload(self.session.c2s_key, pn, b'\x00' * 7, header)
        self.assertFalse(self.service.handle_datagram(invalid, self.endpoint))
        # No second encryption using the same AES-GCM key/nonce: inspect
        # replay directly, then use a *fresh* packet number for valid PING.
        receiver = self.service.get_reliable_receiver(self.cid)
        assert receiver is not None
        self.assertTrue(receiver.connection.recv_replay.can_accept(pn))
        valid_pn = self.client.state.allocate_packet_number()
        valid = encode_packet(self.session.c2s_key, PING, self.cid, valid_pn, encode_heartbeat_body(2000))
        self.assertTrue(self.service.handle_datagram(valid, self.endpoint))
        self.assertEqual(self._read_pong()[1], 2000)

    def test_replayed_ping_does_not_touch_or_generate_extra_pong(self) -> None:
        self.clock.now = 2.0
        packet = self._send_ping(timestamp=2000)
        self._read_pong()
        self.assertAlmostEqual(require_not_none(self.registry.get(self.cid)).last_activity_at, 2.0)
        self.clock.now = 3.0
        self.assertFalse(self.service.handle_datagram(packet, self.endpoint))
        self.assertAlmostEqual(require_not_none(self.registry.get(self.cid)).last_activity_at, 2.0)
        self.client.sock.settimeout(0.04)
        with self.assertRaises(socket.timeout):
            self.client.sock.recvfrom(1201)

    def test_ping_refreshes_idle_without_extending_auth_deadline(self) -> None:
        bound_at = require_not_none(self.registry.get(self.cid)).udp_bound_at
        for seconds in (2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28):
            self.clock.now = float(seconds)
            self._send_ping(timestamp=seconds * 1000)
            self._read_pong()
            live = self.registry.get(self.cid)
            self.assertIsNotNone(live)
            assert live is not None
            self.assertEqual(live.state, SessionState.UDP_BOUND)
            self.assertEqual(live.udp_bound_at, bound_at)
        # Even authenticated PINGs cannot keep an unauthenticated session
        # alive past 30 seconds from first UDP REGISTER.
        self.clock.now = 30.0
        valid = encode_packet(self.session.c2s_key, PING, self.cid, 99, encode_heartbeat_body(30000))
        self.assertFalse(self.service.handle_datagram(valid, self.endpoint))
        self.assertIsNone(self.registry.get(self.cid))
        events = self.registry.drain_closed_events()
        self.assertEqual([ev.reason for ev in events], ['auth_timeout'])

    def test_missing_ping_expires_session_at_ten_seconds_and_blocks_old_keys(self) -> None:
        self.clock.now = 10.0
        expired = self.registry.cleanup_expired()
        self.assertEqual(expired, [self.cid])
        events = self.registry.drain_closed_events()
        self.assertEqual([ev.reason for ev in events], ['idle_timeout'])
        self.assertTrue(self.service.remove_connection(self.cid))
        self.assertEqual(self.service.connection_ids(), set())
        self.assertFalse(self.service.remove_connection(self.cid))
        ping = encode_packet(self.session.c2s_key, PING, self.cid, 50, encode_heartbeat_body(10000))
        self.assertFalse(self.service.handle_datagram(ping, self.endpoint))
        self.assertEqual(self.service.connection_ids(), set())

    def test_client_ignores_wrong_pong_timestamp_and_invalid_aead(self) -> None:
        due = self.client._next_ping_due_ms
        self.assertIsNotNone(due)
        assert due is not None
        self.assertTrue(self.client.send_ping_once(now_ms=due))
        now = self.client._last_verified_server_ms
        self.assertIsNotNone(now)
        assert now is not None
        pn = 999
        wrong_echo = encode_packet(self.session.s2c_key, PONG, self.cid, pn,
                                   encode_heartbeat_body(int(due) + 1))
        tampered = wrong_echo[:-1] + bytes([wrong_echo[-1] ^ 0x01])
        self.service.sock.sendto(tampered, self.endpoint)
        self.assertIsNone(self.client.receive_reliable_once(timeout_s=0.1))
        self.service.sock.sendto(wrong_echo, self.endpoint)
        self.assertIsNone(self.client.receive_reliable_once(timeout_s=0.1))
        self.assertEqual(self.client._last_verified_server_ms, now)
        # Invalid/unsolicited PONG does not commit replay. Never re-encrypt a
        # *different* plaintext using the same key/packet-number (GCM nonce).
        self.assertTrue(self.client.state.recv_replay.can_accept(pn))
        valid = encode_packet(self.session.s2c_key, PONG, self.cid, pn + 1,
                              encode_heartbeat_body(int(due)))
        self.service.sock.sendto(valid, self.endpoint)
        result = self.client.receive_reliable_once(timeout_s=0.1)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.packet_type, PONG)

    def test_due_heartbeat_has_priority_under_one_packet_send_budget(self) -> None:
        self.client.queue_reliable_bytes(1, b'chat')
        self.client._next_ping_due_ms = time.monotonic() * 1000 - 1
        self.client.pump_reliable_once(timeout_s=0.001, max_packets=1)
        # Exactly one datagram: PING first, queued chat remains pending.
        self.service.serve_once()
        pong = self.client.receive_reliable_once(timeout_s=0.1)
        assert pong is not None
        self.assertEqual(pong.packet_type, PONG)
        receiver = self.service.get_reliable_receiver(self.cid)
        assert receiver is not None
        self.assertEqual(receiver.delivery_count, 0)
        self.assertEqual(require_not_none(self.client.send_reliable_once()).kind, 'new_data')
        self.service.serve_once()
        delivery = receiver.pop_delivery()
        assert delivery is not None
        self.assertEqual((delivery.stream_id, delivery.data), (1, b'chat'))

    def test_client_times_out_when_no_authenticated_server_packets_arrive(self) -> None:
        last = self.client._last_verified_server_ms
        self.assertIsNotNone(last)
        assert last is not None
        self.client._check_server_liveness(now_ms=last + 9999)
        with self.assertRaisesRegex(TimeoutError, 'bootstrap again'):
            self.client._check_server_liveness(now_ms=last + 10000)
        self.assertTrue(self.client._closed)
        with self.assertRaises(RuntimeError):
            self.client.queue_reliable_bytes(1, b'no stale session')

    def test_dropped_pong_recovers_with_new_periodic_ping(self) -> None:
        due = self.client._next_ping_due_ms
        assert due is not None
        self.clock.now = 2.0
        self.assertTrue(self.client.send_ping_once(now_ms=due))
        self.service.serve_once()
        # Network drops the first PONG after the server sent it.
        lost_pong, _ = self.client.sock.recvfrom(1201)
        self.assertEqual(decode_packet(self.session.s2c_key, lost_pong)[0], PONG)
        self.assertIsNone(self.client._last_pong_timestamp_ms)

        self.clock.now = 4.0
        self.assertTrue(self.client.send_ping_once(now_ms=due + 2000))
        self.service.serve_once()
        next_pong = self.client.receive_reliable_once(timeout_s=0.1)
        assert next_pong is not None
        self.assertEqual(next_pong.packet_type, PONG)
        self.assertEqual(self.client._last_pong_timestamp_ms, int(due + 2000))
        self.assertIsNotNone(self.registry.get(self.cid))

    def test_online_authenticated_session_stays_online_after_ping(self) -> None:
        self.clock.now = 1.0
        self.assertTrue(self.registry.authenticate_after_verified_udp(self.cid, 'alice', 'pw'))
        self.clock.now = 2.0
        self._send_ping(timestamp=2000)
        self._read_pong()
        session = self.registry.get(self.cid)
        assert session is not None
        self.assertEqual(session.state, SessionState.ONLINE)
        self.assertEqual(session.username, 'alice')

    def test_ping_does_not_change_cubic_or_reliable_offsets(self) -> None:
        self.clock.now = 2.0
        receiver = self.service.get_reliable_receiver(self.cid)
        assert receiver is not None
        cwnd = receiver.cubic.cwnd_bytes
        self._send_ping(timestamp=2000)
        self._read_pong()
        self.assertEqual(receiver.cubic.cwnd_bytes, cwnd)
        self.assertEqual(receiver.sent.bytes_in_flight, 0)
        self.assertEqual(receiver.delivery_count, 0)
        self.assertFalse(receiver.received.ack_pending)


class TestLiveAutoHeartbeat(unittest.TestCase):
    def test_actual_client_pump_keeps_idle_server_session_alive(self) -> None:
        """Real timers and UDP sockets: 2s PINGs survive 3.5s idle window."""
        registry = SessionRegistry(idle_timeout_s=3.5, auth_timeout_s=30.0,
                                   password_verifier=lambda u, p: True)
        session = registry.create_bootstrap(
            tcp_ip='127.0.0.1', c2s_key=b'C' * 32, s2c_key=b'S' * 32,
        )
        service = UDPTransportService(registry, host='127.0.0.1', port=0, logger=None)
        worker = threading.Thread(target=service.serve_forever, daemon=True)
        worker.start()
        client = UDPRegistrationClient(
            host='127.0.0.1', udp_port=service.port, conn_id=session.conn_id,
            c2s_key=session.c2s_key, s2c_key=session.s2c_key,
        )
        try:
            client.register()
            bound = registry.get(session.conn_id)
            assert bound is not None
            original_activity = bound.last_activity_at
            end = time.monotonic() + 4.3
            while time.monotonic() < end:
                client.pump_reliable_once(timeout_s=0.01, max_packets=32)
            live = registry.get(session.conn_id)
            self.assertIsNotNone(live)
            assert live is not None
            self.assertEqual(live.state, SessionState.UDP_BOUND)
            self.assertGreater(live.last_activity_at, original_activity + 1.8)
            self.assertIsNotNone(client._last_pong_timestamp_ms)
            self.assertFalse(client._closed)
        finally:
            client.close()
            service.stop()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())


class TestCoordinatorOwnsTimeoutCleanup(unittest.TestCase):
    def test_real_a_coordinator_removes_b_transport_on_idle_expiry(self) -> None:
        clock = Clock()
        registry = SessionRegistry(clock=clock, password_verifier=lambda u, p: True)
        with TemporaryDirectory() as temp:
            cert, key = generate_certificate(Path(temp))
            close_events = []
            server = CollaborationServer(
                host='127.0.0.1', tcp_port=0, udp_port=0,
                cert=cert, key=key, registry=registry, logger=None,
                enable_reliable_bridge=False, on_session_closed=close_events.append,
            )
            client = None
            try:
                session = registry.create_bootstrap(
                    tcp_ip='127.0.0.1', c2s_key=b'C' * 32, s2c_key=b'S' * 32,
                )
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.bind(('127.0.0.1', 0))
                endpoint = client.getsockname()
                register = encode_packet(session.c2s_key, REGISTER, session.conn_id, 0)
                self.assertTrue(server.udp_service.handle_datagram(register, endpoint))
                self.assertIn(session.conn_id, server.udp_service.connection_ids())
                clock.now = 10.0
                server.dispatch_closed_events()
                self.assertNotIn(session.conn_id, server.udp_service.connection_ids())
                self.assertEqual([(ev.conn_id, ev.reason) for ev in close_events],
                                 [(session.conn_id, 'idle_timeout')])
                server.dispatch_closed_events()
                self.assertEqual(len(close_events), 1)
            finally:
                if client is not None:
                    client.close()
                server.stop()


if __name__ == '__main__':
    unittest.main()
