"""B4.2.1: real UDP loopback DATA/ACK/WINDOW_UPDATE send paths and failure semantics.

Explicit send/receive calls by design. B4.3 will own the periodic pump and RTO.
"""
from __future__ import annotations

import socket
import threading
import time
import unittest
from typing import cast

from client.core.udp_connection import UDPRegistrationClient
from common.constants import ACK, DATA, WINDOW_UPDATE
from common.udp_packet import decode_header
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService


class _FailOneSend:
    """Proxy an actual bound UDP socket, fail exactly the next sendto()."""
    def __init__(self, original: socket.socket):
        self._original = original
        self._remaining = 1

    def sendto(self, packet: bytes, endpoint: tuple[str, int]) -> int:
        if self._remaining:
            self._remaining -= 1
            raise OSError("injected local UDP socket error")
        return self._original.sendto(packet, endpoint)

    def __getattr__(self, name: str):
        return getattr(self._original, name)


class RealLoopbackSendTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(
            bootstrap_timeout_s=8, idle_timeout_s=8, auth_timeout_s=8,
            password_verifier=lambda _u, _p: False,
        )
        self.c2s_key = b"A" * 32
        self.s2c_key = b"B" * 32
        self.session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=self.c2s_key, s2c_key=self.s2c_key,
        )
        self.server = UDPTransportService(
            self.registry, host="127.0.0.1", port=0, logger=None,
        )
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.client = UDPRegistrationClient(
            host="127.0.0.1", udp_port=self.server.port,
            conn_id=self.session.conn_id,
            c2s_key=self.c2s_key, s2c_key=self.s2c_key, bind_host="127.0.0.1",
        )
        self.client.register(attempts=10, wait_s=0.10)
        self.assertIsNotNone(self.client.reliable_receiver)
        self.cid = self.session.conn_id

    def tearDown(self):
        self.client.close()
        self.server.stop()
        self.server_thread.join(timeout=1.5)

    def server_receiver(self):
        receiver = self.server.get_reliable_receiver(self.cid)
        assert receiver is not None
        return receiver

    def client_receiver(self):
        receiver = self.client.reliable_receiver
        assert receiver is not None
        return receiver

    def await_server_delivery(self, timeout_s: float = 1):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            item = self.server.pop_reliable_delivery(self.cid)
            if item is not None:
                return item
            time.sleep(0.005)
        self.fail("server did not receive a stream delivery")

    def await_server_outstanding(self, expected: int, timeout_s: float = 1):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.server_receiver().sent.outstanding_count == expected:
                return
            time.sleep(0.005)
        self.fail(f"server outstanding count not {expected}")

    def test_client_to_server_data_then_server_ack_real_socket(self):
        self.client.queue_reliable_bytes(1, b"hello")
        plan = self.client.send_reliable_once()
        assert plan is not None
        self.assertEqual(plan.kind, "new_data")
        self.assertEqual(plan.stream_id, 1)
        self.assertEqual(len(plan.datagram), 56)
        self.assertEqual(self.client_receiver().sent.outstanding_count, 1)
        item = self.await_server_delivery()
        self.assertEqual((item.stream_id, item.offset, item.data), (1, 0, b"hello"))
        self.assertTrue(self.server.send_ack_once(self.cid))
        result = self.client.receive_reliable_once(timeout_s=0.5)
        assert result is not None
        self.assertEqual(result.packet_type, ACK)
        self.assertEqual(result.newly_acked_packets, (plan.packet_num,))
        self.assertEqual(self.client_receiver().sent.outstanding_count, 0)
        self.assertEqual(self.client_receiver().cubic.cwnd_bytes, 10245)
        self.assertFalse(self.client_receiver().received.ack_pending)  # ACK-only never ACKed

    def test_server_to_client_data_then_client_ack_real_socket(self):
        self.server.queue_reliable_bytes(self.cid, 1, b"world")
        plan = self.server.send_reliable_once(self.cid)
        assert plan is not None
        self.assertEqual(plan.kind, "new_data")
        result = self.client.receive_reliable_once(timeout_s=0.5)
        assert result is not None
        self.assertTrue(result.delivery_enqueued)
        item = self.client_receiver().pop_delivery()
        assert item is not None
        self.assertEqual((item.stream_id, item.offset, item.data), (1, 0, b"world"))
        self.assertTrue(self.client.send_ack_once())
        self.await_server_outstanding(0)
        self.assertEqual(self.server_receiver().cubic.cwnd_bytes, 10245)
        self.assertFalse(self.server_receiver().received.ack_pending)

    def test_send_ack_when_no_pending_returns_false_and_burns_nothing(self):
        self.assertFalse(self.client.send_ack_once())
        self.assertFalse(self.server.send_ack_once(self.cid))
        self.assertEqual(self.client_receiver().sent.outstanding_count, 0)

    def test_data_send_is_not_automatically_acknowledged(self):
        self.client.queue_reliable_bytes(1, b"hello")
        self.client.send_reliable_once()
        self.await_server_delivery()
        self.assertTrue(self.server_receiver().received.ack_pending)
        self.assertEqual(self.client_receiver().sent.outstanding_count, 1)
        self.assertEqual(self.client_receiver().cubic.cwnd_bytes, 10240)

    def test_client_window_update_after_downstream_consumption(self):
        # Server first delivers data; only after application consumption does
        # it advertise the updated receive max_offset.
        self.client.queue_reliable_bytes(1, b"abc")
        self.client.send_reliable_once()
        item = self.await_server_delivery()
        self.assertEqual(item.data, b"abc")
        with self.server._lifecycle_lock:  # simulate serialized B4.4 worker feedback
            self.server._reliable[self.cid].flow.note_consumed(1, 3)
        plan = self.server.send_reliable_once(self.cid)
        assert plan is not None
        self.assertEqual(plan.kind, "window_update")
        result = self.client.receive_reliable_once(timeout_s=0.5)
        assert result is not None
        self.assertEqual(result.packet_type, WINDOW_UPDATE)
        self.assertTrue(result.credit_advanced)
        self.assertEqual(self.client_receiver().streams._send_state(1).advertised_max_offset, 65539)
        self.assertTrue(self.client.send_ack_once())
        self.await_server_outstanding(0)

    def test_client_send_definite_socket_failure_retains_data_and_burns_pn(self):
        self.client.queue_reliable_bytes(1, b"retry")
        original = self.client.sock
        self.client.sock = cast(socket.socket, _FailOneSend(original))
        try:
            with self.assertRaisesRegex(OSError, "injected"):
                self.client.send_reliable_once()
            self.assertEqual(self.client_receiver().sent.outstanding_count, 0)
            self.assertEqual(self.client_receiver().congestion.tracked_attempts, 0)
            self.assertEqual(self.client_receiver().scheduler.staged_count, 1)
            plan = self.client.send_reliable_once()
            assert plan is not None
            assert plan.frame is not None
            self.assertEqual(plan.frame.data, b"retry")
            self.assertGreaterEqual(plan.packet_num, 2)  # REGISTER used PN 0, failed PN 1
            self.assertEqual(self.await_server_delivery().data, b"retry")
        finally:
            self.client.sock = original

    def test_server_send_definite_socket_failure_retains_data_and_burns_pn(self):
        self.server.queue_reliable_bytes(self.cid, 1, b"retry")
        original = self.server.sock
        self.server.sock = cast(socket.socket, _FailOneSend(original))
        try:
            with self.assertRaisesRegex(OSError, "injected"):
                self.server.send_reliable_once(self.cid)
            self.assertEqual(self.server_receiver().scheduler.staged_count, 1)
            self.assertEqual(self.server_receiver().sent.outstanding_count, 0)
            plan = self.server.send_reliable_once(self.cid)
            assert plan is not None
            self.assertEqual(plan.kind, "new_data")
            result = self.client.receive_reliable_once(timeout_s=0.5)
            assert result is not None
            self.assertTrue(result.delivery_enqueued)
            delivery = self.client_receiver().pop_delivery()
            assert delivery is not None
            self.assertEqual(delivery.data, b"retry")
        finally:
            self.server.sock = original

    def test_ack_send_failure_keeps_ack_pending(self):
        self.server.queue_reliable_bytes(self.cid, 1, b"hey")
        self.server.send_reliable_once(self.cid)
        out = self.client.receive_reliable_once(timeout_s=0.5)
        assert out is not None
        original = self.client.sock
        self.client.sock = cast(socket.socket, _FailOneSend(original))
        try:
            with self.assertRaises(OSError):
                self.client.send_ack_once()
            self.assertTrue(self.client_receiver().received.ack_pending)
            self.assertTrue(self.client.send_ack_once())
            self.assertFalse(self.client_receiver().received.ack_pending)
            self.await_server_outstanding(0)
        finally:
            self.client.sock = original

    def test_server_ack_failure_keeps_ack_pending(self):
        self.client.queue_reliable_bytes(1, b"hey")
        self.client.send_reliable_once()
        self.await_server_delivery()
        original = self.server.sock
        self.server.sock = cast(socket.socket, _FailOneSend(original))
        try:
            with self.assertRaises(OSError):
                self.server.send_ack_once(self.cid)
            self.assertTrue(self.server_receiver().received.ack_pending)
            self.assertTrue(self.server.send_ack_once(self.cid))
            out = self.client.receive_reliable_once(timeout_s=0.5)
            assert out is not None
            self.assertEqual(out.packet_type, ACK)
        finally:
            self.server.sock = original

    def test_remove_connection_tombstone_blocks_future_send(self):
        self.server.queue_reliable_bytes(self.cid, 1, b"data")
        self.assertTrue(self.server.remove_connection(self.cid))
        self.assertIsNone(self.server.send_reliable_once(self.cid))
        self.assertFalse(self.server.send_ack_once(self.cid))
        with self.assertRaises(RuntimeError):
            self.server.queue_reliable_bytes(self.cid, 1, b"again")

    def test_no_send_before_register(self):
        other = UDPRegistrationClient(
            host="127.0.0.1", udp_port=self.server.port, conn_id=12345,
            c2s_key=b"C" * 32, s2c_key=b"D" * 32, bind_host="127.0.0.1",
        )
        try:
            with self.assertRaises(RuntimeError):
                other.send_reliable_once()
            with self.assertRaises(RuntimeError):
                other.send_ack_once()
            with self.assertRaises(RuntimeError):
                other.queue_reliable_bytes(1, b"x")
        finally:
            other.close()

    def test_packet_number_and_nonce_shared_with_register(self):
        self.client.queue_reliable_bytes(1, b"hello")
        plan = self.client.send_reliable_once()
        assert plan is not None
        kind, cid, pn = decode_header(plan.datagram[:20])
        self.assertEqual((kind, cid, pn), (DATA, self.cid, plan.packet_num))
        self.assertGreaterEqual(pn, 1)  # REGISTER used same TransportConnectionState
        self.await_server_delivery()
        self.assertTrue(self.server.send_ack_once(self.cid))
        # Server REGISTER_OK used PN 0; server ACK uses same allocator and PN 1.
        out = self.client.receive_reliable_once(timeout_s=0.5)
        assert out is not None
        self.assertEqual(out.packet_type, ACK)
        self.assertGreaterEqual(out.packet_num, 1)

    def test_send_empty_returns_none(self):
        self.assertIsNone(self.client.send_reliable_once())
        self.assertIsNone(self.server.send_reliable_once(self.cid))

    def test_server_backpressure_holds_unsent_bytes(self):
        data = b"x" * 12_000
        self.server.queue_reliable_bytes(self.cid, 1, data)
        # First few datagrams limited by real CUBIC cwnd, no worker timers.
        count = 0
        while True:
            plan = self.server.send_reliable_once(self.cid)
            if plan is None:
                break
            count += 1
        self.assertGreater(count, 0)
        self.assertLess(count, 20)
        self.assertGreater(self.server_receiver().streams.queued_send_bytes, 0)
        self.assertLessEqual(self.server_receiver().sent.bytes_in_flight, self.server_receiver().cubic.cwnd_bytes)


if __name__ == "__main__":
    unittest.main()
