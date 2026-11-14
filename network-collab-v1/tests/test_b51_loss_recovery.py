"""B5.1a: reproducible 0% / 5% / 10% UDP network-loss tests.

Uses real encrypted UDP DATAGRAMS and B4.3 auto pumps, without replacing
ACK/retry/CUBIC/flow-control implementations.  Only an outbound socket's
sendto() is wrapped: intentionally dropped packets still report local success.

This tests a single reliable stream, not application-level AUTH/Chat/file and
not 10-20 clients.  Results report *actual* drop rates; small samples are not
expected to equal the configured probability precisely.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import random
import socket
import threading
import time
import unittest
from typing import cast

from client.core.udp_connection import UDPRegistrationClient
from common.constants import ACK, DATA, WINDOW_UPDATE, HEADER_SIZE, MAX_DATA_PER_PACKET
from common.udp_packet import decode_header, decode_packet, decode_data_body
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService


C2S = b"C" * 32
S2C = b"D" * 32


class NetworkLossSocket:
    """A deterministic outbound lossy link. No local sendto errors are faked."""

    def __init__(
        self,
        underlying: socket.socket,
        *,
        loss_by_type: dict[int, float],
        seed: int,
        outbound_key: bytes | None = None,
        force_drop_first: set[int] | None = None,
    ) -> None:
        self.underlying = underlying
        self.loss_by_type = dict(loss_by_type)
        self.rng = random.Random(seed)
        self.attempts: Counter[int] = Counter()
        self.dropped: Counter[int] = Counter()
        self.packet_numbers: dict[int, list[int]] = {}
        self.lock = threading.Lock()
        self.outbound_key = outbound_key
        self.force_drop_first = set(force_drop_first or ())
        self.data_frames: list[tuple[int, int, bytes]] = []
        for rate in loss_by_type.values():
            if not 0.0 <= rate <= 1.0:
                raise ValueError("loss probability must be between 0 and 1")

    def sendto(self, datagram: bytes, address: tuple[str, int]) -> int:
        if len(datagram) < HEADER_SIZE:
            return self.underlying.sendto(datagram, address)
        packet_type, _conn_id, packet_num = decode_header(datagram[:HEADER_SIZE])
        with self.lock:
            self.attempts[packet_type] += 1
            self.packet_numbers.setdefault(packet_type, []).append(packet_num)
            if packet_type == DATA and self.outbound_key is not None:
                _, _, _, body = decode_packet(self.outbound_key, datagram)
                sid, offset, _flags, frame_bytes = decode_data_body(body)
                self.data_frames.append((sid, offset, frame_bytes))
            rate = self.loss_by_type.get(packet_type, 0.0)
            should_drop = (
                packet_type in self.force_drop_first and self.attempts[packet_type] == 1
            ) or (rate > 0 and self.rng.random() < rate)
            if should_drop:
                self.dropped[packet_type] += 1
        if should_drop:
            return len(datagram)  # Simulates loss *after* a successful UDP send.
        return self.underlying.sendto(datagram, address)

    def summary(self) -> dict[str, int | float]:
        with self.lock:
            n_data = self.attempts[DATA]
            n_ack = self.attempts[ACK]
            repeated_frames = sum(
                count - 1 for count in Counter(self.data_frames).values() if count > 1
            )
            return {
                "retransmitted_frames": repeated_frames,
                "data_attempts": n_data,
                "data_dropped": self.dropped[DATA],
                "actual_data_loss": (self.dropped[DATA] / n_data if n_data else 0.0),
                "window_update_attempts": self.attempts[WINDOW_UPDATE],
                "ack_attempts": n_ack,
                "ack_dropped": self.dropped[ACK],
                "actual_ack_loss": (self.dropped[ACK] / n_ack if n_ack else 0.0),
            }

    def __getattr__(self, name: str):
        return getattr(self.underlying, name)


class LossyUdpReliableLoopback(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = SessionRegistry(
            bootstrap_timeout_s=30,
            auth_timeout_s=30,
            idle_timeout_s=30,
            password_verifier=lambda _username, _password: False,
        )
        session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1",
            c2s_key=C2S,
            s2c_key=S2C,
        )
        self.cid = session.conn_id
        self.server = UDPTransportService(
            self.registry,
            host="127.0.0.1",
            port=0,
            logger=None,
            auto_drive=True,
            tick_interval_s=0.005,
            max_packets_per_tick=16,
        )
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.server_thread.start()
        self.client = UDPRegistrationClient(
            host="127.0.0.1",
            udp_port=self.server.port,
            conn_id=self.cid,
            c2s_key=C2S,
            s2c_key=S2C,
            bind_host="127.0.0.1",
        )
        # REGISTER is not subject to the loss simulation in these tests.
        self.client.register(attempts=8, wait_s=0.1)
        self.client_stop = threading.Event()
        self.client_thread: threading.Thread | None = None
        self.client_original_sock = self.client.sock
        self.server_original_sock = self.server.sock

    def tearDown(self) -> None:
        self.client_stop.set()
        if self.client_thread is not None:
            self.client_thread.join(timeout=2)
        self.client.sock = self.client_original_sock
        self.server.sock = self.server_original_sock
        self.client.close()
        self.server.stop()
        self.server_thread.join(timeout=2)

    def _client_loop(self) -> None:
        self.client_thread = threading.Thread(
            target=self.client.run_reliable_loop,
            args=(self.client_stop,),
            kwargs={"timeout_s": 0.005, "max_packets": 16},
            daemon=True,
        )
        self.client_thread.start()

    def _run_c2s(
        self,
        *,
        data_loss: float = 0.0,
        ack_loss: float = 0.0,
        seed: int = 42,
        total_bytes: int = 32 * 1024,
        timeout_s: float = 15.0,
        force_first_data_drop: bool = False,
    ) -> tuple[dict[str, int | float], dict[str, int | float]]:
        client_link = NetworkLossSocket(
            self.client_original_sock,
            loss_by_type={DATA: data_loss},
            seed=seed,
            outbound_key=C2S,
            force_drop_first={DATA} if force_first_data_drop else None,
        )
        server_link = NetworkLossSocket(
            self.server_original_sock,
            loss_by_type={ACK: ack_loss},
            seed=seed + 1,
        )
        self.client.sock = cast(socket.socket, client_link)
        self.server.sock = cast(socket.socket, server_link)
        self._client_loop()
        started = time.monotonic()

        payload = bytes((i * 37 + 11) % 256 for i in range(total_bytes))
        expected_digest = hashlib.sha256(payload).hexdigest()
        # Do not enqueue >64 KiB in one call: stream send queues are bounded.
        # Producer supplies further bytes as the auto pump drains the queue.
        queued_end = min(32 * 1024, total_bytes)
        self.client.queue_reliable_bytes(1, payload[:queued_end])
        received = bytearray()
        chunks = 0
        deadline = time.monotonic() + timeout_s
        receiver = self.client.reliable_receiver
        self.assertIsNotNone(receiver)
        assert receiver is not None
        # The application consumes each contiguous delivery and returns credit.
        while time.monotonic() < deadline:
            with self.client._transport_lock:
                queued_bytes = receiver.streams._send_state(1).queued_bytes
            if queued_end < total_bytes and queued_bytes < 24 * 1024:
                n = min(32 * 1024, total_bytes - queued_end)
                self.client.queue_reliable_bytes(
                    1, payload[queued_end : queued_end + n]
                )
                queued_end += n
            delivery = self.server.pop_reliable_delivery(self.cid)
            if delivery is not None:
                self.assertEqual(delivery.stream_id, 1)
                self.assertEqual(
                    delivery.offset, len(received), "gap or duplicate delivery"
                )
                self.assertLessEqual(len(received) + len(delivery.data), total_bytes)
                received.extend(delivery.data)
                chunks += 1
                self.server.confirm_consumed(
                    self.cid,
                    delivery.stream_id,
                    delivery.offset + len(delivery.data),
                )
            next_offset = receiver.streams._send_state(1).next_offset
            if (
                queued_end == total_bytes
                and len(received) == total_bytes
                and next_offset == total_bytes
                and receiver.sent.outstanding_count == 0
            ):
                break
            time.sleep(0.005)
        else:
            self.fail(
                f"timeout: received={len(received)}/{total_bytes}, "
                f"sent_offset={receiver.streams._send_state(1).next_offset}, "
                f"outstanding={receiver.sent.outstanding_count}; "
                f"client_link={client_link.summary()}, server_link={server_link.summary()}"
            )

        self.assertEqual(hashlib.sha256(received).hexdigest(), expected_digest)
        self.assertEqual(bytes(received), payload)
        self.assertEqual(self.server.get_reliable_receiver(self.cid).delivery_count, 0)
        client_summary = client_link.summary()
        server_summary = server_link.summary()
        self.assertEqual(
            len(set(client_link.packet_numbers.get(DATA, []))),
            len(client_link.packet_numbers.get(DATA, [])),
            "every DATA attempt (including retry) must use fresh packet number",
        )
        self.assertGreaterEqual(
            client_summary["data_attempts"],
            math.ceil(total_bytes / MAX_DATA_PER_PACKET),
        )
        self.assertGreater(chunks, 0)
        self.assertGreater(receiver.cubic.cwnd_bytes, 0)
        print(
            f"\n[B51] elapsed_s={time.monotonic()-started:.3f} cwnd={receiver.cubic.cwnd_bytes} "
            f"data_loss_config={data_loss:.0%} "
            f"ack_loss_config={ack_loss:.0%} bytes={total_bytes} "
            f"client={client_summary} server={server_summary} chunks={chunks}",
            flush=True,
        )
        return client_summary, server_summary

    def test_baseline_zero_loss(self) -> None:
        c, s = self._run_c2s(seed=42)
        self.assertEqual(c["data_dropped"], 0)
        self.assertEqual(s["ack_dropped"], 0)

    def test_flow_credit_replenishes_beyond_initial_64k_with_loss(self) -> None:
        # Above the initial chat receive window: WINDOW_UPDATE must unblock DATA.
        c, s = self._run_c2s(
            data_loss=0.05, seed=43, total_bytes=96 * 1024, timeout_s=20.0
        )
        self.assertGreater(c["data_dropped"], 0)
        self.assertGreater(c["retransmitted_frames"], 0)
        self.assertGreater(s["window_update_attempts"], 0)

    def test_single_full_size_data_packet_recovers_after_rto(self) -> None:
        # This MUST recover after CUBIC falls to its 1-MSS timeout window.
        # Previously: cwnd=1024 but the encrypted DATA datagram is 1075 B.
        c, _ = self._run_c2s(
            total_bytes=MAX_DATA_PER_PACKET, force_first_data_drop=True, timeout_s=5.0
        )
        self.assertEqual(c["data_dropped"], 1)
        self.assertEqual(c["retransmitted_frames"], 1)

    def test_seeded_five_percent_data_loss(self) -> None:
        c, _ = self._run_c2s(data_loss=0.05, seed=43)
        self.assertGreater(c["data_dropped"], 0)
        self.assertGreater(c["retransmitted_frames"], 0)

    def test_seeded_ten_percent_data_loss(self) -> None:
        c, _ = self._run_c2s(
            data_loss=0.10, seed=22, total_bytes=96 * 1024, timeout_s=20.0
        )
        self.assertGreater(c["data_dropped"], 0)
        self.assertGreater(c["retransmitted_frames"], 0)

    def test_seeded_ten_percent_ack_loss_does_not_redeliver(self) -> None:
        _, s = self._run_c2s(ack_loss=0.10, seed=30)
        self.assertGreater(s["ack_dropped"], 0)

    def test_seeded_mixed_five_percent_data_and_ten_percent_ack_loss(self) -> None:
        c, s = self._run_c2s(data_loss=0.05, ack_loss=0.10, seed=30)
        self.assertGreater(c["data_dropped"], 0)
        self.assertGreater(s["ack_dropped"], 0)


if __name__ == "__main__":
    unittest.main()
