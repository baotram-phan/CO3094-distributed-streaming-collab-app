"""Encrypted UDP registration, reliable streams and heartbeat client.

TLS bootstrap supplies ConnID, directional keys and the server UDP port.
Keep one socket and TransportConnectionState for the lifetime of a connection;
never reset packet numbers while retaining the same AES-GCM key.
"""

from __future__ import annotations

import socket
import threading
import time
from collections import deque

from cryptography.exceptions import InvalidTag

from common.constants import (
    ACK,
    HEADER_SIZE,
    REGISTER,
    REGISTER_OK,
    MAX_UDP_DATAGRAM,
    PING,
    PONG,
)
from common.transport_state import TransportConnectionState
from common.reliable_receive import ReliableReceiveState, ReceiveResult
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamDelivery
from common.udp_packet import (
    decode_header,
    decode_packet,
    encode_packet,
    encode_heartbeat_body,
    decode_heartbeat_body,
)


class UDPRegistrationClient:
    def __init__(
        self,
        *,
        host: str,
        udp_port: int,
        conn_id: int,
        c2s_key: bytes,
        s2c_key: bytes,
        bind_host: str = "0.0.0.0",
        bootstrap_deadline: float | None = None,
    ) -> None:
        if type(udp_port) is not int or not (1 <= udp_port <= 65535):
            raise ValueError("udp_port must be between 1 and 65535")
        if not isinstance(c2s_key, bytes) or len(c2s_key) != 32:
            raise ValueError("c2s_key must be 32 bytes")
        if not isinstance(s2c_key, bytes) or len(s2c_key) != 32:
            raise ValueError("s2c_key must be 32 bytes")
        if c2s_key == s2c_key:
            raise ValueError("UDP send and receive keys must differ")

        self.server_endpoint = (socket.gethostbyname(host), udp_port)
        self.conn_id = conn_id
        self.c2s_key = c2s_key
        self.s2c_key = s2c_key
        self.state = TransportConnectionState(conn_id)
        self.bootstrap_deadline = (
            float(bootstrap_deadline)
            if bootstrap_deadline is not None
            else time.monotonic() + 10.0
        )
        self.registered = False
        self.reliable_receiver: ReliableReceiveState | None = None
        self._closed = False
        # One lock serializes all reliable transport changes and UDP sends.
        # register() is synchronous and MUST NOT overlap the reliable phase.
        self._transport_lock = threading.Lock()
        # B5.2: liveness shares the REGISTER socket, keys, PN and replay bitmap.
        self.heartbeat_interval_ms = 2000.0
        self.server_idle_timeout_ms = 10000.0
        self._next_ping_due_ms: float | None = None
        self._last_verified_server_ms: float | None = None
        self._pending_ping_timestamps: deque[int] = deque(maxlen=8)
        self._last_pong_timestamp_ms: int | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((bind_host, 0))
        except Exception:
            self.sock.close()
            raise

    @property
    def local_endpoint(self) -> tuple[str, int]:
        return self.sock.getsockname()

    def register(self, *, attempts: int = 10, wait_s: float = 0.5) -> tuple[str, int]:
        if self._closed:
            raise RuntimeError("UDP socket is closed; bootstrap again")
        if self.registered:
            raise RuntimeError("Already registered; retain connection for A1.6")
        if type(attempts) is not int or not (1 <= attempts <= 10):
            raise ValueError("attempts must be an integer between 1 and 10")
        if wait_s <= 0:
            raise ValueError("wait_s must be positive")

        for _ in range(attempts):
            now = time.monotonic()
            if now >= self.bootstrap_deadline:
                break
            packet_number = self.state.allocate_packet_number()
            request = encode_packet(self.c2s_key, REGISTER, self.conn_id, packet_number)
            self.sock.sendto(request, self.server_endpoint)
            wait_deadline = min(self.bootstrap_deadline, now + wait_s)

            while True:
                remaining = wait_deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                try:
                    packet, source = self.sock.recvfrom(2048)
                except socket.timeout:
                    break
                if source != self.server_endpoint or len(packet) < HEADER_SIZE:
                    continue
                try:
                    kind, received_conn_id, pn = decode_header(packet[:HEADER_SIZE])
                    if kind != REGISTER_OK or received_conn_id != self.conn_id:
                        continue
                    if not self.state.recv_replay.can_accept(pn):
                        continue
                    decoded = decode_packet(self.s2c_key, packet)
                    if decoded != (REGISTER_OK, self.conn_id, pn, b""):
                        continue
                    self.state.recv_replay.commit(pn)
                    self.registered = True
                    self.reliable_receiver = ReliableReceiveState(self.state)
                    registered_ms = time.monotonic() * 1000
                    self._last_verified_server_ms = registered_ms
                    self._next_ping_due_ms = registered_ms + self.heartbeat_interval_ms
                    self._pending_ping_timestamps.clear()
                    return self.local_endpoint
                except (InvalidTag, ValueError, TypeError):
                    continue

        raise TimeoutError(
            "No authenticated REGISTER_OK before bootstrap deadline; bootstrap again"
        )

    def send_ping_once(self, *, now_ms: float | None = None) -> bool:
        """Send one due encrypted keepalive, without creating a timer thread.

        Only the REGISTER/pump owner may call this (not concurrently with the
        receive/pump loop). Packet number is consumed even if sendto fails.
        """
        now = time.monotonic() * 1000 if now_ms is None else float(now_ms)
        with self._transport_lock:
            self._require_reliable()
            due = self._next_ping_due_ms
            if due is None or now < due:
                return False
            timestamp = int(now)
            body = encode_heartbeat_body(timestamp)
            pn = self.state.allocate_packet_number()
            packet = encode_packet(self.c2s_key, PING, self.conn_id, pn, body)
            sent = self.sock.sendto(packet, self.server_endpoint)
            if sent != len(packet):
                raise OSError("UDP sendto returned a partial PING datagram")
            self._pending_ping_timestamps.append(timestamp)
            self._next_ping_due_ms = now + self.heartbeat_interval_ms
            return True

    def _accept_pong(
        self, packet: bytes, endpoint: tuple[str, int], *, now_ms: float
    ) -> ReceiveResult | None:
        """Called with _transport_lock held, after basic header routing."""
        if endpoint != self.server_endpoint:
            return None
        try:
            kind, conn_id, packet_num = decode_header(packet[:HEADER_SIZE])
            if kind != PONG or conn_id != self.conn_id:
                return None
            if not self.state.recv_replay.can_accept(packet_num):
                return None
            decoded_kind, decoded_conn, decoded_pn, body = decode_packet(
                self.s2c_key, packet
            )
            if (decoded_kind, decoded_conn, decoded_pn) != (PONG, conn_id, packet_num):
                return None
            timestamp = decode_heartbeat_body(body)
            if timestamp not in self._pending_ping_timestamps:
                return None  # Authenticated but unsolicited/stale PONG echo.
            if not self.state.recv_replay.commit(packet_num):
                return None
            self._pending_ping_timestamps.remove(timestamp)
            self._last_pong_timestamp_ms = timestamp
            self._last_verified_server_ms = now_ms
            return ReceiveResult(PONG, packet_num)
        except (InvalidTag, ValueError, TypeError):
            return None

    def _check_server_liveness(self, *, now_ms: float) -> None:
        """Stop using expired keys after 10s with no authenticated inbound UDP.

        This is client-side detection; A's Registry independently owns server
        expiry and sends the close event. Reconnect requires fresh TLS bootstrap.
        """
        with self._transport_lock:
            reference = self._last_verified_server_ms
        if reference is not None and now_ms - reference >= self.server_idle_timeout_ms:
            self.close()
            raise TimeoutError(
                "No authenticated UDP from server for 10s; bootstrap again"
            )

    def receive_reliable_once(self, *, timeout_s: float = 0.25) -> ReceiveResult | None:
        """B4.1 receive-only helper. Call from ONE UDP client receive loop.

        Never call concurrently with register() or another socket recvfrom().
        ACK transmission and A application callbacks are NOT implemented yet.
        """
        if self._closed or not self.registered or self.reliable_receiver is None:
            raise RuntimeError("REGISTER must complete before reliable receive")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.sock.settimeout(timeout_s)
        try:
            packet, endpoint = self.sock.recvfrom(1201)
        except socket.timeout:
            return None
        with self._transport_lock:
            if self._closed or self.reliable_receiver is None:
                return None
            now_ms = time.monotonic() * 1000
            # PONG is authenticated and replay-protected in the SAME PN space
            # as reliable DATA/ACK. It is not an ACK-eliciting DATA frame.
            if len(packet) >= HEADER_SIZE and endpoint == self.server_endpoint:
                try:
                    kind, conn_id, _ = decode_header(packet[:HEADER_SIZE])
                    if kind == PONG and conn_id == self.conn_id:
                        return self._accept_pong(packet, endpoint, now_ms=now_ms)
                except (ValueError, TypeError):
                    return None
            outcome = self.reliable_receiver.accept(
                packet,
                key=self.s2c_key,
                endpoint=endpoint,
                bound_endpoint=self.server_endpoint,
                now_ms=now_ms,
            )
            if outcome is not None and not outcome.duplicate:
                self._last_verified_server_ms = now_ms
            return outcome

    def _require_reliable(self) -> ReliableReceiveState:
        if self._closed or not self.registered or self.reliable_receiver is None:
            raise RuntimeError("REGISTER must complete before reliable send")
        return self.reliable_receiver

    def close_file_stream(self, stream):
        with self._transport_lock:
            self._require_reliable().streams.discard_file_stream(stream)

    def open_file_stream(self, receiving, stream):
        with self._transport_lock:
            state = self._require_reliable()
            state.streams.open_file_stream(stream)
            if receiving:
                state.flow.authorize_file_receive(stream)

    def queue_reliable_bytes(
        self, stream_id: int, data: bytes, *, fin: bool = False
    ) -> None:
        """Queue *exact* stream bytes; do not add an application framing prefix."""
        with self._transport_lock:
            self._require_reliable().streams.queue_bytes(stream_id, data, fin=fin)

    def pop_reliable_delivery(self) -> StreamDelivery | None:
        """Pop one ordered StreamDelivery outside the UDP receive handler.

        The caller processes/stores the data outside _transport_lock, then
        calls confirm_consumed(stream_id, exclusive_end_offset).
        """
        with self._transport_lock:
            return self._require_reliable().pop_delivery()

    def confirm_consumed(self, stream_id: int, consumed_offset: int) -> bool:
        """Confirm application progress and enqueue WINDOW_UPDATE safely.

        Popping a delivery alone does not grant credit. A's application must
        confirm only contiguous bytes it has actually processed/stored.
        """
        with self._transport_lock:
            return self._require_reliable().confirm_consumed(stream_id, consumed_offset)

    def send_reliable_once(self) -> PreparedScheduledSend | None:
        """Send at most one DATA/retry/WINDOW_UPDATE via the REGISTER socket.

        None = idle or backpressured. A definite OSError aborts the staged
        plan, burns the packet number, and propagates the error to the caller.
        The B4.3 pump calls this automatically when enabled.
        """
        with self._transport_lock:
            receiver = self._require_reliable()
            plan = receiver.prepare_send(self.c2s_key, now_ms=time.monotonic() * 1000)
            if plan is None:
                return None
            try:
                sent = self.sock.sendto(plan.datagram, self.server_endpoint)
                if sent != len(plan.datagram):
                    raise OSError("UDP sendto returned a partial datagram")
            except OSError:
                receiver.abort_send(plan)
                raise
            receiver.commit_send(plan)
            return plan

    def send_ack_once(self) -> bool:
        """Send one pending ACK snapshot; ACK-only never elicits an ACK.

        On send failure ACK remains pending, but this packet number is burned.
        """
        with self._transport_lock:
            receiver = self._require_reliable()
            now_ms = time.monotonic() * 1000
            snapshot = receiver.received.build_ack(now_ms)
            if snapshot is None:
                return False
            pn = self.state.allocate_packet_number()
            packet = encode_packet(self.c2s_key, ACK, self.conn_id, pn, snapshot.body)
            receiver.sent.track_sent(pn, ACK, len(packet), now_ms)
            sent = self.sock.sendto(packet, self.server_endpoint)
            if sent != len(packet):
                raise OSError("UDP sendto returned a partial ACK datagram")
            receiver.received.mark_ack_sent(snapshot)
            return True

    def pump_reliable_once(
        self,
        *,
        timeout_s: float = 0.01,
        max_packets: int = 32,
    ) -> ReceiveResult | None:
        """One receive + timer + bounded send round for the REGISTER socket.

        Call this repeatedly from exactly ONE client UDP receive loop. It
        works when the network is silent: recvfrom times out, then the RTO
        timer still runs. Do not call concurrently with register(),
        receive_reliable_once(), or another pump. Applications may enqueue
        stream bytes from other threads via queue_reliable_bytes().

        ACKs have priority, then due PING, then DATA/retries.
        The 2s heartbeat does not extend server AUTH deadlines.
        `max_packets` bounds the total
        datagrams sent by this round; no per-packet thread is created.
        """
        if type(max_packets) is not int or not 1 <= max_packets <= 128:
            raise ValueError("max_packets must be in 1..128")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._require_reliable()
        try:
            result = self.receive_reliable_once(timeout_s=timeout_s)
        except OSError:
            if self._closed:
                return None
            raise
        now_ms = time.monotonic() * 1000
        self._check_server_liveness(now_ms=now_ms)
        with self._transport_lock:
            receiver = self._require_reliable()
            due = receiver.timer_tick(now_ms=now_ms).ack_due
        budget = max_packets
        if due and self.send_ack_once():
            budget -= 1
        # Heartbeat is a low-volume, periodic control packet. Keep one slot
        # when due, before a large file transfer could fill the send budget.
        if budget > 0 and self.send_ping_once(now_ms=time.monotonic() * 1000):
            budget -= 1
        while budget > 0:
            if self.send_reliable_once() is None:
                break
            budget -= 1
        return result

    def run_reliable_loop(
        self,
        stop_event: threading.Event,
        *,
        timeout_s: float = 0.01,
        max_packets: int = 32,
    ) -> None:
        """Blocking UDP event loop; caller owns its single worker/thread.

        Invoke only after register(), and keep socket receive ownership here.
        Use stop_event.set() or close() to finish; no background worker is
        created by the transport itself.
        """
        self._require_reliable()
        while not self._closed and not stop_event.is_set():
            self.pump_reliable_once(timeout_s=timeout_s, max_packets=max_packets)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
