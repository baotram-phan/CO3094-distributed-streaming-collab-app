"""A1.5 UDP REGISTER client using B's official packet/crypto/replay modules.

A TLS bootstrap provides conn_id, c2s_key, s2c_key and udp_port.
Use ONE socket and ONE TransportConnectionState per connection; never reset the
outbound packet number while retaining its AES-GCM key.  Keep this object alive
if A1.6 adds authenticated reliable streams and heartbeat to the session.
"""
from __future__ import annotations

import socket
import threading
import time

from cryptography.exceptions import InvalidTag

from common.constants import ACK, HEADER_SIZE, REGISTER, REGISTER_OK, MAX_UDP_DATAGRAM
from common.transport_state import TransportConnectionState
from common.reliable_receive import ReliableReceiveState, ReceiveResult
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamDelivery
from common.udp_packet import decode_header, decode_packet, encode_packet


class UDPRegistrationClient:
    def __init__(
        self, *, host: str, udp_port: int, conn_id: int,
        c2s_key: bytes, s2c_key: bytes, bind_host: str = '0.0.0.0',
        bootstrap_deadline: float | None = None,
    ) -> None:
        """bootstrap_deadline: absolute time.monotonic() deadline (seconds).

        To respect the server's 10-second BOOTSTRAPPED deadline, the caller
        should calculate it *before* beginning TLS bootstrap, e.g.:
            started = time.monotonic()
            session = bootstrap(...)
            client = UDPRegistrationClient(..., bootstrap_deadline=started + 10)
        If omitted, the client uses a 10-second cap from construction; this
        cannot account for time already spent in the preceding TLS bootstrap.
        """
        if type(udp_port) is not int or not (1 <= udp_port <= 65535):
            raise ValueError('udp_port must be between 1 and 65535')
        if not isinstance(c2s_key, bytes) or len(c2s_key) != 32:
            raise ValueError('c2s_key must be 32 bytes')
        if not isinstance(s2c_key, bytes) or len(s2c_key) != 32:
            raise ValueError('s2c_key must be 32 bytes')
        if c2s_key == s2c_key:
            raise ValueError('UDP send and receive keys must differ')

        self.server_endpoint = (socket.gethostbyname(host), udp_port)
        self.conn_id = conn_id
        self.c2s_key = c2s_key
        self.s2c_key = s2c_key
        self.state = TransportConnectionState(conn_id)
        self.bootstrap_deadline = (
            float(bootstrap_deadline)
            if bootstrap_deadline is not None else time.monotonic() + 10.0
        )
        self.registered = False
        self.reliable_receiver: ReliableReceiveState | None = None
        self._closed = False
        # One lock serializes all reliable transport changes and UDP sends.
        # register() is synchronous and MUST NOT overlap the reliable phase.
        self._transport_lock = threading.Lock()
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
        """Send new authenticated REGISTER each retry, verify REGISTER_OK.

        Never sends after bootstrap_deadline.  A positive attempt count and
        timeout are required.  A valid delayed reply to an earlier attempt is
        still acceptable; server packet-number replay protection applies.
        """
        if self._closed:
            raise RuntimeError('UDP socket is closed; bootstrap again')
        if self.registered:
            raise RuntimeError('Already registered; retain connection for A1.6')
        if type(attempts) is not int or not (1 <= attempts <= 10):
            raise ValueError('attempts must be an integer between 1 and 10')
        if wait_s <= 0:
            raise ValueError('wait_s must be positive')

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
                    if decoded != (REGISTER_OK, self.conn_id, pn, b''):
                        continue
                    self.state.recv_replay.commit(pn)
                    self.registered = True
                    self.reliable_receiver = ReliableReceiveState(self.state)
                    return self.local_endpoint
                except (InvalidTag, ValueError, TypeError):
                    continue

        raise TimeoutError('No authenticated REGISTER_OK before bootstrap deadline; bootstrap again')

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
            return self.reliable_receiver.accept(
                packet, key=self.s2c_key, endpoint=endpoint,
                bound_endpoint=self.server_endpoint,
                now_ms=time.monotonic() * 1000,
            )

    def _require_reliable(self) -> ReliableReceiveState:
        if self._closed or not self.registered or self.reliable_receiver is None:
            raise RuntimeError("REGISTER must complete before reliable send")
        return self.reliable_receiver

    def queue_reliable_bytes(self, stream_id: int, data: bytes, *, fin: bool = False) -> None:
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
        self, *, timeout_s: float = 0.01, max_packets: int = 32,
    ) -> ReceiveResult | None:
        """One receive + timer + bounded send round for the REGISTER socket.

        Call this repeatedly from exactly ONE client UDP receive loop. It
        works when the network is silent: recvfrom times out, then the RTO
        timer still runs. Do not call concurrently with register(),
        receive_reliable_once(), or another pump. Applications may enqueue
        stream bytes from other threads via queue_reliable_bytes().

        ACKs have priority over DATA/retries. `max_packets` bounds the total
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
        with self._transport_lock:
            receiver = self._require_reliable()
            due = receiver.timer_tick(now_ms=time.monotonic() * 1000).ack_due
        budget = max_packets
        if due and self.send_ack_once():
            budget -= 1
        while budget > 0:
            if self.send_reliable_once() is None:
                break
            budget -= 1
        return result

    def run_reliable_loop(
        self, stop_event: threading.Event, *, timeout_s: float = 0.01,
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