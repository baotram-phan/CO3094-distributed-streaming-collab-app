"""Reliable receive, send scheduling and CUBIC feedback for one UDP ConnID.

This module owns transport state, not sockets, threads or Registry callbacks.
Callers serialize all mutations for the connection. Accepted DATA enters a
bounded queue; the application worker confirms consumption before receive
credit advances. Socket adapters transmit the prepared ACK/DATA/control packets.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from common.constants import (
    ACK,
    DATA,
    WINDOW_UPDATE,
    HEADER_SIZE,
    GCM_TAG_SIZE,
    MAX_UDP_DATAGRAM,
)
from common.cubic import CubicController
from common.congestion_feedback import CongestionFeedback
from common.send_scheduler import ConnectionSendScheduler, PreparedScheduledSend
from common.streams import StreamDelivery, StreamManager
from common.transport import (
    AckReceipt,
    DataRetransmissionQueue,
    PacketLossDetector,
    ReceivedPacketAckTracker,
    RttEstimator,
    SentPacketTracker,
    LostPacket,
    _clock_ms,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    MAX_DATA_DATAGRAM_BYTES,
    decode_data_body,
    decode_header,
    decode_packet,
)
from common.window_update_flow import WindowUpdateFlow


@dataclass(frozen=True, slots=True)
class ReceiveResult:
    packet_type: int
    packet_num: int
    duplicate: bool = False
    delivery_enqueued: bool = False
    credit_advanced: bool = False
    newly_acked_packets: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class TimerTickResult:
    """What one deterministic timer poll discovered; it never sends packets.

    `ack_due` means the socket adapter should send one pending ACK snapshot.
    `newly_lost` is already handed to the B3 DATA/WINDOW_UPDATE retry queues.
    """

    ack_due: bool
    newly_lost: tuple[LostPacket, ...]


class ReliableReceiveState:
    """A bounded receiver for one authorized, endpoint-bound connection.

    `accept()` returns None for rejected datagrams, a result for authenticated
    and accepted packets. An authenticated replay may request re-ACK, but MUST
    NOT enter reassembly or application delivery a second time.

    Outgoing state includes sent packets, retry queues and receive windows.
    Socket I/O remains the responsibility of the transport service.
    """

    def __init__(
        self,
        connection: TransportConnectionState,
        *,
        max_delivery_bytes: int = 2 * 1024 * 1024,
        max_delivery_events: int = 256,
    ) -> None:
        if not isinstance(connection, TransportConnectionState):
            raise TypeError("connection must be TransportConnectionState")
        if type(max_delivery_bytes) is not int or max_delivery_bytes < 512 * 1024:
            raise ValueError(
                "max_delivery_bytes must be at least one file window (512 KiB)"
            )
        if type(max_delivery_events) is not int or max_delivery_events < 1:
            raise ValueError("max_delivery_events must be positive")
        self.connection = connection
        self.conn_id = connection.conn_id
        self.streams = StreamManager(self.conn_id)
        self.flow = WindowUpdateFlow(self.streams)
        self.received = ReceivedPacketAckTracker()
        self.sent = SentPacketTracker()
        self.retries = DataRetransmissionQueue(self.conn_id)
        self.rtt = RttEstimator()
        self.loss = PacketLossDetector()
        # One CUBIC and one scheduler per ConnID; never reset on REGISTER retry.
        self.cubic = CubicController(mss_bytes=MAX_DATA_DATAGRAM_BYTES)
        self.congestion = CongestionFeedback(self.cubic)
        self.scheduler = ConnectionSendScheduler(
            self.streams, self.connection, self.sent, self.retries, self.flow
        )
        self.max_delivery_bytes = max_delivery_bytes
        self.max_delivery_events = max_delivery_events
        self._deliveries: deque[StreamDelivery] = deque()
        self._delivery_bytes = 0
        # Exclusive end of DATA handed to an application worker, per stream.
        # A worker's acknowledgment must never credit DATA still in our queue.
        self._handed_off_end: dict[int, int] = {}

    @property
    def delivery_bytes(self) -> int:
        return self._delivery_bytes

    @property
    def delivery_count(self) -> int:
        return len(self._deliveries)

    def pop_delivery(self) -> StreamDelivery | None:
        """Application worker calls this OUTSIDE the UDP receive handler.

        Popping transfers ownership to downstream. Do not call note_consumed()
        until that downstream has actually accepted/processed the data.
        """
        if not self._deliveries:
            return None
        delivery = self._deliveries.popleft()
        self._delivery_bytes -= len(delivery.data)
        end = delivery.offset + len(delivery.data)
        self._handed_off_end[delivery.stream_id] = max(
            self._handed_off_end.get(delivery.stream_id, 0), end
        )
        return delivery

    def confirm_consumed(self, stream_id: int, consumed_offset: int) -> bool:
        """Application-confirmed contiguous progress; never on queue/pop alone.

        The application must first pop the StreamDelivery, and should confirm
        only after processing/storing those bytes (or taking durable ownership).
        A partial confirmation is allowed. Validates against *handed-off*
        bytes, not StreamReceiveState.delivered_offset, to avoid crediting
        packets that have never left the bounded delivery queue.

        All calls must be serialized with pop_delivery()/accept() per ConnID.
        WINDOW_UPDATE is queued by B3; the UDP pump sends it later.
        """
        if type(stream_id) is not int or not 0 <= stream_id <= (1 << 32) - 1:
            raise ValueError("stream_id must be uint32")
        if (
            type(consumed_offset) is not int
            or not 0 <= consumed_offset <= (1 << 64) - 1
        ):
            raise ValueError("consumed_offset must be uint64")
        if consumed_offset > self._handed_off_end.get(stream_id, 0):
            raise ValueError("cannot consume bytes not handed off to the application")
        return self.flow.note_consumed(stream_id, consumed_offset)

    def prepare_send(
        self, key: bytes, *, now_ms: float
    ) -> PreparedScheduledSend | None:
        """Prepare a packet using REAL CUBIC cwnd, not a demo constant.

        The socket adapter calls this under per-ConnID serialization, followed by
        socket.sendto(), then commit_send() or abort_send(). No socket here.
        """
        if not self.congestion.can_note_sent():
            return None  # bounded DATA attempt accounting; never silently drop
        # No RTO probe exception: congestion MSS and DATA wire size now agree.
        return self.scheduler.prepare_next(
            key,
            now_ms=now_ms,
            cwnd_bytes=self.cubic.cwnd_bytes,
        )

    def commit_send(self, plan: PreparedScheduledSend) -> None:
        """Commit after a full successful socket send, then record DATA attempt."""
        self.scheduler.commit_sent(plan)
        self.congestion.note_sent(plan)

    def abort_send(self, plan: PreparedScheduledSend) -> None:
        """Definite socket failure: retain DATA and burn the packet number."""
        self.scheduler.abort_send(plan)

    def check_rto(self, *, now_ms: float) -> tuple[LostPacket, ...]:
        """One timer tick: detect RTO, back off RTT once, notify CUBIC once.

        Returns loss signals for periodic transport timer processing.
        """
        losses = self.loss.check_timeouts(self.sent, self.rtt, now_ms)
        self.congestion.on_losses(losses, now_ms=now_ms)
        for item in losses:
            if item.packet.packet_type == DATA:
                self.retries.note_loss(item, self.sent)
            elif item.packet.packet_type == WINDOW_UPDATE:
                self.flow.note_loss(item, self.sent)
        return losses

    def timer_tick(self, *, now_ms: float | int) -> TimerTickResult:
        """Run ACK-deadline and RTO decisions using ONE monotonic clock.

        Called periodically by the UDP event loop.
        No socket calls, callbacks, threads, sleeps, or Registry accesses.
        Callers serialize per ConnID with DATA/ACK receive and send operations.

        `ack_due` stays True until the socket confirms send_ack_once() and
        ReceivedPacketAckTracker.mark_ack_sent() completes its batch.
        """
        now = _clock_ms(now_ms)
        due = self.received.ack_due(now)
        losses = self.check_rto(now_ms=now)
        return TimerTickResult(ack_due=due, newly_lost=losses)

    def accept(
        self,
        packet: bytes,
        *,
        key: bytes,
        endpoint: tuple[str, int],
        bound_endpoint: tuple[str, int],
        now_ms: float,
    ) -> ReceiveResult | None:
        """Validate endpoint, AEAD, anti-replay, body and bounded acceptance.

        Invalid packets never consume replay numbers or receive credit.
        The caller checks live session/tombstone before entering this method.
        All transport calls must be serialized per ConnID.
        """
        if endpoint != bound_endpoint:
            return None
        if not isinstance(packet, bytes) or not (
            HEADER_SIZE + GCM_TAG_SIZE <= len(packet) <= MAX_UDP_DATAGRAM
        ):
            return None
        try:
            packet_type, conn_id, pn = decode_header(packet[:HEADER_SIZE])
            if conn_id != self.conn_id or packet_type not in (DATA, ACK, WINDOW_UPDATE):
                return None
            fresh = self.connection.recv_replay.can_accept(pn)
            # Even an apparently repeated packet must authenticate before re-ACK.
            decoded_type, decoded_conn, decoded_pn, body = decode_packet(key, packet)
            if (decoded_type, decoded_conn, decoded_pn) != (packet_type, conn_id, pn):
                return None
            if not fresh:
                if packet_type != ACK:
                    self.received.request_reack(pn)
                return ReceiveResult(packet_type, pn, duplicate=True)

            if packet_type == DATA:
                stream_id, offset, flags, data = decode_data_body(body)
                receive_state = self.streams._receive_state(stream_id)
                # Conservative preflight: a newly filled gap might release ALL
                # buffered out-of-order bytes plus current DATA in one delivery.
                # Do not mutate stream/replay/ACK if downstream is saturated.
                potential_delivery = receive_state.buffered_bytes + len(data)
                if len(self._deliveries) >= self.max_delivery_events:
                    return None
                if self._delivery_bytes + potential_delivery > self.max_delivery_bytes:
                    return None
                delivery = self.streams.receive_frame(
                    stream_id, offset, data, fin=bool(flags & 1)
                )
                if delivery is not None:
                    self._deliveries.append(delivery)
                    self._delivery_bytes += len(delivery.data)
                if not self.connection.recv_replay.commit(pn):
                    raise RuntimeError("caller must serialize per-ConnID replay commit")
                self.received.note_received(pn, DATA, now_ms)
                return ReceiveResult(DATA, pn, delivery_enqueued=delivery is not None)

            if packet_type == WINDOW_UPDATE:
                # Unknown/unauthorized file stream raises BEFORE replay commit.
                changed = self.flow.receive_peer_update(body)
                if not self.connection.recv_replay.commit(pn):
                    raise RuntimeError("caller must serialize per-ConnID replay commit")
                self.received.note_received(pn, WINDOW_UPDATE, now_ms)
                return ReceiveResult(WINDOW_UPDATE, pn, credit_advanced=changed)

            # ACK has no application delivery and is never ACK-eliciting.
            # Body already structurally validated by decode_packet().
            # Commit before mutating outgoing state; subsequent operations are
            # state-only and use the same monotonically increasing time source.
            if not self.connection.recv_replay.commit(pn):
                raise RuntimeError("caller must serialize per-ConnID replay commit")
            receipt: AckReceipt = self.sent.process_ack(body)
            lost = self.loss.on_ack(receipt, self.sent, now_ms)
            self.rtt.record_ack(receipt, now_ms)
            completed = self.retries.on_ack(receipt, self.sent)
            self.flow.on_ack(receipt, self.sent)
            # Cancel spurious loss reports already retired by ACK completion.
            active_losses = tuple(
                item
                for item in lost
                if self.sent.get(item.packet.packet_num) is not None
            )
            self.congestion.on_losses(active_losses, now_ms=now_ms)
            self.congestion.on_feedback(receipt, completed, self.rtt, now_ms=now_ms)
            for item in active_losses:
                if item.packet.packet_type == DATA:
                    self.retries.note_loss(item, self.sent)
                elif item.packet.packet_type == WINDOW_UPDATE:
                    self.flow.note_loss(item, self.sent)
            return ReceiveResult(
                ACK,
                pn,
                newly_acked_packets=tuple(p.packet_num for p in receipt.newly_acked),
            )
        except (InvalidTag, ValueError, TypeError, BufferError):
            return None
