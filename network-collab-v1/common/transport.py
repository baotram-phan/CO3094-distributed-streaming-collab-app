"""B3.1: bounded ACK tracking for one encrypted UDP connection.

Protocol v1.0-proposed §4.2, §6. This is deliberately *state only*:
no socket calls, no retransmission, no RTT/RTO, no callbacks, no CUBIC.

IMPORTANT receive integration ordering:
    source endpoint + header + AES-GCM + body validation -> ReplayWindow.commit
    -> accept DATA into bounded stream/reliable delivery state
    -> ReceivedPacketAckTracker.note_received() (only after safe acceptance).
An authenticated duplicate MAY use request_reack() but MUST NEVER be
replayed into stream/application logic. ACK-only packets are never ACKed.

One ConnectionAckState belongs to ONE conn_id and ONE local endpoint; the
caller serializes access per ConnID. No Registry/callback activity inside here.
Internal B API; integration ABI still awaits A/B approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from common.constants import (
    ACK, GCM_TAG_SIZE, HEADER_SIZE, MAX_UDP_DATAGRAM,
    REPLAY_WINDOW_SIZE, DATA, VALID_PACKET_TYPES,
)
from common.streams import StreamSendFrame
from common.transport_state import TransportConnectionState
from common.udp_packet import MAX_ACK_RANGES, decode_ack_body, encode_ack_body

_UINT64_MAX = (1 << 64) - 1


def _packet_number(value: int) -> None:
    if type(value) is not int or not 0 <= value <= _UINT64_MAX:
        raise ValueError("packet_num must be uint64")


def _clock_ms(value: float | int) -> float:
    if type(value) not in (float, int) or not isfinite(value) or value < 0:
        raise ValueError("time must be a nonnegative finite monotonic millisecond value")
    return float(value)


def _packet_type(value: int) -> None:
    if type(value) is not int or value not in VALID_PACKET_TYPES:
        raise ValueError("invalid UDP packet type")


@dataclass(frozen=True, slots=True)
class SentPacket:
    """ACK-eliciting packet retained until ACK or explicitly canceled.

    `frame` owns the original DATA stream identity for B3.2 retransmission:
    a resend must use a NEW packet number with the SAME stream frame.
    """

    packet_num: int
    packet_type: int
    sent_at_ms: float
    datagram_size: int
    frame: StreamSendFrame | None = None


@dataclass(frozen=True, slots=True)
class AckReceipt:
    """One parsed ACK result. Only `newly_acked` may free in-flight bytes."""

    ack_delay_ms: int
    ranges: tuple[tuple[int, int], ...]
    newly_acked: tuple[SentPacket, ...]
    bytes_acked: int

    @property
    def newly_acked_count(self) -> int:
        return len(self.newly_acked)

    @property
    def largest_acked(self) -> int:
        return self.ranges[0][1]


class SentPacketTracker:
    """Bounded send metadata for one ConnID; never allocates packet numbers.

    Call `track_sent()` immediately after packet-number allocation but BEFORE
    the packet can be lost by the send path; `cancel_sent()` on a definite
    send failure. Caller must serialize sends in allocated packet-number order.
    For DATA, do not pop the B2 frame unless there is tracking capacity or a
    separate bounded staging queue guarantees that the frame cannot be lost.
    B3.2 will implement retry/loss accounting and CUBIC events.
    """

    def __init__(
        self, *, max_outstanding_packets: int = 1024,
        max_pending_bytes: int = 1024 * 1024,
    ) -> None:
        if type(max_outstanding_packets) is not int or not 1 <= max_outstanding_packets <= _UINT64_MAX:
            raise ValueError("max_outstanding_packets must be positive int")
        if type(max_pending_bytes) is not int or not 1 <= max_pending_bytes <= _UINT64_MAX:
            raise ValueError("max_pending_bytes must be positive int")
        self.max_outstanding_packets = max_outstanding_packets
        self.max_pending_bytes = max_pending_bytes
        self._outstanding: dict[int, SentPacket] = {}
        self._last_noted_packet_num = -1
        self._bytes_in_flight = 0

    @property
    def outstanding_count(self) -> int:
        return len(self._outstanding)

    @property
    def bytes_in_flight(self) -> int:
        """ACK-eliciting datagram bytes, NOT yet a CUBIC congestion window."""
        return self._bytes_in_flight

    def get(self, packet_num: int) -> SentPacket | None:
        _packet_number(packet_num)
        return self._outstanding.get(packet_num)

    def can_track(self, datagram_size: int) -> bool:
        """Capacity preflight for a prospective ACK-eliciting datagram.

        The caller should check this BEFORE popping a B2 StreamSendFrame.
        False means the sender must backpressure instead of losing the frame.
        """
        if type(datagram_size) is not int or not HEADER_SIZE + GCM_TAG_SIZE <= datagram_size <= MAX_UDP_DATAGRAM:
            raise ValueError("datagram_size must be a valid encrypted UDP packet size")
        return (
            len(self._outstanding) < self.max_outstanding_packets
            and self._bytes_in_flight + datagram_size <= self.max_pending_bytes
        )

    def track_sent(
        self, packet_num: int, packet_type: int, datagram_size: int,
        sent_at_ms: float | int, *, frame: StreamSendFrame | None = None,
    ) -> bool:
        """Save one ACK-eliciting packet; ACK-only needs no entry.

        Returns False for ACK-only. For DATA, retaining `frame` is mandatory.
        Raises BufferError before mutating if bounded tracking is full.
        """
        _packet_number(packet_num)
        _packet_type(packet_type)
        sent_at = _clock_ms(sent_at_ms)
        if type(datagram_size) is not int or not HEADER_SIZE + GCM_TAG_SIZE <= datagram_size <= MAX_UDP_DATAGRAM:
            raise ValueError("datagram_size must be a valid encrypted UDP packet size")
        if packet_num <= self._last_noted_packet_num:
            raise ValueError("packet numbers must be strictly increasing and never reused")
        if packet_type == ACK:
            if frame is not None:
                raise ValueError("ACK-only packet cannot carry a stream frame")
            self._last_noted_packet_num = packet_num
            return False
        if packet_type == DATA:
            if not isinstance(frame, StreamSendFrame):
                raise ValueError("DATA packet must retain its StreamSendFrame")
        elif frame is not None:
            raise ValueError("only DATA may carry a StreamSendFrame")
        if len(self._outstanding) >= self.max_outstanding_packets:
            raise BufferError("maximum outstanding packet count reached")
        if self._bytes_in_flight + datagram_size > self.max_pending_bytes:
            raise BufferError("maximum outstanding packet bytes reached")
        packet = SentPacket(packet_num, packet_type, sent_at, datagram_size, frame)
        self._outstanding[packet_num] = packet
        self._last_noted_packet_num = packet_num
        self._bytes_in_flight += datagram_size
        return True

    def cancel_sent(self, packet_num: int) -> SentPacket | None:
        """Retire definitely unsent/abandoned metadata without calling it ACKed."""
        _packet_number(packet_num)
        packet = self._outstanding.pop(packet_num, None)
        if packet is not None:
            self._bytes_in_flight -= packet.datagram_size
        return packet

    def process_ack(self, body: bytes) -> AckReceipt:
        """Validate ACK before mutation, retire only currently tracked packets.

        Unknown/already-ACKed/ACK-only packet numbers are ignored; do not
        iterate the potentially enormous range of uint64 packet numbers.
        Caller must authenticate, bind endpoint and replay-check ACK first.
        """
        ack_delay_ms, ranges = decode_ack_body(body)
        newly: list[SentPacket] = []
        for packet_num in sorted(self._outstanding):
            if any(start <= packet_num <= end for start, end in ranges):
                newly.append(self._outstanding[packet_num])
        for packet in newly:
            del self._outstanding[packet.packet_num]
            self._bytes_in_flight -= packet.datagram_size
        return AckReceipt(ack_delay_ms, tuple(ranges), tuple(newly), sum(p.datagram_size for p in newly))


@dataclass(frozen=True, slots=True)
class AckSnapshot:
    """ACK body ready to encrypt. Mark sent ONLY after the UDP send succeeds."""

    ack_delay_ms: int
    ranges: tuple[tuple[int, int], ...]
    body: bytes
    generation: int
    range_cursor: int


class ReceivedPacketAckTracker:
    """Keep bounded ACK history of authenticated, replay-committed packets.

    Caller is responsible for AEAD verification, source/ConnID validation,
    ReplayWindow checks, and avoiding application delivery of duplicates.
    ACK-only never triggers an ACK (prevents ACK storms).
    """

    def __init__(
        self, *, history_size: int = REPLAY_WINDOW_SIZE,
        max_ranges_per_ack: int = MAX_ACK_RANGES,
    ) -> None:
        if type(history_size) is not int or not 1 <= history_size <= REPLAY_WINDOW_SIZE:
            raise ValueError("history_size must be in 1..REPLAY_WINDOW_SIZE")
        if type(max_ranges_per_ack) is not int or not 1 <= max_ranges_per_ack <= MAX_ACK_RANGES:
            raise ValueError("max_ranges_per_ack must be in 1..MAX_ACK_RANGES")
        self.history_size = history_size
        self.max_ranges_per_ack = max_ranges_per_ack
        self._received_at: dict[int, float] = {}
        self._highest_packet_num = -1
        self._generation = 0
        self._cursor = 0
        self._ack_pending = False

    @property
    def tracked_count(self) -> int:
        return len(self._received_at)

    @property
    def ack_pending(self) -> bool:
        return self._ack_pending

    def note_received(self, packet_num: int, packet_type: int, received_at_ms: float | int) -> bool:
        """Call for a newly accepted (ReplayWindow.commit=True) packet.

        A repeated/too-old packet returns False. ACK-only returns False and
        does not set pending; no mutation is made on bad input.
        """
        _packet_number(packet_num)
        _packet_type(packet_type)
        stamp = _clock_ms(received_at_ms)
        if packet_type == ACK:
            return False
        if packet_num in self._received_at:
            return False
        if packet_num <= self._highest_packet_num - self.history_size:
            return False
        self._highest_packet_num = max(self._highest_packet_num, packet_num)
        self._received_at[packet_num] = stamp
        cutoff = self._highest_packet_num - self.history_size + 1
        self._received_at = {n: t for n, t in self._received_at.items() if n >= cutoff}
        self._generation += 1
        self._cursor = 0
        self._ack_pending = True
        return True

    def request_reack(self, packet_num: int) -> bool:
        """Ask to ACK a replayed authenticated packet without re-delivering DATA.

        Only packet numbers still in our ACK history can be re-ACKed.
        The transport must authenticate and check the endpoint first.
        """
        _packet_number(packet_num)
        if packet_num not in self._received_at:
            return False
        self._generation += 1
        self._cursor = 0
        self._ack_pending = True
        return True

    def _ranges(self) -> list[tuple[int, int]]:
        ordered = sorted(self._received_at, reverse=True)
        if not ordered:
            return []
        start = end = ordered[0]
        result = []
        for num in ordered[1:]:
            if num == start - 1:
                start = num
            else:
                result.append((start, end))
                start = end = num
        result.append((start, end))
        return result

    def build_ack(self, now_ms: float | int, *, force: bool = False) -> AckSnapshot | None:
        """Build one <=16-range ACK; does not clear `ack_pending`.

        When >16 disjoint ranges exist, send/mark successive snapshots to
        cover ALL tracked ranges instead of permanently omitting older ones.
        `force=True` permits re-ACK without a new received packet.
        """
        now = _clock_ms(now_ms)
        if type(force) is not bool:
            raise ValueError("force must be bool")
        if not self._received_at or not (self._ack_pending or force):
            return None
        ranges = self._ranges()
        cursor = self._cursor if self._ack_pending else 0
        chosen = tuple(ranges[cursor : cursor + self.max_ranges_per_ack])
        if not chosen:
            return None
        newest_number_in_ack = chosen[0][1]
        delay = now - self._received_at[newest_number_in_ack]
        if delay < 0:
            raise ValueError("now_ms cannot precede the receipt time of the ACKed packet")
        ack_delay_ms = min(int(delay), 65535)
        return AckSnapshot(
            ack_delay_ms, chosen, encode_ack_body(ack_delay_ms, list(chosen)),
            self._generation, cursor,
        )

    def mark_ack_sent(self, snapshot: AckSnapshot) -> bool:
        """Advance ACK coverage only after the encrypted ACK datagram is sent.

        A stale snapshot cannot clear newly arrived packets or consume a
        newer range batch. On send failure, do NOT call this method.
        """
        if not isinstance(snapshot, AckSnapshot):
            raise TypeError("snapshot must be AckSnapshot")
        if not self._ack_pending or snapshot.generation != self._generation or snapshot.range_cursor != self._cursor:
            return False
        ranges = self._ranges()
        next_cursor = self._cursor + len(snapshot.ranges)
        if next_cursor < len(ranges):
            self._cursor = next_cursor
            self._ack_pending = True
        else:
            self._cursor = 0
            self._ack_pending = False
        return True


class ConnectionAckState:
    """One local ACK state per ConnID, reusing A1.5's packet-number allocator.

    Create only for an already authorized live connection, and dispose on
    A-coordinator remove_connection. These are B-internal helpers, not A ABI.
    """

    def __init__(
        self, transport_state: TransportConnectionState, *,
        max_outstanding_packets: int = 1024,
        max_pending_bytes: int = 1024 * 1024,
    ) -> None:
        if not isinstance(transport_state, TransportConnectionState):
            raise TypeError("transport_state must be TransportConnectionState")
        self.transport_state = transport_state
        self.sent = SentPacketTracker(
            max_outstanding_packets=max_outstanding_packets,
            max_pending_bytes=max_pending_bytes,
        )
        self.received = ReceivedPacketAckTracker()

    @property
    def conn_id(self) -> int:
        return self.transport_state.conn_id

    def allocate_packet_number(self) -> int:
        """Never allocate a second independent packet-number sequence."""
        return self.transport_state.allocate_packet_number()
