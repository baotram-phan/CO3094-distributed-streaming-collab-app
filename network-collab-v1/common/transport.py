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
    ACK,
    GCM_TAG_SIZE,
    HEADER_SIZE,
    MAX_UDP_DATAGRAM,
    REPLAY_WINDOW_SIZE,
    DATA,
    VALID_PACKET_TYPES,
)

# Constants stay internal until A/B settle the reliable transport ABI.
RTO_INIT_MS = 500.0
RTO_MIN_MS = 100.0
RTO_MAX_MS = 3000.0
ACK_DELAY_CAP_MS = 25
# This code is appended after RttEstimator and does NOT retransmit datagrams.
PACKET_LOSS_THRESHOLD = 3
# B3.2.3 — DATA retransmission scheduling (§6.2 Protocol v1.0-proposed).
# No socket I/O or application callbacks. A/B integration ABI remains pending.
from collections import deque
from common.udp_packet import encode_data_body, encode_packet, DATA_STRUCT

MAX_DATA_RETRANSMISSIONS = 8

from common.streams import StreamSendFrame
from common.transport_state import TransportConnectionState
from common.udp_packet import MAX_ACK_RANGES, decode_ack_body, encode_ack_body

_UINT64_MAX = (1 << 64) - 1


def _packet_number(value: int) -> None:
    if type(value) is not int or not 0 <= value <= _UINT64_MAX:
        raise ValueError("packet_num must be uint64")


def _clock_ms(value: float | int) -> float:
    if type(value) not in (float, int) or not isfinite(value) or value < 0:
        raise ValueError(
            "time must be a nonnegative finite monotonic millisecond value"
        )
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
        self,
        *,
        max_outstanding_packets: int = 1024,
        max_pending_bytes: int = 1024 * 1024,
    ) -> None:
        if (
            type(max_outstanding_packets) is not int
            or not 1 <= max_outstanding_packets <= _UINT64_MAX
        ):
            raise ValueError("max_outstanding_packets must be positive int")
        if (
            type(max_pending_bytes) is not int
            or not 1 <= max_pending_bytes <= _UINT64_MAX
        ):
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

    def outstanding_packets(self) -> tuple[SentPacket, ...]:
        """Return a snapshot of packets waiting for ACK."""
        return tuple(self._outstanding.values())

    def can_track(self, datagram_size: int) -> bool:
        """Capacity preflight for a prospective ACK-eliciting datagram.

        The caller should check this BEFORE popping a B2 StreamSendFrame.
        False means the sender must backpressure instead of losing the frame.
        """
        if (
            type(datagram_size) is not int
            or not HEADER_SIZE + GCM_TAG_SIZE <= datagram_size <= MAX_UDP_DATAGRAM
        ):
            raise ValueError("datagram_size must be a valid encrypted UDP packet size")
        return (
            len(self._outstanding) < self.max_outstanding_packets
            and self._bytes_in_flight + datagram_size <= self.max_pending_bytes
        )

    def track_sent(
        self,
        packet_num: int,
        packet_type: int,
        datagram_size: int,
        sent_at_ms: float | int,
        *,
        frame: StreamSendFrame | None = None,
    ) -> bool:
        """Save one ACK-eliciting packet; ACK-only needs no entry.

        Returns False for ACK-only. For DATA, retaining `frame` is mandatory.
        Raises BufferError before mutating if bounded tracking is full.
        """
        _packet_number(packet_num)
        _packet_type(packet_type)
        sent_at = _clock_ms(sent_at_ms)
        if (
            type(datagram_size) is not int
            or not HEADER_SIZE + GCM_TAG_SIZE <= datagram_size <= MAX_UDP_DATAGRAM
        ):
            raise ValueError("datagram_size must be a valid encrypted UDP packet size")
        if packet_num <= self._last_noted_packet_num:
            raise ValueError(
                "packet numbers must be strictly increasing and never reused"
            )
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
        return AckReceipt(
            ack_delay_ms,
            tuple(ranges),
            tuple(newly),
            sum(p.datagram_size for p in newly),
        )


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
        self,
        *,
        history_size: int = REPLAY_WINDOW_SIZE,
        max_ranges_per_ack: int = MAX_ACK_RANGES,
    ) -> None:
        if type(history_size) is not int or not 1 <= history_size <= REPLAY_WINDOW_SIZE:
            raise ValueError("history_size must be in 1..REPLAY_WINDOW_SIZE")
        if (
            type(max_ranges_per_ack) is not int
            or not 1 <= max_ranges_per_ack <= MAX_ACK_RANGES
        ):
            raise ValueError("max_ranges_per_ack must be in 1..MAX_ACK_RANGES")
        self.history_size = history_size
        self.max_ranges_per_ack = max_ranges_per_ack
        self._received_at: dict[int, float] = {}
        self._highest_packet_num = -1
        self._generation = 0
        self._cursor = 0
        self._ack_pending = False
        # Earliest time at which the current ACK batch became pending.
        # Keep this deadline while a multi-range ACK batch is in progress.
        self._ack_pending_since_ms: float | None = None

    @property
    def tracked_count(self) -> int:
        return len(self._received_at)

    @property
    def ack_pending(self) -> bool:
        return self._ack_pending

    @property
    def ack_pending_since_ms(self) -> float | None:
        """Earliest unflushed ACK-eliciting receipt, or None when idle."""
        return self._ack_pending_since_ms

    def ack_due(
        self, now_ms: float | int, *, max_delay_ms: float = ACK_DELAY_CAP_MS
    ) -> bool:
        """Whether an ACK should be sent *by now* (no network I/O).

        UDP ACK-only packets never set this deadline. A valid replay request
        uses its original receipt timestamp, so a lost ACK can be resent
        promptly. `max_delay_ms` cannot exceed the protocol's 25 ms limit.
        """
        now = _clock_ms(now_ms)
        if type(max_delay_ms) not in (int, float) or not isfinite(max_delay_ms):
            raise ValueError("max_delay_ms must be a finite number")
        if not 0 <= max_delay_ms <= ACK_DELAY_CAP_MS:
            raise ValueError("max_delay_ms must be in 0..25")
        if not self._ack_pending:
            return False
        pending_since = self._ack_pending_since_ms
        if pending_since is None:
            raise RuntimeError("ACK pending without a receipt timestamp")
        if now < pending_since:
            raise ValueError("ACK clock cannot precede the receipt time")
        return now - pending_since >= max_delay_ms

    def note_received(
        self, packet_num: int, packet_type: int, received_at_ms: float | int
    ) -> bool:
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
        if self._ack_pending_since_ms is None:
            self._ack_pending_since_ms = stamp
        else:
            self._ack_pending_since_ms = min(self._ack_pending_since_ms, stamp)
        self._ack_pending = True
        return True

    def request_reack(self, packet_num: int) -> bool:
        """Ask to ACK a replayed authenticated packet without re-delivering DATA.

        Only packet numbers still in our ACK history can be re-ACKed.
        The transport must authenticate and check the endpoint first.
        """
        _packet_number(packet_num)
        received_at = self._received_at.get(packet_num)
        if received_at is None:
            return False
        self._generation += 1
        self._cursor = 0
        if self._ack_pending_since_ms is None:
            self._ack_pending_since_ms = received_at
        else:
            self._ack_pending_since_ms = min(self._ack_pending_since_ms, received_at)
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

    def build_ack(
        self, now_ms: float | int, *, force: bool = False
    ) -> AckSnapshot | None:
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
            raise ValueError(
                "now_ms cannot precede the receipt time of the ACKed packet"
            )
        ack_delay_ms = min(int(delay), 65535)
        return AckSnapshot(
            ack_delay_ms,
            chosen,
            encode_ack_body(ack_delay_ms, list(chosen)),
            self._generation,
            cursor,
        )

    def mark_ack_sent(self, snapshot: AckSnapshot) -> bool:
        """Advance ACK coverage only after the encrypted ACK datagram is sent.

        A stale snapshot cannot clear newly arrived packets or consume a
        newer range batch. On send failure, do NOT call this method.
        """
        if not isinstance(snapshot, AckSnapshot):
            raise TypeError("snapshot must be AckSnapshot")
        if (
            not self._ack_pending
            or snapshot.generation != self._generation
            or snapshot.range_cursor != self._cursor
        ):
            return False
        ranges = self._ranges()
        next_cursor = self._cursor + len(snapshot.ranges)
        if next_cursor < len(ranges):
            self._cursor = next_cursor
            self._ack_pending = True
        else:
            self._cursor = 0
            self._ack_pending = False
            self._ack_pending_since_ms = None
        return True


class ConnectionAckState:
    """One local ACK state per ConnID, reusing A1.5's packet-number allocator.

    Create only for an already authorized live connection, and dispose on
    A-coordinator remove_connection. These are B-internal helpers, not A ABI.
    """

    def __init__(
        self,
        transport_state: TransportConnectionState,
        *,
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


class RttEstimator:
    """One sender-side RTT/RTO estimator per connection, with no UDP I/O.

    Accept *only* a packet's first newly authenticated ACK as an RTT sample:
    `SentPacketTracker.process_ack()` supplies `AckReceipt.newly_acked`.
    B3.2.2 must call `on_timeout()` only when an actual timer fires.

    All times use the SAME monotonic clock in milliseconds. `ack_delay_ms`
    comes from an authenticated ACK and is capped at the protocol's 25 ms;
    adjustments never make the sample negative. This is an internal B API,
    not an agreed callback interface with A.
    """

    def __init__(self) -> None:
        self.smoothed_rtt_ms: float | None = None
        self.rttvar_ms: float | None = None
        self.latest_rtt_ms: float | None = None
        self.last_adjusted_rtt_ms: float | None = None
        self.sample_count = 0
        self.timeout_count = 0
        self._current_rto_ms = RTO_INIT_MS

    @property
    def rto_ms(self) -> float:
        """Current retransmission timeout including exponential backoff."""
        return self._current_rto_ms

    @property
    def base_rto_ms(self) -> float:
        """RTO inferred from RTT, without timeout backoff."""
        if self.smoothed_rtt_ms is None or self.rttvar_ms is None:
            return RTO_INIT_MS
        return min(
            RTO_MAX_MS, max(RTO_MIN_MS, self.smoothed_rtt_ms + 4 * self.rttvar_ms)
        )

    def record_sample(self, raw_rtt_ms: float | int, *, ack_delay_ms: int = 0) -> float:
        """Update SRTT/RTTVAR from one validated RTT observation.

        Uses first-sample RTTVAR=RTT/2; subsequent EWMA weights 1/4
        (variation) and 1/8 (smoothed RTT). ACK delay is bounded at 25 ms.
        A new valid sample clears timeout backoff.
        """
        raw_rtt = _clock_ms(raw_rtt_ms)
        if type(ack_delay_ms) is not int or not 0 <= ack_delay_ms <= 0xFFFF:
            raise ValueError("ack_delay_ms must be uint16")
        adjusted = max(0.0, raw_rtt - min(ack_delay_ms, ACK_DELAY_CAP_MS))

        if self.smoothed_rtt_ms is None:
            self.smoothed_rtt_ms = adjusted
            self.rttvar_ms = adjusted / 2.0
        else:
            # rttvar exists whenever smoothed_rtt exists.
            assert self.rttvar_ms is not None
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * abs(
                self.smoothed_rtt_ms - adjusted
            )
            self.smoothed_rtt_ms = 0.875 * self.smoothed_rtt_ms + 0.125 * adjusted

        self.latest_rtt_ms = raw_rtt
        self.last_adjusted_rtt_ms = adjusted
        self.sample_count += 1
        self.timeout_count = 0
        self._current_rto_ms = self.base_rto_ms
        return adjusted

    def record_ack(
        self, receipt: AckReceipt, received_at_ms: float | int
    ) -> float | None:
        """Sample only the highest-numbered *newly acknowledged* packet.

        A duplicate/unknown-only ACK supplies no sample and cannot reset
        timeout backoff. The caller must authenticate/replay-check ACK before
        running `SentPacketTracker.process_ack()` and then this method.
        """
        if not isinstance(receipt, AckReceipt):
            raise TypeError("receipt must be AckReceipt")
        now = _clock_ms(received_at_ms)
        if (
            type(receipt.ack_delay_ms) is not int
            or not 0 <= receipt.ack_delay_ms <= 0xFFFF
        ):
            raise ValueError("receipt ack_delay_ms must be uint16")
        if not receipt.newly_acked:
            return None
        packet = max(receipt.newly_acked, key=lambda p: p.packet_num)
        sent_at = _clock_ms(packet.sent_at_ms)
        if now < sent_at:
            raise ValueError(
                "ACK clock cannot precede the acknowledged packet send time"
            )
        return self.record_sample(now - sent_at, ack_delay_ms=receipt.ack_delay_ms)

    def on_timeout(self) -> float:
        """Exponential timeout backoff, saturated at RTO_MAX_MS.

        Called by the FUTURE retransmission scheduler, not by a timer in this
        class. RTT tracking alone must not infer that a packet was lost.
        """
        self._current_rto_ms = min(RTO_MAX_MS, self._current_rto_ms * 2.0)
        self.timeout_count += 1
        return self._current_rto_ms


@dataclass(frozen=True, slots=True)
class LostPacket:
    """One newly detected loss; the original tracker entry is NOT removed.

    The B3.2.3 sender must safely hand off/retire the original tracked packet,
    and must allocate a NEW packet number to retransmit its original frame.
    """

    packet: SentPacket
    reason: str  # "packet_threshold" or "rto"
    detected_at_ms: float


class PacketLossDetector:
    """Bounded, one-shot packet loss signals for ONE outgoing connection.

    - Packet threshold counts *newly ACKed, tracked, ACK-eliciting packets*,
      not differences between packet numbers (ACK-only numbers may intervene).
    - Keep only the 3 largest distinct ACKed numbers: that is sufficient to
      determine whether >=3 later ACK-eliciting packets were ACKed for ANY
      still-pending packet, without unbounded ACK-history retention.
    - RTO checks use the RttEstimator's current RTO, with one timeout backoff
      per batch containing newly reported RTO losses.
    - No I/O, callbacks, packet-number allocation or tracker retirement.

    Caller serializes operations per ConnID and must call process_ack() on an
    authenticated/validated/replay-checked ACK BEFORE on_ack(). Never share
    this detector or its RttEstimator across different connections.
    """

    def __init__(self) -> None:
        self._largest_acked: tuple[int, ...] = ()
        self._already_reported: set[int] = set()
        self._last_checked_ms: float | None = None

    @property
    def largest_acked_packets(self) -> tuple[int, ...]:
        """Up to three descending ACKed ACK-eliciting packet numbers."""
        return self._largest_acked

    @property
    def pending_loss_reports(self) -> int:
        """Number of still-outstanding packets already flagged as lost."""
        return len(self._already_reported)

    def _validate_call(self, sent: SentPacketTracker, now_ms: float | int) -> float:
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        now = _clock_ms(now_ms)
        if self._last_checked_ms is not None and now < self._last_checked_ms:
            raise ValueError("loss-detector timestamps must be monotonic")
        return now

    def _pending_and_prune(self, sent: SentPacketTracker) -> tuple[SentPacket, ...]:
        pending = sent.outstanding_packets()
        self._already_reported.intersection_update(
            packet.packet_num for packet in pending
        )
        return pending

    def on_ack(
        self,
        receipt: AckReceipt,
        sent: SentPacketTracker,
        now_ms: float | int,
    ) -> tuple[LostPacket, ...]:
        """Report unACKed packets with >=3 later newly ACKed eliciting sends.

        `receipt` MUST be the output of sent.process_ack() on a validated ACK.
        Subsequent/duplicate ACKs cannot count a packet again. Reporting does
        not retire a packet, change bytes_in_flight, or change RTO.
        """
        if not isinstance(receipt, AckReceipt):
            raise TypeError("receipt must be AckReceipt")
        now = self._validate_call(sent, now_ms)
        if any(packet.sent_at_ms > now for packet in receipt.newly_acked):
            raise ValueError("ACK time cannot precede the acknowledged send time")

        pending = self._pending_and_prune(sent)
        self._largest_acked = tuple(
            sorted(
                set(self._largest_acked).union(
                    p.packet_num for p in receipt.newly_acked
                ),
                reverse=True,
            )[:PACKET_LOSS_THRESHOLD]
        )
        self._last_checked_ms = now
        if len(self._largest_acked) < PACKET_LOSS_THRESHOLD:
            return ()

        # Third-largest ACKed packet is the threshold cutoff.  For original
        # packet n, exactly 3 ACKed later packets exist iff n < cutoff.
        cutoff = self._largest_acked[-1]
        newly_lost = tuple(
            LostPacket(p, "packet_threshold", now)
            for p in sorted(pending, key=lambda p: p.packet_num)
            if p.packet_num < cutoff and p.packet_num not in self._already_reported
        )
        self._already_reported.update(loss.packet.packet_num for loss in newly_lost)
        return newly_lost

    def check_timeouts(
        self,
        sent: SentPacketTracker,
        rtt: RttEstimator,
        now_ms: float | int,
    ) -> tuple[LostPacket, ...]:
        """Report newly timed-out packets; back off RTO ONCE if any fire.

        Timeouts use the RTO value at entry, BEFORE the exponential backoff.
        Repeated polling of an unretired packet does not trigger another loss
        or backoff. The retransmission scheduler will retire/handoff in B3.2.3.
        """
        if not isinstance(rtt, RttEstimator):
            raise TypeError("rtt must be RttEstimator")
        now = self._validate_call(sent, now_ms)
        pending = sent.outstanding_packets()
        if any(packet.sent_at_ms > now for packet in pending):
            raise ValueError("loss-check time cannot precede pending send times")

        pending = self._pending_and_prune(sent)
        timeout_ms = rtt.rto_ms
        newly_lost = tuple(
            LostPacket(p, "rto", now)
            for p in sorted(pending, key=lambda p: p.packet_num)
            if p.packet_num not in self._already_reported
            and now - p.sent_at_ms >= timeout_ms
        )
        self._already_reported.update(loss.packet.packet_num for loss in newly_lost)
        self._last_checked_ms = now
        if newly_lost:
            rtt.on_timeout()
        return newly_lost


@dataclass(frozen=True, slots=True)
class PreparedRetransmission:
    """A fresh encrypted DATA datagram reserved for one socket send attempt.

    The packet number is consumed even if the send later fails; callers MUST
    commit_sent() on success, or abort_send() on a definite send failure.
    """

    packet_num: int
    frame: StreamSendFrame
    datagram: bytes
    retry_number: int


@dataclass(slots=True)
class _RetryGroup:
    """One logical DATA frame across all of its packet-number attempts."""

    frame: StreamSendFrame
    packet_numbers: set[int]
    retry_count: int = 0
    queued: bool = False


class DataRetransmissionQueue:
    """Bounded, in-memory resend scheduler for ONE connection and direction.

    Each logical DATA frame has at most one queued retry and one in-flight
    prepared send. Old packet numbers are retained so a *late valid ACK* can
    cancel a queued retransmission after loss was reported.

    No socket calls, Registry operations, callbacks, locks, or CUBIC. All
    methods are called serially for the same ConnID. The encrypted datagram
    returned by prepare_next() is passed to the *existing* socket send path.

    Loss transition is safe: store the frame in a bounded group and queue
    BEFORE retiring the lost packet from SentPacketTracker. If capacity is
    exhausted, BufferError is raised with the original tracker entry intact;
    the caller MUST retain/retry that loss notification (one-shot detector).

    To handle late ACKs for retired packet numbers, call on_ack(receipt,sent)
    after the authenticated ACK has passed through sent.process_ack().
    """

    def __init__(
        self,
        conn_id: int,
        *,
        max_tracked_frames: int = 1024,
        max_queued_frames: int = 256,
        max_queued_bytes: int = 256 * 1024,
        max_retransmissions: int = MAX_DATA_RETRANSMISSIONS,
    ) -> None:
        if type(conn_id) is not int or not 1 <= conn_id <= _UINT64_MAX:
            raise ValueError("conn_id must be nonzero uint64")
        for name, value in (
            ("max_tracked_frames", max_tracked_frames),
            ("max_queued_frames", max_queued_frames),
            ("max_queued_bytes", max_queued_bytes),
            ("max_retransmissions", max_retransmissions),
        ):
            if type(value) is not int or not 1 <= value <= _UINT64_MAX:
                raise ValueError(f"{name} must be positive integer")
        self.conn_id = conn_id
        self.max_tracked_frames = max_tracked_frames
        self.max_queued_frames = max_queued_frames
        self.max_queued_bytes = max_queued_bytes
        self.max_retransmissions = max_retransmissions
        self._groups: dict[StreamSendFrame, _RetryGroup] = {}
        self._packet_to_frame: dict[int, StreamSendFrame] = {}
        self._queue: deque[StreamSendFrame] = deque()
        self._queued_bytes = 0
        self._prepared: PreparedRetransmission | None = None

    @property
    def queued_count(self) -> int:
        return len(self._queue)

    @property
    def queued_bytes(self) -> int:
        return self._queued_bytes

    @property
    def tracked_frames(self) -> int:
        return len(self._groups)

    @property
    def prepared(self) -> PreparedRetransmission | None:
        return self._prepared

    def peek_queued_frame(self) -> StreamSendFrame | None:
        """Read-only head of the resend queue; does NOT allocate a packet number."""
        return self._queue[0] if self._queue else None

    def note_loss(self, lost: LostPacket, sent: SentPacketTracker) -> bool:
        """Queue retransmission after a fresh DATA loss report.

        True iff a still-outstanding DATA attempt was safely retired.
        False for a stale signal already ACKed/retired; non-DATA losses
        explicitly require a different control-packet retry path.
        """
        if not isinstance(lost, LostPacket):
            raise TypeError("lost must be LostPacket")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        packet = lost.packet
        if packet.packet_type != DATA or packet.frame is None:
            raise NotImplementedError(
                "B3.2.3 retries DATA only; WINDOW_UPDATE needs control retry"
            )
        current = sent.get(packet.packet_num)
        if current is None:
            return False
        if current != packet:
            raise ValueError("loss signal does not match tracked packet")

        frame = packet.frame
        group = self._groups.get(frame)
        need_enqueue = group is None or not group.queued
        if group is None and len(self._groups) >= self.max_tracked_frames:
            raise BufferError("retransmission frame history full")
        if (
            group is not None
            and group.retry_count >= self.max_retransmissions
            and need_enqueue
        ):
            raise TimeoutError(
                "DATA retransmission limit reached; report TIMEOUT to application"
            )
        if need_enqueue:
            if len(self._queue) >= self.max_queued_frames:
                raise BufferError("retransmission queue full")
            if self._queued_bytes + len(frame.data) > self.max_queued_bytes:
                raise BufferError("retransmission byte budget exhausted")

        # Safe handoff: establish ownership in our bounded state FIRST.
        if group is None:
            group = _RetryGroup(frame=frame, packet_numbers=set())
            self._groups[frame] = group
        if need_enqueue:
            self._queue.append(frame)
            self._queued_bytes += len(frame.data)
            group.queued = True
        group.packet_numbers.add(packet.packet_num)
        self._packet_to_frame[packet.packet_num] = frame
        removed = sent.cancel_sent(packet.packet_num)
        assert removed is not None  # serialized access per ConnID
        return True

    def prepare_next(
        self,
        connection: TransportConnectionState,
        sent: SentPacketTracker,
        key: bytes,
        now_ms: float | int,
    ) -> PreparedRetransmission | None:
        """Reserve a new packet number and encrypt a queued DATA retry.

        Returns None when empty or when in-flight tracker capacity is full.
        Track BEFORE exposing bytes to the socket. Must commit/abort later.
        """
        if not isinstance(connection, TransportConnectionState):
            raise TypeError("connection must be TransportConnectionState")
        if connection.conn_id != self.conn_id:
            raise ValueError("connection does not match retransmission queue ConnID")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        now = _clock_ms(now_ms)
        if self._prepared is not None:
            raise RuntimeError("previous DATA retry has not been committed or aborted")
        if not self._queue:
            return None
        frame = self._queue[0]
        group = self._groups[frame]
        if group.retry_count >= self.max_retransmissions:
            raise TimeoutError(
                "DATA retransmission limit reached; report TIMEOUT to application"
            )
        datagram_size = HEADER_SIZE + GCM_TAG_SIZE + DATA_STRUCT.size + len(frame.data)
        if not sent.can_track(datagram_size):
            return None
        body = encode_data_body(frame.stream_id, frame.offset, frame.flags, frame.data)
        pn = connection.allocate_packet_number()  # fresh AES-GCM nonce, NEVER reused
        datagram = encode_packet(key, DATA, self.conn_id, pn, body)
        sent.track_sent(pn, DATA, len(datagram), now, frame=frame)
        plan = PreparedRetransmission(pn, frame, datagram, group.retry_count + 1)
        self._prepared = plan
        return plan

    def commit_sent(self, plan: PreparedRetransmission) -> None:
        """Call only after socket.sendto successfully accepted the datagram."""
        if plan is not self._prepared:
            raise ValueError("plan is not the current prepared retransmission")
        group = self._groups[plan.frame]
        assert group.queued and self._queue[0] == plan.frame
        self._queue.popleft()
        self._queued_bytes -= len(plan.frame.data)
        group.queued = False
        group.retry_count += 1
        group.packet_numbers.add(plan.packet_num)
        self._packet_to_frame[plan.packet_num] = plan.frame
        self._prepared = None

    def abort_send(self, plan: PreparedRetransmission, sent: SentPacketTracker) -> None:
        """Definite send failure: restore queued frame, but do NOT reuse nonce."""
        if plan is not self._prepared:
            raise ValueError("plan is not the current prepared retransmission")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        removed = sent.cancel_sent(plan.packet_num)
        if removed is None or removed.frame != plan.frame:
            raise RuntimeError("prepared packet missing from sent tracker")
        # The queue and retry counter were not modified by prepare_next.
        self._prepared = None

    def on_ack(
        self,
        receipt: AckReceipt,
        sent: SentPacketTracker,
    ) -> tuple[StreamSendFrame, ...]:
        """Cancel all later attempts if ANY packet number for a frame is ACKed.

        Includes packet numbers retired as lost: sent.process_ack() no longer
        knows those numbers, but this queue's bounded attempt history does.
        ACK must be authenticated, replay-checked and validated FIRST.
        """
        if not isinstance(receipt, AckReceipt):
            raise TypeError("receipt must be AckReceipt")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        acked_frames: set[StreamSendFrame] = set()
        for packet_num, frame in self._packet_to_frame.items():
            if any(start <= packet_num <= end for start, end in receipt.ranges):
                acked_frames.add(frame)
        completed: list[StreamSendFrame] = []
        for frame in self._groups:
            if frame not in acked_frames:
                continue
            group = self._groups[frame]
            for packet_num in group.packet_numbers:
                sent.cancel_sent(packet_num)
                self._packet_to_frame.pop(packet_num, None)
            if group.queued:
                self._queue.remove(frame)
                self._queued_bytes -= len(frame.data)
            if self._prepared is not None and self._prepared.frame == frame:
                sent.cancel_sent(self._prepared.packet_num)
                self._prepared = None
            completed.append(frame)
        for frame in completed:
            del self._groups[frame]
        return tuple(completed)
