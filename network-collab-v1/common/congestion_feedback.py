"""B4.2.0: CUBIC feedback adapter for one outgoing UDP connection.

A owns CubicController. B owns ACK/loss/RTO events and their ordering.
No socket, Registry, app callback, thread or timer is created here.

Important: call note_sent() ONLY after successful socket send + scheduler
commit; call on_feedback() AFTER SentPacketTracker.process_ack() and
DataRetransmissionQueue.on_ack(), but BEFORE retiring newly detected losses.
Call on_losses() for the same loss batch before on_feedback(), so ACKs
of pre-recovery packets do not grow the window.
All events are serialized per ConnID. Time input is monotonic milliseconds;
the CUBIC API is monotonic seconds.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from common.constants import DATA
from common.cubic import CubicController
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamSendFrame
from common.transport import AckReceipt, LostPacket, RttEstimator, _clock_ms


@dataclass(frozen=True, slots=True)
class CongestionAckResult:
    """Frames completed once, and payload bytes eligible for cwnd growth."""

    completed_frames: int
    newly_credited_bytes: int
    suppressed_pre_recovery_bytes: int


class CongestionFeedback:
    """Correlate original/retry packet numbers with one logical DATA frame.

    Per-frame attempt metadata remains until the first valid ACK completes the
    frame, then *all* attempts are forgotten. B3 retransmission owns recovery
    and late-ACK cancellation; this adapter does not reimplement it.
    A caller must preflight can_note_sent() before making a new DATA send.
    """

    def __init__(self, cubic: CubicController, *, max_tracked_attempts: int = 16384) -> None:
        if not isinstance(cubic, CubicController):
            raise TypeError("cubic must be CubicController")
        if type(max_tracked_attempts) is not int or max_tracked_attempts < 1:
            raise ValueError("max_tracked_attempts must be positive int")
        self.cubic = cubic
        self.max_tracked_attempts = max_tracked_attempts
        self._attempts: dict[int, StreamSendFrame] = {}
        self._by_frame: dict[StreamSendFrame, set[int]] = {}
        self._highest_sent_data_pn = -1
        self._recovery_boundary = -1
        self._last_event_ms: float | None = None

    @property
    def cwnd_bytes(self) -> int:
        return self.cubic.cwnd_bytes

    @property
    def tracked_attempts(self) -> int:
        return len(self._attempts)

    @property
    def highest_sent_data_pn(self) -> int:
        return self._highest_sent_data_pn

    @property
    def recovery_marker(self) -> int:
        return self._recovery_boundary

    def can_note_sent(self) -> bool:
        return len(self._attempts) < self.max_tracked_attempts

    def note_sent(self, plan: PreparedScheduledSend) -> bool:
        """Record successfully COMMITTED DATA (including retry), never prepared.

        False for WINDOW_UPDATE, whose ACK must not grow CUBIC.
        Do not call after abort_send().
        """
        if not isinstance(plan, PreparedScheduledSend):
            raise TypeError("plan must be PreparedScheduledSend")
        if plan.kind == "window_update":
            return False
        if plan.frame is None or plan.kind not in ("new_data", "data_retry"):
            raise ValueError("DATA send must retain its StreamSendFrame")
        pn = plan.packet_num
        if type(pn) is not int or pn < 0 or pn <= self._highest_sent_data_pn:
            raise ValueError("successful DATA packet numbers must be strictly increasing")
        if not self.can_note_sent():
            raise BufferError("congestion feedback attempt history full")
        self._attempts[pn] = plan.frame
        self._by_frame.setdefault(plan.frame, set()).add(pn)
        self._highest_sent_data_pn = pn
        return True

    def _event_time(self, now_ms: float | int) -> float:
        now = _clock_ms(now_ms)
        if self._last_event_ms is not None and now < self._last_event_ms:
            raise ValueError("congestion feedback timestamps must be monotonic")
        self._last_event_ms = now
        return now / 1000.0

    def on_losses(self, losses: Iterable[LostPacket], *, now_ms: float | int) -> bool:
        """React once per newly crossed recovery epoch, or once per RTO batch.

        Only DATA attempts we *actually sent* participate. WINDOW_UPDATE loss
        is retried separately; its congestion-loss policy awaits A/B signoff.
        Packet-threshold batches invoke one on_loss; RTO batches invoke one
        on_timeout (PacketLossDetector already performed RTT backoff).
        """
        now_sec = self._event_time(now_ms)
        relevant: list[LostPacket] = []
        for loss in losses:
            if not isinstance(loss, LostPacket):
                raise TypeError("losses must contain LostPacket")
            if loss.packet.packet_type == DATA and loss.packet.packet_num in self._attempts:
                relevant.append(loss)
        if not relevant:
            return False
        # New RTO batch: don't separately trigger multiplicative decrease.
        if any(item.reason == "rto" for item in relevant):
            if any(item.packet.packet_num > self._recovery_boundary for item in relevant):
                self.cubic.on_timeout(now_sec)
                self._recovery_boundary = self._highest_sent_data_pn
                return True
            return False
        if any(item.packet.packet_num > self._recovery_boundary for item in relevant):
            marker = self._highest_sent_data_pn
            self.cubic.on_loss(now_sec, marker)
            self._recovery_boundary = marker
            return True
        return False

    def on_feedback(
        self,
        receipt: AckReceipt,
        completed_retry_frames: Iterable[StreamSendFrame],
        rtt: RttEstimator,
        *,
        now_ms: float | int,
    ) -> CongestionAckResult:
        """Grow cwnd from distinct delivered DATA frames, never ACK packet bytes.

        A completed retry frame can be confirmed by an old, already-retired
        packet number. Thus match the authenticated ACK ranges against our
        successful-attempt history, not only receipt.newly_acked.
        """
        now_sec = self._event_time(now_ms)
        if not isinstance(receipt, AckReceipt):
            raise TypeError("receipt must be AckReceipt")
        if not isinstance(rtt, RttEstimator):
            raise TypeError("rtt must be RttEstimator")
        completed = {packet.frame for packet in receipt.newly_acked if packet.packet_type == DATA and packet.frame is not None}
        for frame in completed_retry_frames:
            if not isinstance(frame, StreamSendFrame):
                raise TypeError("completed_retry_frames must contain StreamSendFrame")
            completed.add(frame)

        eligible = 0
        suppressed = 0
        counted = 0
        for frame in completed:
            attempts = self._by_frame.get(frame)
            if not attempts:
                continue  # not committed through this adapter
            acked_pns = (
                pn for pn in attempts
                if any(start <= pn <= end for start, end in receipt.ranges)
            )
            acked_pn = max(acked_pns, default=None)
            if acked_pn is None:
                continue
            counted += 1
            if acked_pn <= self._recovery_boundary:
                suppressed += len(frame.data)
            else:
                eligible += len(frame.data)
            for pn in attempts:
                del self._attempts[pn]
            del self._by_frame[frame]

        # Never manufacture an RTT. Duplicate ACKs cannot grow cwnd.
        srtt_ms = rtt.smoothed_rtt_ms
        if eligible and srtt_ms is not None and srtt_ms > 0:
            self.cubic.on_ack(eligible, now_sec, srtt_ms / 1000.0)
        return CongestionAckResult(counted, eligible if srtt_ms is not None and srtt_ms > 0 else 0, suppressed)
