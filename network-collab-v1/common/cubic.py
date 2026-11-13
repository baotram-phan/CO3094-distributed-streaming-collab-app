"""Minimal, testable CUBIC congestion-window controller for the A/B UDP protocol.

The interface is the existing docs/INTERFACES.md v1 API. A owns this algorithm;
B owns per-connection scheduling, ACK/loss detection, retransmission and flight-size.

Model: RFC 9438 CUBIC cubic function + Reno-friendly growth, Reno slow-start,
0.7 multiplicative loss decrease, 1-MSS timeout and recovery-marker dedup.
This is a first integration implementation, not a full RFC 9438 TCP stack:
no HyStart++, ECN, PRR, spurious-loss undo, or app-limited epoch compensation.
A/B should verify behavior with the packet-loss simulator before deployment.
"""
from __future__ import annotations

import math


class CubicController:
    BETA = 0.7
    C = 0.4

    def __init__(self, mss_bytes: int = 1024):
        if not isinstance(mss_bytes, int) or isinstance(mss_bytes, bool) or mss_bytes <= 0:
            raise ValueError("mss_bytes must be a positive integer")
        self.mss_bytes = mss_bytes
        self._cwnd = float(10 * mss_bytes)
        self._ssthresh = math.inf
        self._w_max = 0.0  # window in MSS-size segments
        self._cwnd_prior = 0.0
        self._epoch: float | None = None
        self._epoch_cwnd = 0.0
        self._k = 0.0
        self._w_est = 0.0
        self._last_recovery_marker: int | None = None
        self._last_now: float | None = None

    @property
    def cwnd_bytes(self) -> int:
        return max(self.mss_bytes, int(self._cwnd))

    @property
    def ssthresh_bytes(self) -> float:
        return self._ssthresh

    @property
    def last_recovery_marker(self) -> int | None:
        return self._last_recovery_marker

    @staticmethod
    def _time(value: float) -> float:
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("now_seconds must be finite and non-negative")
        return float(value)

    def _check_clock(self, now: float) -> None:
        if self._last_now is not None and now < self._last_now:
            raise ValueError("now_seconds must use a monotonic clock")
        self._last_now = now

    def _start_epoch(self, now: float) -> None:
        self._epoch = now
        self._epoch_cwnd = self._cwnd / self.mss_bytes
        if self._w_max <= self._epoch_cwnd:
            self._w_max = self._epoch_cwnd
            self._k = 0.0
        else:
            self._k = ((self._w_max - self._epoch_cwnd) / self.C) ** (1.0 / 3.0)
        self._w_est = self._epoch_cwnd

    def on_ack(self, acked_bytes: int, now_seconds: float, rtt_seconds: float) -> None:
        """Call only for *newly* ACKed DATA bytes, never for duplicate ACKs.

        B must suppress ACK-driven congestion growth for packets sent before
        the current recovery boundary; this API has no ACK packet-number input.
        """
        now = self._time(now_seconds)
        if not isinstance(acked_bytes, int) or isinstance(acked_bytes, bool) or acked_bytes < 0:
            raise ValueError("acked_bytes must be a non-negative integer")
        if not isinstance(rtt_seconds, (int, float)) or not math.isfinite(rtt_seconds) or rtt_seconds <= 0:
            raise ValueError("rtt_seconds must be positive and finite")
        self._check_clock(now)
        if acked_bytes == 0:
            return

        # An ACK cannot plausibly expand cwnd by more than one current window.
        credited = min(acked_bytes, self.cwnd_bytes)
        if self._cwnd < self._ssthresh:
            self._cwnd += credited  # Reno slow start; count ACKed bytes
            return

        if self._epoch is None:
            self._start_epoch(now)

        assert self._epoch is not None
        cwnd_segments = self._cwnd / self.mss_bytes
        newly_acked_segments = credited / self.mss_bytes
        alpha = 3.0 * (1.0 - self.BETA) / (1.0 + self.BETA)
        if self._cwnd_prior > 0 and self._w_est >= self._cwnd_prior:
            alpha = 1.0
        self._w_est += alpha * newly_acked_segments / cwnd_segments

        elapsed = now - self._epoch
        w_cubic = self.C * ((elapsed - self._k) ** 3) + self._w_max
        if w_cubic < self._w_est:
            next_segments = max(cwnd_segments, self._w_est)
        else:
            predicted = self.C * ((elapsed + rtt_seconds - self._k) ** 3) + self._w_max
            target = min(1.5 * cwnd_segments, max(cwnd_segments, predicted))
            delta = (target - cwnd_segments) / cwnd_segments * newly_acked_segments
            next_segments = cwnd_segments + max(0.0, delta)
        # Prevent one batched ACK from causing an unrealistic send burst.
        self._cwnd = min(self._cwnd + credited, next_segments * self.mss_bytes)

    def on_loss(self, now_seconds: float, recovery_marker: int) -> None:
        """One multiplicative decrease per B-defined recovery epoch.

        recovery_marker is the highest DATA packet number sent on this ConnID
        when B enters recovery. Repeat/non-increasing markers are ignored.
        """
        now = self._time(now_seconds)
        if not isinstance(recovery_marker, int) or isinstance(recovery_marker, bool) or recovery_marker < 0:
            raise ValueError("recovery_marker must be a non-negative integer")
        self._check_clock(now)
        if (self._last_recovery_marker is not None
                and recovery_marker <= self._last_recovery_marker):
            return
        self._last_recovery_marker = recovery_marker
        old_cwnd_bytes = self._cwnd
        old = old_cwnd_bytes / self.mss_bytes
        self._cwnd_prior = old
        if self._w_max > 0 and old < self._w_max:
            self._w_max = old * (1.0 + self.BETA) / 2.0  # fast convergence
        else:
            self._w_max = old
        self._ssthresh = max(2.0 * self.mss_bytes, self.BETA * self._cwnd)
        # A late loss indication after an RTO must never INCREASE cwnd.
        self._cwnd = min(old_cwnd_bytes, self._ssthresh)
        self._epoch = None

    def on_timeout(self, now_seconds: float) -> None:
        """RTO congestion reaction. B owns RTO calculation and backoff."""
        now = self._time(now_seconds)
        self._check_clock(now)
        self._cwnd_prior = self._cwnd / self.mss_bytes
        self._ssthresh = max(2.0 * self.mss_bytes, self.BETA * self._cwnd)
        self._cwnd = float(self.mss_bytes)
        self._w_max = 0.0  # next epoch must start from its new slow-start exit
        self._epoch = None
        self._k = 0.0
        self._w_est = 0.0
