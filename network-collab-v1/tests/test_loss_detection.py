"""All times are synthetic monotonic milliseconds; no real UDP network or sleeps.
"""
from __future__ import annotations

import math
import unittest
from dataclasses import FrozenInstanceError
from typing import cast

from common.constants import ACK, DATA, PING
from common.streams import StreamSendFrame
from common.transport import (
    PACKET_LOSS_THRESHOLD,
    AckReceipt,
    LostPacket,
    PacketLossDetector,
    RttEstimator,
    SentPacketTracker,
)
from common.udp_packet import encode_ack_body


def make_sent(*numbers: int, time_ms: float = 0) -> SentPacketTracker:
    sent = SentPacketTracker()
    for number in numbers:
        sent.track_sent(number, PING, 64, time_ms)
    return sent


def ack(sent: SentPacketTracker, *nums: int):
    if not nums:
        raise ValueError("test helper needs ACKed packet numbers")
    ranges = [(n, n) for n in sorted(set(nums), reverse=True)]
    return sent.process_ack(encode_ack_body(0, ranges))


def numbers(losses: tuple[LostPacket, ...]) -> list[int]:
    return [loss.packet.packet_num for loss in losses]


class TestReadOnlyOutstandingSnapshot(unittest.TestCase):
    def test_snapshot_is_tuple(self):
        sent = make_sent(10, 11)
        self.assertIsInstance(sent.outstanding_packets(), tuple)
        self.assertEqual([p.packet_num for p in sent.outstanding_packets()], [10, 11])

    def test_snapshot_does_not_change_after_tracker_retires(self):
        sent = make_sent(10, 11)
        snapshot = sent.outstanding_packets()
        ack(sent, 11)
        self.assertEqual([p.packet_num for p in snapshot], [10, 11])
        self.assertEqual([p.packet_num for p in sent.outstanding_packets()], [10])

    def test_old_b31_tracking_and_bytes_unchanged(self):
        sent = make_sent(10, 11, 12)
        self.assertEqual(sent.outstanding_count, 3)
        self.assertEqual(sent.bytes_in_flight, 192)
        _ = sent.outstanding_packets()
        self.assertEqual(sent.outstanding_count, 3)
        self.assertEqual(sent.bytes_in_flight, 192)


class TestPacketThresholdLoss(unittest.TestCase):
    def test_protocol_threshold_is_three(self):
        self.assertEqual(PACKET_LOSS_THRESHOLD, 3)

    def test_less_than_three_later_acks_do_not_mark_loss(self):
        sent = make_sent(10, 11, 12, 13)
        loss = PacketLossDetector()
        receipt = ack(sent, 11, 12)
        self.assertEqual(loss.on_ack(receipt, sent, 10), ())
        self.assertIsNotNone(sent.get(10))

    def test_three_later_ack_packets_mark_old_packet_lost(self):
        sent = make_sent(10, 11, 12, 13)
        loss = PacketLossDetector()
        result = loss.on_ack(ack(sent, 11, 12, 13), sent, 10)
        self.assertEqual(numbers(result), [10])
        self.assertEqual(result[0].reason, "packet_threshold")
        self.assertEqual(result[0].detected_at_ms, 10)

    def test_exactly_three_later_acks_from_separate_ack_datagrams(self):
        sent = make_sent(10, 11, 12, 13)
        loss = PacketLossDetector()
        self.assertEqual(loss.on_ack(ack(sent, 11), sent, 10), ())
        self.assertEqual(loss.on_ack(ack(sent, 12), sent, 20), ())
        self.assertEqual(numbers(loss.on_ack(ack(sent, 13), sent, 30)), [10])

    def test_packet_numbers_gap_alone_does_not_trigger_loss(self):
        sent = make_sent(10, 100)
        loss = PacketLossDetector()
        self.assertEqual(loss.on_ack(ack(sent, 100), sent, 10), ())
        self.assertIsNotNone(sent.get(10))

    def test_ack_only_packet_numbers_do_not_count(self):
        sent = SentPacketTracker()
        sent.track_sent(10, PING, 64, 0)
        for n in (11, 13, 15):
            self.assertFalse(sent.track_sent(n, ACK, 36, 0))
            if n != 15:
                sent.track_sent(n + 1, PING, 64, 0)
        loss = PacketLossDetector()
        self.assertEqual(loss.on_ack(ack(sent, 12, 14), sent, 10), ())
        self.assertIsNotNone(sent.get(10))

    def test_ack_of_unknown_packet_does_not_count(self):
        sent = make_sent(10, 11, 12)
        loss = PacketLossDetector()
        receipt = sent.process_ack(encode_ack_body(0, [(999, 999)]))
        self.assertEqual(receipt.newly_acked, ())
        self.assertEqual(loss.on_ack(receipt, sent, 10), ())
        self.assertEqual(loss.largest_acked_packets, ())

    def test_ack_received_twice_does_not_count_twice(self):
        sent = make_sent(10, 11, 12, 13)
        loss = PacketLossDetector()
        self.assertEqual(loss.on_ack(ack(sent, 11), sent, 10), ())
        for i in range(3):
            self.assertEqual(loss.on_ack(ack(sent, 11), sent, 11 + i), ())
        self.assertEqual(loss.on_ack(ack(sent, 12), sent, 15), ())
        self.assertEqual(numbers(loss.on_ack(ack(sent, 13), sent, 20)), [10])

    def test_multiple_older_packets_can_be_flagged_together(self):
        sent = make_sent(7, 8, 9, 10, 11, 12)
        loss = PacketLossDetector()
        self.assertEqual(numbers(loss.on_ack(ack(sent, 10, 11, 12), sent, 20)), [7, 8, 9])

    def test_only_unacked_packets_are_marked_lost(self):
        sent = make_sent(7, 8, 9, 10, 11, 12)
        loss = PacketLossDetector()
        result = loss.on_ack(ack(sent, 7, 10, 11, 12), sent, 20)
        self.assertEqual(numbers(result), [8, 9])

    def test_reordering_old_ack_does_not_break_newer_threshold(self):
        sent = make_sent(10, 11, 12, 13, 14, 15)
        loss = PacketLossDetector()
        self.assertEqual(loss.on_ack(ack(sent, 13, 15), sent, 10), ())
        self.assertEqual(loss.largest_acked_packets, (15, 13))
        self.assertEqual(numbers(loss.on_ack(ack(sent, 11), sent, 11)), [10])
        self.assertEqual(numbers(loss.on_ack(ack(sent, 14), sent, 12)), [12])
        self.assertEqual(loss.largest_acked_packets, (15, 14, 13))

    def test_ack_evidence_keeps_only_top_three(self):
        sent = make_sent(*range(1, 31))
        loss = PacketLossDetector()
        for n in range(10, 31):
            loss.on_ack(ack(sent, n), sent, 10 + n)
        self.assertEqual(loss.largest_acked_packets, (30, 29, 28))

    def test_packet_threshold_reported_only_once(self):
        sent = make_sent(10, 11, 12, 13, 14)
        loss = PacketLossDetector()
        self.assertEqual(numbers(loss.on_ack(ack(sent, 11, 12, 13), sent, 20)), [10])
        self.assertEqual(loss.on_ack(ack(sent, 14), sent, 21), ())
        self.assertEqual(loss.pending_loss_reports, 1)

    def test_loss_does_not_remove_packets_or_flight_bytes(self):
        sent = make_sent(10, 11, 12, 13)
        original = sent.bytes_in_flight
        loss = PacketLossDetector()
        loss.on_ack(ack(sent, 11, 12, 13), sent, 10)
        self.assertEqual(sent.bytes_in_flight, original - 3 * 64)
        self.assertIsNotNone(sent.get(10))

    def test_late_ack_of_reported_packet_does_not_report_it_again(self):
        sent = make_sent(10, 11, 12, 13, 14)
        loss = PacketLossDetector()
        loss.on_ack(ack(sent, 11, 12, 13), sent, 20)
        self.assertEqual(loss.pending_loss_reports, 1)
        self.assertEqual(loss.on_ack(ack(sent, 10), sent, 21), ())
        self.assertEqual(loss.pending_loss_reports, 0)
        self.assertEqual(loss.on_ack(ack(sent, 14), sent, 22), ())

    def test_abandoned_packet_frees_report_marker_next_check(self):
        sent = make_sent(10, 11, 12, 13)
        loss = PacketLossDetector()
        loss.on_ack(ack(sent, 11, 12, 13), sent, 20)
        sent.cancel_sent(10)
        loss.on_ack(ack(sent, 12), sent, 21)
        self.assertEqual(loss.pending_loss_reports, 0)

    def test_packet_number_near_uint64_max(self):
        high = (1 << 64) - 1
        sent = make_sent(high - 3, high - 2, high - 1, high)
        loss = PacketLossDetector()
        self.assertEqual(numbers(loss.on_ack(ack(sent, high - 2, high - 1, high), sent, 10)), [high - 3])

    def test_no_rtt_backoff_from_packet_threshold(self):
        sent = make_sent(10, 11, 12, 13)
        rtt = RttEstimator()
        loss = PacketLossDetector()
        loss.on_ack(ack(sent, 11, 12, 13), sent, 50)
        self.assertEqual(rtt.rto_ms, 500)
        self.assertEqual(rtt.timeout_count, 0)


class TestRtoTimeoutLoss(unittest.TestCase):
    def test_default_rto_before_500_ms(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(detector.check_timeouts(sent, rtt, 499.99), ())
        self.assertEqual(rtt.timeout_count, 0)

    def test_timeout_at_exactly_500_ms(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        result = detector.check_timeouts(sent, rtt, 500)
        self.assertEqual(numbers(result), [10])
        self.assertEqual(result[0].reason, "rto")
        self.assertEqual(rtt.rto_ms, 1000)
        self.assertEqual(rtt.timeout_count, 1)

    def test_delayed_send_uses_own_sent_timestamp(self):
        sent = make_sent(10, time_ms=120)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(detector.check_timeouts(sent, rtt, 619), ())
        self.assertEqual(numbers(detector.check_timeouts(sent, rtt, 620)), [10])

    def test_one_backoff_for_multiple_timeouts_at_once(self):
        sent = make_sent(10, 11, 12)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        result = detector.check_timeouts(sent, rtt, 500)
        self.assertEqual(numbers(result), [10, 11, 12])
        self.assertEqual(rtt.timeout_count, 1)
        self.assertEqual(rtt.rto_ms, 1000)

    def test_no_repeat_backoff_on_repeated_polls(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.check_timeouts(sent, rtt, 500)
        for n in (500, 1000, 5000):
            self.assertEqual(detector.check_timeouts(sent, rtt, n), ())
        self.assertEqual(rtt.timeout_count, 1)

    def test_rtt_sample_changes_timeout_deadline(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        rtt.record_sample(100)
        self.assertEqual(rtt.rto_ms, 300)
        self.assertEqual(detector.check_timeouts(sent, rtt, 299.9), ())
        self.assertEqual(numbers(detector.check_timeouts(sent, rtt, 300)), [10])
        self.assertEqual(rtt.rto_ms, 600)

    def test_rto_cap_applied_after_repeated_timeout_batches(self):
        sent = make_sent(1, 2, 3, 4)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(numbers(detector.check_timeouts(sent, rtt, 500)), [1, 2, 3, 4])
        self.assertEqual(rtt.rto_ms, 1000)
        # No new sends can timeout again; scheduler handles retries in B3.2.3.
        self.assertEqual(detector.check_timeouts(sent, rtt, 8000), ())
        self.assertEqual(rtt.timeout_count, 1)

    def test_rto_after_backoff_used_for_newer_packet(self):
        sent = make_sent(10, time_ms=0)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.check_timeouts(sent, rtt, 500)
        sent.track_sent(11, PING, 64, 501)
        self.assertEqual(detector.check_timeouts(sent, rtt, 1500), ())
        self.assertEqual(numbers(detector.check_timeouts(sent, rtt, 1501)), [11])
        self.assertEqual(rtt.rto_ms, 2000)

    def test_explicitly_acknowledged_packet_not_timed_out(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.on_ack(ack(sent, 10), sent, 200)
        self.assertEqual(detector.check_timeouts(sent, rtt, 1000), ())
        self.assertEqual(rtt.timeout_count, 0)

    def test_already_threshold_lost_packet_not_rto_lost_again(self):
        sent = make_sent(10, 11, 12, 13)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(numbers(detector.on_ack(ack(sent, 11, 12, 13), sent, 100)), [10])
        self.assertEqual(detector.check_timeouts(sent, rtt, 1000), ())
        self.assertEqual(rtt.timeout_count, 0)

    def test_loss_does_not_change_tracker_bytes_in_flight(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.check_timeouts(sent, rtt, 500)
        self.assertEqual(sent.outstanding_count, 1)
        self.assertEqual(sent.bytes_in_flight, 64)

    def test_timeout_on_data_keeps_original_stream_frame(self):
        sent = SentPacketTracker()
        frame = StreamSendFrame(2, 4096, b"file bytes", False)
        sent.track_sent(10, DATA, 64, 0, frame=frame)
        result = PacketLossDetector().check_timeouts(sent, RttEstimator(), 500)
        self.assertEqual(result[0].packet.frame, frame)
        self.assertEqual(result[0].packet.packet_num, 10)

    def test_no_pending_packets_no_timeout_or_backoff(self):
        sent = SentPacketTracker()
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(detector.check_timeouts(sent, rtt, 99999), ())
        self.assertEqual(rtt.rto_ms, 500)

    def test_ack_only_never_added_to_outstanding(self):
        sent = SentPacketTracker()
        self.assertFalse(sent.track_sent(10, ACK, 36, 0))
        detector = PacketLossDetector()
        rtt = RttEstimator()
        self.assertEqual(detector.check_timeouts(sent, rtt, 20000), ())
        self.assertEqual(rtt.timeout_count, 0)


class TestLossDetectorRobustness(unittest.TestCase):
    def test_invalid_receipt_type(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        with self.assertRaises(TypeError):
            detector.on_ack(cast(AckReceipt, None), sent, 500)

    def test_invalid_tracker_type(self):
        detector = PacketLossDetector()
        rtt = RttEstimator()
        with self.assertRaises(TypeError):
            detector.check_timeouts(cast(SentPacketTracker, None), rtt, 100)

    def test_invalid_rtt_type(self):
        detector = PacketLossDetector()
        with self.assertRaises(TypeError):
            detector.check_timeouts(make_sent(10), cast(RttEstimator, None), 100)

    def test_invalid_clock_types_and_values(self):
        for invalid in (-1, math.nan, math.inf, -math.inf, True, "100", None):
            with self.subTest(invalid=invalid):
                detector = PacketLossDetector()
                sent = make_sent(10)
                with self.assertRaises(ValueError):
                    detector.check_timeouts(sent, RttEstimator(), cast(float, invalid))
                self.assertEqual(detector.pending_loss_reports, 0)

    def test_monotonic_clock_cannot_go_backwards(self):
        sent = make_sent(10)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.check_timeouts(sent, rtt, 100)
        with self.assertRaises(ValueError):
            detector.check_timeouts(sent, rtt, 99)
        self.assertEqual(rtt.timeout_count, 0)

    def test_future_send_time_rejected_without_mutation(self):
        sent = make_sent(10, time_ms=200)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        with self.assertRaises(ValueError):
            detector.check_timeouts(sent, rtt, 100)
        self.assertEqual(detector.pending_loss_reports, 0)
        self.assertEqual(rtt.timeout_count, 0)

    def test_connection_states_are_independent(self):
        first, second = make_sent(10, 11, 12, 13), make_sent(10, 11, 12, 13)
        first_det, second_det = PacketLossDetector(), PacketLossDetector()
        self.assertEqual(numbers(first_det.on_ack(ack(first, 11, 12, 13), first, 10)), [10])
        self.assertEqual(second_det.largest_acked_packets, ())
        self.assertEqual(second_det.pending_loss_reports, 0)
        self.assertEqual(first_det.pending_loss_reports, 1)

    def test_old_ack_after_later_timeout_does_not_double_report(self):
        sent = make_sent(10, 11, 12, 13)
        detector = PacketLossDetector()
        rtt = RttEstimator()
        detector.check_timeouts(sent, rtt, 500)
        receipt = ack(sent, 11, 12, 13)
        self.assertEqual(detector.on_ack(receipt, sent, 501), ())
        self.assertEqual(detector.pending_loss_reports, 1)

    def test_lost_packet_contents_immutable(self):
        sent = make_sent(10)
        loss = PacketLossDetector().check_timeouts(sent, RttEstimator(), 500)[0]
        with self.assertRaises(FrozenInstanceError):
            setattr(loss, "reason", "other")

    def test_returned_losses_sorted_by_packet_number(self):
        sent = make_sent(20, 21, 22)
        got = PacketLossDetector().check_timeouts(sent, RttEstimator(), 500)
        self.assertEqual(numbers(got), [20, 21, 22])

    def test_no_implicit_packet_number_allocation(self):
        sent = make_sent(10, 11, 12, 13)
        detector = PacketLossDetector()
        detector.on_ack(ack(sent, 11, 12, 13), sent, 10)
        with self.assertRaises(ValueError):
            sent.track_sent(13, PING, 64, 10)


if __name__ == "__main__":
    unittest.main()
