"""B3.2.1 — sender RTT estimator + RTO tests against Protocol §6.2."""
from __future__ import annotations

import math
import unittest
from typing import cast

from common.constants import DATA, PING
from common.streams import StreamSendFrame
from common.transport import (
    AckReceipt,
    ACK_DELAY_CAP_MS,
    ConnectionAckState,
    RTO_INIT_MS,
    RTO_MAX_MS,
    RTO_MIN_MS,
    RttEstimator,
    SentPacket,
    SentPacketTracker,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import encode_ack_body


def sent_packet(n: int, at_ms: float, size: int = 64) -> SentPacket:
    return SentPacket(n, PING, at_ms, size)


class TestRttEstimatorDefaults(unittest.TestCase):
    def test_protocol_constants(self):
        self.assertEqual((RTO_INIT_MS, RTO_MIN_MS, RTO_MAX_MS, ACK_DELAY_CAP_MS), (500, 100, 3000, 25))

    def test_no_samples_initial_values(self):
        rtt = RttEstimator()
        self.assertIsNone(rtt.smoothed_rtt_ms)
        self.assertIsNone(rtt.rttvar_ms)
        self.assertIsNone(rtt.latest_rtt_ms)
        self.assertIsNone(rtt.last_adjusted_rtt_ms)
        self.assertEqual(rtt.base_rto_ms, 500)
        self.assertEqual(rtt.rto_ms, 500)
        self.assertEqual(rtt.sample_count, 0)

    def test_first_sample_initializes_srtt_and_rttvar(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(200), 200)
        self.assertEqual(rtt.latest_rtt_ms, 200)
        self.assertEqual(rtt.smoothed_rtt_ms, 200)
        self.assertEqual(rtt.rttvar_ms, 100)
        self.assertEqual(rtt.base_rto_ms, 600)
        self.assertEqual(rtt.sample_count, 1)

    def test_second_sample_ewma(self):
        rtt = RttEstimator()
        rtt.record_sample(200)
        rtt.record_sample(100)
        assert rtt.rttvar_ms is not None
        self.assertAlmostEqual(rtt.rttvar_ms, 100.0)
        assert rtt.smoothed_rtt_ms is not None
        self.assertAlmostEqual(rtt.smoothed_rtt_ms, 187.5)
        self.assertAlmostEqual(rtt.rto_ms, 587.5)
        self.assertEqual(rtt.sample_count, 2)

    def test_third_sample_uses_updated_state(self):
        rtt = RttEstimator()
        for n in (100, 100, 100):
            rtt.record_sample(n)
        assert rtt.smoothed_rtt_ms is not None
        self.assertAlmostEqual(rtt.smoothed_rtt_ms, 100)
        assert rtt.rttvar_ms is not None
        self.assertAlmostEqual(rtt.rttvar_ms, 28.125)
        self.assertAlmostEqual(rtt.rto_ms, 212.5)

    def test_min_rto_clamp(self):
        rtt = RttEstimator()
        for _ in range(8):
            rtt.record_sample(1)
        self.assertEqual(rtt.rto_ms, RTO_MIN_MS)

    def test_max_rto_clamp(self):
        rtt = RttEstimator()
        rtt.record_sample(10_000)
        self.assertEqual(rtt.rto_ms, RTO_MAX_MS)

    def test_rto_calculation_retains_submillisecond_precision(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(100.25), 100.25)
        self.assertAlmostEqual(rtt.base_rto_ms, 300.75)

    def test_rtt_zero_is_allowed_and_never_negative(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(0), 0)
        self.assertEqual(rtt.smoothed_rtt_ms, 0)
        self.assertEqual(rtt.rto_ms, RTO_MIN_MS)

    def test_short_rtt_ack_delay_larger_than_rtt(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(10, ack_delay_ms=25), 0)
        self.assertEqual(rtt.last_adjusted_rtt_ms, 0)

    def test_ack_delay_is_subtracted(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(115, ack_delay_ms=15), 100)
        self.assertEqual(rtt.latest_rtt_ms, 115)
        self.assertEqual(rtt.smoothed_rtt_ms, 100)

    def test_ack_delay_is_capped_at_25_ms(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(100, ack_delay_ms=65_535), 75)
        self.assertEqual(rtt.rttvar_ms, 37.5)

    def test_ack_delay_zero(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.record_sample(117, ack_delay_ms=0), 117)

    def test_no_mutation_on_bad_sample_type_or_value(self):
        rtt = RttEstimator()
        rtt.record_sample(123)
        old = (rtt.sample_count, rtt.rto_ms, rtt.smoothed_rtt_ms, rtt.rttvar_ms)
        for value in (-1, math.inf, -math.inf, math.nan, True, None, "100"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rtt.record_sample(cast(float, value))
            self.assertEqual((rtt.sample_count, rtt.rto_ms, rtt.smoothed_rtt_ms, rtt.rttvar_ms), old)

    def test_no_mutation_on_bad_ack_delay(self):
        rtt = RttEstimator()
        rtt.record_sample(120)
        old = (rtt.sample_count, rtt.rto_ms)
        for value in (-1, 65536, True, 1.0, None, "10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rtt.record_sample(100, ack_delay_ms=cast(int, value))
            self.assertEqual((rtt.sample_count, rtt.rto_ms), old)


class TestTimeoutBackoff(unittest.TestCase):
    def test_initial_timeout_doubles(self):
        rtt = RttEstimator()
        self.assertEqual(rtt.on_timeout(), 1000)
        self.assertEqual(rtt.timeout_count, 1)

    def test_multiple_timeouts_saturate_at_3000(self):
        rtt = RttEstimator()
        self.assertEqual([rtt.on_timeout() for _ in range(5)], [1000, 2000, 3000, 3000, 3000])
        self.assertEqual(rtt.base_rto_ms, 500)
        self.assertEqual(rtt.timeout_count, 5)

    def test_backoff_after_samples_uses_current_rto(self):
        rtt = RttEstimator()
        rtt.record_sample(100)
        self.assertEqual(rtt.rto_ms, 300)
        self.assertEqual(rtt.on_timeout(), 600)
        self.assertEqual(rtt.on_timeout(), 1200)

    def test_successful_new_sample_resets_backoff(self):
        rtt = RttEstimator()
        rtt.record_sample(100)
        rtt.on_timeout()
        rtt.on_timeout()
        self.assertGreater(rtt.rto_ms, rtt.base_rto_ms)
        rtt.record_sample(100)
        self.assertEqual(rtt.rto_ms, rtt.base_rto_ms)
        self.assertEqual(rtt.timeout_count, 0)

    def test_timeout_does_not_overwrite_rtt_statistics(self):
        rtt = RttEstimator()
        rtt.record_sample(155)
        state = (rtt.latest_rtt_ms, rtt.smoothed_rtt_ms, rtt.rttvar_ms, rtt.sample_count)
        rtt.on_timeout()
        self.assertEqual((rtt.latest_rtt_ms, rtt.smoothed_rtt_ms, rtt.rttvar_ms, rtt.sample_count), state)

    def test_timeout_after_max_base_stays_max(self):
        rtt = RttEstimator()
        rtt.record_sample(5000)
        self.assertEqual(rtt.on_timeout(), 3000)


class TestAckReceiptIntegration(unittest.TestCase):
    def make_tracker(self) -> SentPacketTracker:
        return SentPacketTracker()

    def test_single_new_ack_samples_rtt(self):
        sent = self.make_tracker()
        sent.track_sent(10, PING, 64, 100)
        ack = sent.process_ack(encode_ack_body(10, [(10, 10)]))
        rtt = RttEstimator()
        self.assertEqual(rtt.record_ack(ack, 220), 110)
        self.assertEqual(rtt.smoothed_rtt_ms, 110)

    def test_multiple_new_acked_only_one_sample(self):
        sent = self.make_tracker()
        sent.track_sent(10, PING, 64, 100)
        sent.track_sent(11, PING, 64, 120)
        sent.track_sent(12, PING, 64, 140)
        receipt = sent.process_ack(encode_ack_body(5, [(10, 12)]))
        rtt = RttEstimator()
        self.assertEqual(rtt.record_ack(receipt, 190), 45)
        self.assertEqual(rtt.sample_count, 1)

    def test_ack_ranges_highest_can_be_untracked(self):
        sent = self.make_tracker()
        sent.track_sent(10, PING, 64, 100)
        receipt = sent.process_ack(encode_ack_body(0, [(20, 20), (10, 10)]))
        rtt = RttEstimator()
        self.assertEqual(rtt.record_ack(receipt, 180), 80)

    def test_duplicate_ack_never_adds_sample(self):
        sent = self.make_tracker()
        sent.track_sent(10, PING, 64, 100)
        body = encode_ack_body(0, [(10, 10)])
        rtt = RttEstimator()
        self.assertEqual(rtt.record_ack(sent.process_ack(body), 180), 80)
        self.assertIsNone(rtt.record_ack(sent.process_ack(body), 200))
        self.assertEqual(rtt.sample_count, 1)

    def test_unknown_ack_does_not_add_sample(self):
        sent = self.make_tracker()
        rtt = RttEstimator()
        receipt = sent.process_ack(encode_ack_body(0, [(10000, 10000)]))
        self.assertIsNone(rtt.record_ack(receipt, 99))
        self.assertEqual(rtt.sample_count, 0)

    def test_old_duplicate_ack_does_not_reset_timeout(self):
        sent = self.make_tracker()
        sent.track_sent(1, PING, 64, 100)
        body = encode_ack_body(0, [(1, 1)])
        rtt = RttEstimator()
        rtt.record_ack(sent.process_ack(body), 200)
        rtt.on_timeout()
        old_rto = rtt.rto_ms
        self.assertIsNone(rtt.record_ack(sent.process_ack(body), 220))
        self.assertEqual(rtt.rto_ms, old_rto)
        self.assertEqual(rtt.timeout_count, 1)

    def test_ack_of_data_frame_uses_packet_send_timestamp(self):
        sent = self.make_tracker()
        frame = StreamSendFrame(1, 0, b"hi", False)
        sent.track_sent(5, DATA, 60, 10, frame=frame)
        receipt = sent.process_ack(encode_ack_body(20, [(5, 5)]))
        rtt = RttEstimator()
        self.assertEqual(rtt.record_ack(receipt, 130), 100)
        self.assertIs(receipt.newly_acked[0].frame, frame)

    def test_invalid_receipt_type(self):
        with self.assertRaises(TypeError):
            RttEstimator().record_ack(cast(AckReceipt, None), 100)

    def test_bad_receipt_time_no_mutation(self):
        rtt = RttEstimator()
        ack = AckReceipt(0, ((1, 1),), (sent_packet(1, 100),), 64)
        for value in (-1, math.nan, math.inf, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rtt.record_ack(ack, cast(float, value))
            self.assertEqual(rtt.sample_count, 0)

    def test_ack_received_before_send_timestamp_rejected(self):
        rtt = RttEstimator()
        ack = AckReceipt(0, ((1, 1),), (sent_packet(1, 101),), 64)
        with self.assertRaises(ValueError):
            rtt.record_ack(ack, 100)
        self.assertIsNone(rtt.smoothed_rtt_ms)

    def test_bad_ack_delay_receipt_rejected(self):
        rtt = RttEstimator()
        for value in (-1, 65536, True):
            ack = AckReceipt(cast(int, value), ((1, 1),), (sent_packet(1, 50),), 64)
            with self.subTest(value=value), self.assertRaises(ValueError):
                rtt.record_ack(ack, 100)
            self.assertEqual(rtt.sample_count, 0)

    def test_bad_receipt_delay_even_if_no_packets(self):
        rtt = RttEstimator()
        receipt = AckReceipt(-1, ((1, 1),), (), 0)
        with self.assertRaises(ValueError):
            rtt.record_ack(receipt, 100)

    def test_ack_sent_timestamp_nan_rejected(self):
        rtt = RttEstimator()
        receipt = AckReceipt(0, ((1, 1),), (sent_packet(1, math.nan),), 64)
        with self.assertRaises(ValueError):
            rtt.record_ack(receipt, 100)

    def test_ack_received_exactly_at_sent_time(self):
        ack = AckReceipt(0, ((7, 7),), (sent_packet(7, 100),), 64)
        self.assertEqual(RttEstimator().record_ack(ack, 100), 0)

    def test_time_origin_independent_of_absolute_clock(self):
        ack1 = AckReceipt(0, ((2, 2),), (sent_packet(2, 1_000_000),), 64)
        ack2 = AckReceipt(0, ((2, 2),), (sent_packet(2, 100),), 64)
        self.assertEqual(RttEstimator().record_ack(ack1, 1_000_100), RttEstimator().record_ack(ack2, 200))

    def test_distinct_connection_estimators_do_not_share_rtt(self):
        one = RttEstimator()
        two = RttEstimator()
        one.record_sample(100)
        self.assertEqual(two.rto_ms, 500)
        self.assertIsNone(two.smoothed_rtt_ms)

    def test_real_connection_state_allocator_not_changed(self):
        state = TransportConnectionState(conn_id=22)
        rtt = RttEstimator()
        rtt.record_sample(150)
        rtt.on_timeout()
        self.assertEqual(state.allocate_packet_number(), 0)


if __name__ == "__main__":
    unittest.main()
