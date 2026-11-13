"""B4.2.0 integration: ACK growth, recovery marker, RTO and send wrapper."""
import unittest
from typing import Literal, cast

from common.constants import ACK, DATA, WINDOW_UPDATE
from common.congestion_feedback import CongestionFeedback
from common.cubic import CubicController
from common.reliable_receive import ReliableReceiveState
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamSendFrame
from common.transport import (
    AckReceipt, LostPacket, RttEstimator, SentPacket,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import encode_ack_body, encode_packet

OUT_KEY = bytes(range(32))
IN_KEY = bytes(range(32, 64))
ENDPOINT = ("127.0.0.1", 39009)


class TestCongestionReceive(unittest.TestCase):
    def setUp(self):
        self.r = ReliableReceiveState(TransportConnectionState(808))
        self.ack_pn = 0

    def prepare(self, now=1000) -> PreparedScheduledSend:
        plan = self.r.prepare_send(OUT_KEY, now_ms=now)
        assert plan is not None
        return plan

    def send(self, payload: bytes, now=1000) -> PreparedScheduledSend:
        self.r.streams.queue_bytes(1, payload)
        plan = self.prepare(now)
        self.assertEqual(plan.kind, "new_data")
        self.r.commit_send(plan)
        return plan

    def ack(self, *packet_numbers: int, now=1100):
        ranges = tuple((pn, pn) for pn in sorted(packet_numbers, reverse=True))
        self.ack_pn += 1
        datagram = encode_packet(IN_KEY, ACK, 808, self.ack_pn, encode_ack_body(0, ranges))
        result = self.r.accept(datagram, key=IN_KEY, endpoint=ENDPOINT,
                               bound_endpoint=ENDPOINT, now_ms=now)
        assert result is not None
        return result

    def test_initial_cwnd_is_10_mss(self):
        self.assertEqual(self.r.cubic.cwnd_bytes, 10240)
        self.assertEqual(self.r.congestion.cwnd_bytes, 10240)

    def test_successful_data_send_records_packet_number(self):
        p = self.send(b"hello")
        self.assertEqual(self.r.congestion.highest_sent_data_pn, p.packet_num)
        self.assertEqual(self.r.congestion.tracked_attempts, 1)

    def test_cwnd_grows_by_newly_acked_payload_not_wire_cost(self):
        p = self.send(b"hello")
        self.ack(p.packet_num)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10245)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)

    def test_ack_updates_rtt_milliseconds_to_seconds(self):
        p = self.send(b"hello")
        self.ack(p.packet_num, now=1200)
        self.assertAlmostEqual(self.r.rtt.smoothed_rtt_ms or 0, 200)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10245)

    def test_duplicate_ack_does_not_grow_cwnd(self):
        p = self.send(b"hello")
        self.ack(p.packet_num)
        self.ack(p.packet_num, now=1200)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10245)

    def test_same_ack_datagram_replay_does_not_grow(self):
        p = self.send(b"hello")
        self.ack(p.packet_num)
        self.ack_pn -= 1  # deliberately use same encrypted ACK packet number
        self.ack(p.packet_num, now=1200)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10245)

    def test_multiple_ack_ranges_credit_distinct_frames_once(self):
        a = self.send(b"hello")
        b = self.send(b"world")
        self.ack(a.packet_num, b.packet_num)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10250)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)

    def test_acked_packet_with_no_registered_attempt_never_grows(self):
        frame = StreamSendFrame(1, 0, b"hello")
        self.r.sent.track_sent(7, DATA, 56, 1000, frame=frame)
        self.ack(7)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10240)

    def test_abort_does_not_record_send_or_reuse_packet_num(self):
        self.r.streams.queue_bytes(1, b"hello")
        p = self.prepare()
        self.r.abort_send(p)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)
        p2 = self.prepare(1100)
        self.assertGreater(p2.packet_num, p.packet_num)
        self.assertEqual(p2.frame, p.frame)
        self.r.commit_send(p2)
        self.assertEqual(self.r.congestion.tracked_attempts, 1)

    def test_ack_window_update_does_not_grow_cwnd(self):
        self.r.streams.receive_frame(1, 0, b"abc")
        self.r.flow.note_consumed(1, 3)
        plan = self.prepare()
        self.assertEqual(plan.kind, "window_update")
        self.r.commit_send(plan)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)
        self.ack(plan.packet_num)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10240)

    def test_packet_threshold_loss_enters_single_recovery(self):
        packets = [self.send(bytes([65 + k]) * 1024) for k in range(4)]
        self.ack(*(p.packet_num for p in packets[1:]), now=1100)
        self.assertEqual(self.r.congestion.recovery_marker, packets[-1].packet_num)
        self.assertEqual(self.r.cubic.cwnd_bytes, 7168)
        self.assertEqual(self.r.retries.queued_count, 1)

    def test_recovery_suppresses_growth_from_pre_boundary_ack(self):
        packets = [self.send(bytes([65 + k]) * 1024) for k in range(4)]
        self.ack(*(p.packet_num for p in packets[1:]), now=1100)
        before = self.r.cubic.cwnd_bytes
        # Original lost DATA is already handed to retry queue; ACK arrives late.
        self.ack(packets[0].packet_num, now=1200)
        self.assertEqual(self.r.cubic.cwnd_bytes, before)
        self.assertEqual(self.r.retries.queued_count, 0)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)

    def test_late_original_ack_cancels_retransmission_after_timeout(self):
        p = self.send(b"hello")
        losses = self.r.check_rto(now_ms=1600)
        self.assertEqual(len(losses), 1)
        self.assertEqual(self.r.cubic.cwnd_bytes, 1024)
        retry = self.prepare(1700)
        self.assertEqual(retry.kind, "data_retry")
        self.assertNotEqual(p.packet_num, retry.packet_num)
        self.r.commit_send(retry)
        self.ack(p.packet_num, now=1800)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)
        self.assertEqual(self.r.sent.outstanding_count, 0)
        before = self.r.cubic.cwnd_bytes
        self.ack(retry.packet_num, now=1900)
        self.assertEqual(self.r.cubic.cwnd_bytes, before)

    def test_retry_ack_after_rto_is_counted_once_but_suppressed(self):
        p = self.send(b"hello")
        self.r.check_rto(now_ms=1600)
        retry = self.prepare(1700)
        self.assertEqual(retry.kind, "data_retry")
        self.r.commit_send(retry)
        self.ack(retry.packet_num, now=1800)
        self.assertEqual(self.r.congestion.tracked_attempts, 0)
        self.assertEqual(self.r.cubic.cwnd_bytes, 1029)  # ACK of post-RTO retry
        self.ack(p.packet_num, now=1900)
        self.assertEqual(self.r.cubic.cwnd_bytes, 1029)

    def test_rto_invokes_cubic_once_for_one_batch(self):
        self.send(b"aaa")
        self.send(b"bbb")
        losses = self.r.check_rto(now_ms=1600)
        self.assertEqual(len(losses), 2)
        self.assertEqual(self.r.cubic.cwnd_bytes, 1024)
        self.assertEqual(self.r.rtt.timeout_count, 1)
        self.assertEqual(self.r.congestion.recovery_marker, 1)
        self.assertEqual(self.r.check_rto(now_ms=2000), ())
        self.assertEqual(self.r.rtt.timeout_count, 1)

    def test_rto_does_not_reset_packet_numbers(self):
        p = self.send(b"aaa")
        self.r.check_rto(now_ms=1600)
        retry = self.prepare(1700)
        self.assertGreater(retry.packet_num, p.packet_num)

    def test_ack_after_loss_of_fresh_post_recovery_data_grows(self):
        self.send(b"aaa")
        self.r.check_rto(now_ms=1600)
        self.r.streams.queue_bytes(1, b"fresh")
        p = self.prepare(1700)  # one of DATA / retry (fair scheduler)
        self.assertIn(p.kind, ("new_data", "data_retry"))
        self.r.commit_send(p)
        self.ack(p.packet_num, now=1800)
        self.assertGreater(self.r.cubic.cwnd_bytes, 1024)

    def test_no_cubic_feedback_for_ack_without_new_data(self):
        self.ack(123)
        self.assertEqual(self.r.cubic.cwnd_bytes, 10240)

    def test_timeout_tick_without_outstanding_does_not_reduce_cwnd(self):
        self.assertEqual(self.r.check_rto(now_ms=1500), ())
        self.assertEqual(self.r.cubic.cwnd_bytes, 10240)

    def test_repeated_old_loss_same_epoch_no_second_reduction(self):
        p = self.send(b"hello")
        packet = self.r.sent.get(p.packet_num)
        assert packet is not None
        loss = LostPacket(packet, "packet_threshold", 1200)
        self.assertTrue(self.r.congestion.on_losses((loss,), now_ms=1200))
        cwnd = self.r.cubic.cwnd_bytes
        self.assertFalse(self.r.congestion.on_losses((loss,), now_ms=1250))
        self.assertEqual(self.r.cubic.cwnd_bytes, cwnd)

    def test_new_recovery_epoch_needs_lost_post_boundary_packet(self):
        p = self.send(b"hello")
        packet = self.r.sent.get(p.packet_num)
        assert packet is not None
        self.r.congestion.on_losses((LostPacket(packet, "packet_threshold", 1200),), now_ms=1200)
        initial = self.r.cubic.cwnd_bytes
        later = self.send(b"world", now=1300)
        later_packet = self.r.sent.get(later.packet_num)
        assert later_packet is not None
        self.assertTrue(self.r.congestion.on_losses((LostPacket(later_packet, "packet_threshold", 1400),), now_ms=1400))
        self.assertLess(self.r.cubic.cwnd_bytes, initial)
        self.assertEqual(self.r.congestion.recovery_marker, later.packet_num)


class TestFeedbackStandalone(unittest.TestCase):
    def setUp(self):
        self.cubic = CubicController(mss_bytes=1024)
        self.feedback = CongestionFeedback(self.cubic)

    def plan(
        self,
        pn: int,
        frame: StreamSendFrame | None = None,
        kind: Literal["new_data", "data_retry"] = "new_data",
    ) -> PreparedScheduledSend:
        if frame is None:
            frame = StreamSendFrame(1, pn * 4, b"data")

        return PreparedScheduledSend(
            kind,
            pn,
            b"packet",
            frame.stream_id,
            frame,
        )
    
    def test_feedback_input_validation(self):
        with self.assertRaises(TypeError):
            CongestionFeedback(cast(CubicController, None))
        with self.assertRaises(ValueError):
            CongestionFeedback(self.cubic, max_tracked_attempts=0)
        with self.assertRaises(TypeError):
            self.feedback.note_sent(cast(PreparedScheduledSend, None))

    def test_note_sent_rejects_reused_packet_number(self):
        p = self.plan(4)
        self.feedback.note_sent(p)
        with self.assertRaises(ValueError):
            self.feedback.note_sent(p)

    def test_bounded_attempt_history_prevents_more_data(self):
        feedback = CongestionFeedback(self.cubic, max_tracked_attempts=1)
        self.assertTrue(feedback.can_note_sent())
        feedback.note_sent(self.plan(4))
        self.assertFalse(feedback.can_note_sent())
        with self.assertRaises(BufferError):
            feedback.note_sent(self.plan(5))

    def test_empty_loss_batch_no_congestion_reaction(self):
        self.assertFalse(self.feedback.on_losses((), now_ms=1000))
        self.assertEqual(self.cubic.cwnd_bytes, 10240)

    def test_untracked_loss_does_not_change_congestion(self):
        packet = SentPacket(12, DATA, 1000, 55, StreamSendFrame(1, 0, b"x"))
        self.assertFalse(self.feedback.on_losses((LostPacket(packet, "rto", 1600),), now_ms=1600))
        self.assertEqual(self.cubic.cwnd_bytes, 10240)

    def test_window_loss_does_not_decrease_cwnd_pending_a_signoff(self):
        packet = SentPacket(12, WINDOW_UPDATE, 1000, 48, None)
        self.assertFalse(self.feedback.on_losses((LostPacket(packet, "packet_threshold", 1100),), now_ms=1100))
        self.assertEqual(self.cubic.cwnd_bytes, 10240)

    def test_mixed_loss_batch_only_one_cwnd_reduction(self):
        for pn in range(3):
            self.feedback.note_sent(self.plan(pn))
        losses = tuple(LostPacket(SentPacket(pn, DATA, 1000, 55, StreamSendFrame(1, pn * 4, b"data")),
                                  "packet_threshold", 1500) for pn in range(3))
        self.assertTrue(self.feedback.on_losses(losses, now_ms=1500))
        self.assertEqual(self.feedback.recovery_marker, 2)
        self.assertEqual(self.cubic.cwnd_bytes, 7168)

    def test_ack_with_no_positive_rtt_does_not_fabricate_rtt(self):
        frame = StreamSendFrame(1, 0, b"hello")
        self.feedback.note_sent(self.plan(0, frame))
        receipt = AckReceipt(0, ((0, 0),), (SentPacket(0, DATA, 0, 56, frame),), 56)
        result = self.feedback.on_feedback(receipt, (), RttEstimator(), now_ms=100)
        self.assertEqual(result.newly_credited_bytes, 0)
        self.assertEqual(self.cubic.cwnd_bytes, 10240)
        self.assertEqual(self.feedback.tracked_attempts, 0)

    def test_ack_recovery_filters_acked_packet_number_not_frame_offset(self):
        frame = StreamSendFrame(1, 0, b"hello")
        self.feedback.note_sent(self.plan(1, frame))
        self.feedback.note_sent(self.plan(3, frame, "data_retry"))
        loss = LostPacket(SentPacket(1, DATA, 0, 56, frame), "packet_threshold", 200)
        self.feedback.on_losses((loss,), now_ms=200)
        receipt = AckReceipt(0, ((1, 1),), (), 0)
        rtt = RttEstimator()
        rtt.record_sample(100)
        result = self.feedback.on_feedback(receipt, (frame,), rtt, now_ms=300)
        self.assertEqual(result.suppressed_pre_recovery_bytes, 5)
        self.assertEqual(self.cubic.cwnd_bytes, 7168)
        self.assertEqual(self.feedback.tracked_attempts, 0)

    def test_monotonic_congestion_event_time(self):
        self.feedback.on_losses((), now_ms=1000)
        with self.assertRaises(ValueError):
            self.feedback.on_losses((), now_ms=999)


if __name__ == "__main__":
    unittest.main()
