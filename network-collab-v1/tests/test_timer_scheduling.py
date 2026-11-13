"""B4.3.1: deterministic ACK-deadline/RTO tick; NO real sleeping or sockets.

This tests the actual protocol state, never fake 'PASS' based on print output.
The UDP event-loop and sendto integration remain B4.3.2.
"""
from __future__ import annotations

import math
import unittest
from typing import cast

from common.constants import ACK, DATA, WINDOW_UPDATE
from common.reliable_receive import ReliableReceiveState, TimerTickResult
from common.transport import ReceivedPacketAckTracker
from common.transport_state import TransportConnectionState
from common.udp_packet import encode_ack_body, encode_packet

KEY_C2S = bytes(range(32))
KEY_S2C = bytes(range(32, 64))
CONN_ID = 7321


def state() -> ReliableReceiveState:
    return ReliableReceiveState(TransportConnectionState(CONN_ID))


def committed_data(sender: ReliableReceiveState, *, t: float = 100.0, payload: bytes = b"hello"):
    sender.streams.queue_bytes(1, payload)
    plan = sender.prepare_send(KEY_C2S, now_ms=t)
    assert plan is not None
    assert plan.kind == "new_data"
    sender.commit_send(plan)  # simulate successful sendto; payload may be dropped in network
    return plan


class TestAckClock(unittest.TestCase):
    def setUp(self) -> None:
        self.acks = ReceivedPacketAckTracker()

    def test_ack_only_never_schedules_ack(self):
        self.assertFalse(self.acks.note_received(7, ACK, 100))
        self.assertIsNone(self.acks.ack_pending_since_ms)
        self.assertFalse(self.acks.ack_due(100000))
        self.assertFalse(self.acks.ack_pending)

    def test_data_ack_is_due_at_25ms_not_before(self):
        self.assertTrue(self.acks.note_received(1, DATA, 100))
        self.assertEqual(self.acks.ack_pending_since_ms, 100)
        self.assertFalse(self.acks.ack_due(124.999))
        self.assertTrue(self.acks.ack_due(125))

    def test_window_update_also_elicits_ack(self):
        self.acks.note_received(1, WINDOW_UPDATE, 0)
        self.assertFalse(self.acks.ack_due(24))
        self.assertTrue(self.acks.ack_due(25))

    def test_immediate_ack_mode_allowed(self):
        self.acks.note_received(1, DATA, 99)
        self.assertTrue(self.acks.ack_due(99, max_delay_ms=0))

    def test_receiving_more_data_does_not_reset_earliest_deadline(self):
        self.acks.note_received(1, DATA, 100)
        self.acks.note_received(2, DATA, 119)
        self.assertEqual(self.acks.ack_pending_since_ms, 100)
        self.assertTrue(self.acks.ack_due(125))

    def test_successful_ack_resets_deadline(self):
        self.acks.note_received(1, DATA, 10)
        snapshot = self.acks.build_ack(35)
        assert snapshot is not None
        self.assertTrue(self.acks.mark_ack_sent(snapshot))
        self.assertIsNone(self.acks.ack_pending_since_ms)
        self.assertFalse(self.acks.ack_due(500))
        self.acks.note_received(2, DATA, 500)
        self.assertFalse(self.acks.ack_due(524))
        self.assertTrue(self.acks.ack_due(525))

    def test_building_without_successful_send_does_not_clear_deadline(self):
        self.acks.note_received(2, DATA, 100)
        snapshot = self.acks.build_ack(125)
        assert snapshot is not None
        self.assertTrue(self.acks.ack_due(126))
        self.assertTrue(self.acks.ack_pending)

    def test_replay_request_makes_old_ack_due_immediately(self):
        self.acks.note_received(1, DATA, 100)
        snapshot = self.acks.build_ack(125)
        assert snapshot is not None
        self.acks.mark_ack_sent(snapshot)
        self.assertTrue(self.acks.request_reack(1))
        self.assertEqual(self.acks.ack_pending_since_ms, 100)
        self.assertTrue(self.acks.ack_due(500))

    def test_replay_unknown_packet_cannot_schedule(self):
        self.assertFalse(self.acks.request_reack(123))
        self.assertFalse(self.acks.ack_pending)

    def test_batching_more_ranges_does_not_reset_deadline_early(self):
        tracker = ReceivedPacketAckTracker(max_ranges_per_ack=1)
        tracker.note_received(1, DATA, 100)
        tracker.note_received(3, DATA, 101)
        first = tracker.build_ack(125)
        assert first is not None
        self.assertTrue(tracker.mark_ack_sent(first))
        self.assertTrue(tracker.ack_pending)
        self.assertTrue(tracker.ack_due(126))
        second = tracker.build_ack(126)
        assert second is not None
        self.assertTrue(tracker.mark_ack_sent(second))
        self.assertFalse(tracker.ack_due(1000))

    def test_stale_ack_snapshot_does_not_clear_new_pending(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(1, DATA, 100)
        snapshot = tracker.build_ack(110)
        assert snapshot is not None
        tracker.note_received(2, DATA, 120)
        self.assertFalse(tracker.mark_ack_sent(snapshot))
        self.assertTrue(tracker.ack_due(125))

    def test_invalid_ack_delay_config_is_rejected_without_mutation(self):
        self.acks.note_received(1, DATA, 50)
        for value in (-1, 26, math.inf, math.nan, True, None, "25"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.acks.ack_due(75, max_delay_ms=cast(float, value))
            self.assertEqual(self.acks.ack_pending_since_ms, 50)

    def test_clock_before_receipt_rejected(self):
        self.acks.note_received(1, DATA, 100)
        with self.assertRaises(ValueError):
            self.acks.ack_due(99)

    def test_duplicate_fresh_packet_number_does_not_change_deadline(self):
        self.acks.note_received(1, DATA, 100)
        self.assertFalse(self.acks.note_received(1, DATA, 120))
        self.assertEqual(self.acks.ack_pending_since_ms, 100)


class TestRtoTimerTick(unittest.TestCase):
    def test_idle_tick_does_nothing(self):
        receiver = state()
        result = receiver.timer_tick(now_ms=100000)
        self.assertIsInstance(result, TimerTickResult)
        self.assertFalse(result.ack_due)
        self.assertEqual(result.newly_lost, ())
        self.assertEqual(receiver.rtt.timeout_count, 0)

    def test_ack_due_only_after_authenticated_data(self):
        receiver = state()
        from common.udp_packet import encode_data_body
        valid_packet = encode_packet(KEY_S2C, DATA, CONN_ID, 0, encode_data_body(1, 0, 0, b"a"))
        # Corrupt the authenticated tag; AEAD verification must fail.
        packet = valid_packet[:-1] + bytes([valid_packet[-1] ^ 1])
        self.assertIsNone(receiver.accept(packet, key=KEY_S2C,
            endpoint=("127.0.0.1", 9001), bound_endpoint=("127.0.0.1", 9001), now_ms=100))
        self.assertFalse(receiver.timer_tick(now_ms=125).ack_due)

    def test_received_valid_data_creates_ack_deadline(self):
        from common.udp_packet import encode_data_body
        receiver = state()
        packet = encode_packet(KEY_S2C, DATA, CONN_ID, 3, encode_data_body(1, 0, 0, b"a"))
        outcome = receiver.accept(packet, key=KEY_S2C,
            endpoint=("127.0.0.1", 9001), bound_endpoint=("127.0.0.1", 9001), now_ms=100)
        self.assertIsNotNone(outcome)
        self.assertFalse(receiver.timer_tick(now_ms=124).ack_due)
        self.assertTrue(receiver.timer_tick(now_ms=125).ack_due)

    def test_rto_exact_threshold_requeues_data_once(self):
        sender = state()
        original = committed_data(sender, t=100)
        self.assertEqual(sender.sent.outstanding_count, 1)
        self.assertEqual(sender.timer_tick(now_ms=599.99).newly_lost, ())
        result = sender.timer_tick(now_ms=600)
        self.assertEqual([loss.packet.packet_num for loss in result.newly_lost], [original.packet_num])
        self.assertEqual(sender.rtt.rto_ms, 1000)
        self.assertEqual(sender.rtt.timeout_count, 1)
        self.assertEqual(sender.retries.queued_count, 1)
        self.assertEqual(sender.sent.outstanding_count, 0)
        self.assertEqual(sender.timer_tick(now_ms=601).newly_lost, ())
        self.assertEqual(sender.rtt.timeout_count, 1)

    def test_data_retry_has_fresh_packet_number_and_same_payload(self):
        sender = state()
        original = committed_data(sender, t=0, payload=b"abc")
        sender.timer_tick(now_ms=500)
        retry = sender.prepare_send(KEY_C2S, now_ms=501)
        assert retry is not None
        self.assertEqual(retry.kind, "data_retry")
        self.assertGreater(retry.packet_num, original.packet_num)
        self.assertEqual(retry.frame, original.frame)
        self.assertNotEqual(retry.datagram, original.datagram)
        sender.commit_send(retry)
        self.assertEqual(sender.sent.outstanding_count, 1)

    def test_second_retry_timeout_uses_backoff(self):
        sender = state()
        committed_data(sender, t=0)
        sender.timer_tick(now_ms=500)
        retry = sender.prepare_send(KEY_C2S, now_ms=501)
        assert retry is not None
        sender.commit_send(retry)
        self.assertEqual(sender.timer_tick(now_ms=1500).newly_lost, ())
        second = sender.timer_tick(now_ms=1501)
        self.assertEqual(len(second.newly_lost), 1)
        self.assertEqual(sender.rtt.rto_ms, 2000)
        self.assertEqual(sender.retries.queued_count, 1)

    def test_window_update_timeout_requeues_credit(self):
        sender = state()
        sender.streams.receive_frame(1, 0, b"abc")
        sender.flow.note_consumed(1, 3)
        plan = sender.prepare_send(KEY_C2S, now_ms=10)
        assert plan is not None
        self.assertEqual(plan.kind, "window_update")
        sender.commit_send(plan)
        result = sender.timer_tick(now_ms=510)
        self.assertEqual(len(result.newly_lost), 1)
        self.assertEqual(result.newly_lost[0].packet.packet_type, WINDOW_UPDATE)
        retry = sender.prepare_send(KEY_C2S, now_ms=511)
        assert retry is not None
        self.assertEqual(retry.kind, "window_update")
        self.assertGreater(retry.packet_num, plan.packet_num)

    def test_tick_does_not_allocate_packet_numbers_or_send(self):
        sender = state()
        committed_data(sender, t=0)
        pn_before = sender.connection._next_send_packet_num
        sender.timer_tick(now_ms=500)
        self.assertEqual(sender.connection._next_send_packet_num, pn_before)
        self.assertEqual(sender.retries.queued_count, 1)

    def test_silent_network_causes_rto_without_any_incoming_ack(self):
        sender = state()
        committed_data(sender, t=10)
        self.assertFalse(sender.timer_tick(now_ms=509).newly_lost)
        self.assertTrue(sender.timer_tick(now_ms=510).newly_lost)

    def test_lost_ack_keeps_delivery_once_and_retry_can_be_acked(self):
        from common.udp_packet import encode_packet
        sender = state()
        recipient = state()
        original = committed_data(sender, t=0)
        addr = ("127.0.0.1", 9001)
        incoming = recipient.accept(original.datagram, key=KEY_C2S, endpoint=addr,
                                    bound_endpoint=addr, now_ms=1)
        self.assertIsNotNone(incoming)
        self.assertEqual(recipient.delivery_count, 1)
        self.assertTrue(recipient.timer_tick(now_ms=26).ack_due)
        snapshot = recipient.received.build_ack(26)
        assert snapshot is not None
        recipient.received.mark_ack_sent(snapshot)
        # ACK was lost in network: sender still has packet in-flight.
        self.assertEqual(sender.sent.outstanding_count, 1)
        sender.timer_tick(now_ms=500)
        retry = sender.prepare_send(KEY_C2S, now_ms=501)
        assert retry is not None
        self.assertEqual(retry.kind, "data_retry")
        sender.commit_send(retry)
        again = recipient.accept(retry.datagram, key=KEY_C2S, endpoint=addr,
                                 bound_endpoint=addr, now_ms=502)
        self.assertIsNotNone(again)
        self.assertEqual(recipient.delivery_count, 1)  # in-order dedup by stream offsets
        ack_body = encode_ack_body(0, [(retry.packet_num, retry.packet_num)])
        ack_packet = encode_packet(KEY_S2C, ACK, CONN_ID, 0, ack_body)
        result = sender.accept(ack_packet, key=KEY_S2C, endpoint=addr,
                               bound_endpoint=addr, now_ms=550)
        self.assertIsNotNone(result)
        self.assertEqual(sender.sent.outstanding_count, 0)
        self.assertEqual(sender.retries.queued_count, 0)

    def test_late_original_ack_cancels_queued_retry(self):
        sender = state()
        original = committed_data(sender, t=0)
        sender.timer_tick(now_ms=500)
        self.assertEqual(sender.retries.queued_count, 1)
        ack_body = encode_ack_body(0, [(original.packet_num, original.packet_num)])
        ack_packet = encode_packet(KEY_S2C, ACK, CONN_ID, 0, ack_body)
        addr = ("127.0.0.1", 9001)
        received = sender.accept(ack_packet, key=KEY_S2C, endpoint=addr,
                                  bound_endpoint=addr, now_ms=510)
        self.assertIsNotNone(received)
        self.assertEqual(sender.retries.queued_count, 0)
        self.assertIsNone(sender.prepare_send(KEY_C2S, now_ms=511))

    def test_invalid_timer_clock_rejected_without_mutating_rto(self):
        sender = state()
        for value in (-1, math.inf, math.nan, True, None, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sender.timer_tick(now_ms=cast(float, value))
        self.assertEqual(sender.rtt.timeout_count, 0)


if __name__ == "__main__":
    unittest.main()
