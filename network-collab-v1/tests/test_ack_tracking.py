"""B3.1 ACK tracking: bounded states, ranges, ACK-only, dedup, no UDP I/O.

Run: python -m unittest discover -s tests -p 'test_ack_tracking.py' -v
"""

import unittest
from typing import cast

from common.constants import ACK, DATA, PING, WINDOW_UPDATE
from common.streams import StreamSendFrame
from common.transport import (
    ConnectionAckState,
    ReceivedPacketAckTracker,
    SentPacketTracker,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    decode_ack_body,
    decode_packet,
    encode_ack_body,
    encode_data_body,
    encode_packet,
)

KEY = bytes(range(32))


def frame(
    offset: int = 0, data: bytes = b"hello", *, fin: bool = False
) -> StreamSendFrame:
    return StreamSendFrame(1, offset, data, fin)


class TestReceivedPacketAckTracker(unittest.TestCase):
    def test_empty_does_not_generate_ack(self):
        self.assertIsNone(ReceivedPacketAckTracker().build_ack(100))

    def test_single_packet_roundtrip(self):
        tracker = ReceivedPacketAckTracker()
        self.assertTrue(tracker.note_received(7, DATA, 100))
        snapshot = tracker.build_ack(125)
        assert snapshot is not None
        self.assertEqual(decode_ack_body(snapshot.body), (25, [(7, 7)]))
        self.assertEqual(snapshot.ack_delay_ms, 25)

    def test_contiguous_packets_merge(self):
        tracker = ReceivedPacketAckTracker()
        for pn in (10, 11, 12):
            self.assertTrue(tracker.note_received(pn, DATA, 100))
        ack = tracker.build_ack(100)
        assert ack is not None
        self.assertEqual(ack.ranges, ((10, 12),))

    def test_reordered_packets_merge(self):
        tracker = ReceivedPacketAckTracker()
        for pn in (12, 10, 11):
            tracker.note_received(pn, DATA, 100)
        ack = tracker.build_ack(100)
        assert ack is not None
        self.assertEqual(ack.ranges, ((10, 12),))

    def test_gaps_produce_descending_ranges(self):
        tracker = ReceivedPacketAckTracker()
        for pn in (5, 7, 10, 12, 11, 6):
            tracker.note_received(pn, DATA, 100)
        ack = tracker.build_ack(100)
        assert ack is not None
        self.assertEqual(ack.ranges, ((10, 12), (5, 7)))
        self.assertEqual(decode_ack_body(ack.body)[1], [(10, 12), (5, 7)])

    def test_duplicate_does_not_change_state(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(9, DATA, 20)
        self.assertFalse(tracker.note_received(9, DATA, 25))
        self.assertEqual(tracker.tracked_count, 1)
        ack = tracker.build_ack(30)
        assert ack is not None
        self.assertEqual(ack.ack_delay_ms, 10)

    def test_ack_only_never_elicits_ack(self):
        tracker = ReceivedPacketAckTracker()
        self.assertFalse(tracker.note_received(100, ACK, 100))
        self.assertFalse(tracker.ack_pending)
        self.assertEqual(tracker.tracked_count, 0)
        self.assertIsNone(tracker.build_ack(200, force=True))

    def test_ack_only_does_not_dirty_pending_after_send(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(9, DATA, 20)
        ack = tracker.build_ack(25)
        assert ack is not None
        self.assertTrue(tracker.mark_ack_sent(ack))
        self.assertFalse(tracker.note_received(10, ACK, 26))
        self.assertFalse(tracker.ack_pending)
        self.assertIsNone(tracker.build_ack(30))

    def test_cannot_mark_same_ack_as_sent_twice(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(7, DATA, 0)
        snapshot = tracker.build_ack(1)
        assert snapshot is not None
        self.assertTrue(tracker.mark_ack_sent(snapshot))
        self.assertFalse(tracker.mark_ack_sent(snapshot))

    def test_mark_sent_clears_pending(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(1, DATA, 0)
        ack = tracker.build_ack(5)
        assert ack is not None
        self.assertTrue(tracker.ack_pending)
        self.assertTrue(tracker.mark_ack_sent(ack))
        self.assertFalse(tracker.ack_pending)
        self.assertIsNone(tracker.build_ack(10))

    def test_build_does_not_clear_pending_on_send_failure(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(1, DATA, 0)
        a = tracker.build_ack(5)
        b = tracker.build_ack(7)
        assert a is not None and b is not None
        self.assertTrue(tracker.ack_pending)
        self.assertEqual(a.ranges, b.ranges)
        self.assertEqual(b.ack_delay_ms, 7)

    def test_new_packet_after_snapshot_prevents_stale_clear(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(10, DATA, 1)
        stale = tracker.build_ack(2)
        assert stale is not None
        tracker.note_received(11, DATA, 3)
        self.assertFalse(tracker.mark_ack_sent(stale))
        self.assertTrue(tracker.ack_pending)
        new = tracker.build_ack(4)
        assert new is not None
        self.assertEqual(new.ranges, ((10, 11),))

    def test_reack_after_authenticated_duplicate(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(20, DATA, 100)
        first = tracker.build_ack(105)
        assert first is not None
        tracker.mark_ack_sent(first)
        self.assertTrue(tracker.request_reack(20))
        second = tracker.build_ack(110)
        assert second is not None
        self.assertEqual(second.ranges, ((20, 20),))

    def test_reack_does_not_invent_unreceived_packet(self):
        tracker = ReceivedPacketAckTracker()
        self.assertFalse(tracker.request_reack(11))
        tracker.note_received(10, DATA, 1)
        self.assertFalse(tracker.request_reack(11))

    def test_force_reack_without_pending(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(10, DATA, 100)
        first = tracker.build_ack(101)
        assert first is not None
        tracker.mark_ack_sent(first)
        self.assertIsNone(tracker.build_ack(105))
        forced = tracker.build_ack(105, force=True)
        assert forced is not None
        self.assertEqual(forced.ranges, ((10, 10),))

    def test_ack_delay_clamps_u16(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(10, PING, 0)
        ack = tracker.build_ack(90000)
        assert ack is not None
        self.assertEqual(ack.ack_delay_ms, 65535)
        self.assertEqual(decode_ack_body(ack.body)[0], 65535)

    def test_delay_uses_largest_acked_packet_time(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(10, DATA, 50)
        tracker.note_received(9, DATA, 60)
        ack = tracker.build_ack(70)
        assert ack is not None
        self.assertEqual(ack.ack_delay_ms, 20)

    def test_future_time_rejected(self):
        tracker = ReceivedPacketAckTracker()
        tracker.note_received(1, DATA, 100)
        with self.assertRaises(ValueError):
            tracker.build_ack(99)
        self.assertTrue(tracker.ack_pending)

    def test_invalid_received_packet_number(self):
        tracker = ReceivedPacketAckTracker()
        for pn in (-1, True, 1 << 64, 1.2, "1"):
            with self.subTest(pn=pn), self.assertRaises(ValueError):
                tracker.note_received(cast(int, pn), DATA, 0)
        self.assertEqual(tracker.tracked_count, 0)

    def test_invalid_time_and_type(self):
        tracker = ReceivedPacketAckTracker()
        for timestamp in (-1, float("nan"), float("inf"), True, "10"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                tracker.note_received(1, DATA, cast(float, timestamp))
        with self.assertRaises(ValueError):
            tracker.note_received(1, 999, 0)
        self.assertEqual(tracker.tracked_count, 0)

    def test_invalid_constructor(self):
        for history_size in (0, -1, 4097, True):
            with self.subTest(value=history_size), self.assertRaises(ValueError):
                ReceivedPacketAckTracker(history_size=cast(int, history_size))
        for limit in (0, 17, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                ReceivedPacketAckTracker(max_ranges_per_ack=cast(int, limit))

    def test_history_prunes_old_numbers(self):
        tracker = ReceivedPacketAckTracker(history_size=4)
        for pn in (0, 1, 2, 3, 4):
            tracker.note_received(pn, DATA, 0)
        self.assertEqual(tracker.tracked_count, 4)
        self.assertFalse(tracker.request_reack(0))
        self.assertFalse(tracker.note_received(0, DATA, 1))
        ack = tracker.build_ack(1)
        assert ack is not None
        self.assertEqual(ack.ranges, ((1, 4),))

    def test_huge_packet_num_jump_bounded_history(self):
        tracker = ReceivedPacketAckTracker(history_size=4)
        tracker.note_received(1, DATA, 0)
        tracker.note_received((1 << 64) - 1, DATA, 1)
        self.assertEqual(tracker.tracked_count, 1)
        ack = tracker.build_ack(2)
        assert ack is not None
        self.assertEqual(ack.ranges, (((1 << 64) - 1, (1 << 64) - 1),))

    def test_more_than_sixteen_ranges_in_batches(self):
        tracker = ReceivedPacketAckTracker(history_size=100)
        for pn in range(0, 40, 2):  # 20 disjoint ranges
            tracker.note_received(pn, DATA, 1)
        first = tracker.build_ack(2)
        assert first is not None
        self.assertEqual(len(first.ranges), 16)
        self.assertEqual(first.ranges[0], (38, 38))
        self.assertTrue(tracker.mark_ack_sent(first))
        self.assertTrue(tracker.ack_pending)
        second = tracker.build_ack(2)
        assert second is not None
        self.assertEqual(second.ranges, ((6, 6), (4, 4), (2, 2), (0, 0)))
        self.assertTrue(tracker.mark_ack_sent(second))
        self.assertFalse(tracker.ack_pending)
        self.assertEqual(
            set(
                n
                for snap in (first, second)
                for s, e in snap.ranges
                for n in range(s, e + 1)
            ),
            set(range(0, 40, 2)),
        )

    def test_new_packet_during_range_batches_resets_cursor(self):
        tracker = ReceivedPacketAckTracker(history_size=100, max_ranges_per_ack=2)
        for pn in (10, 20, 30, 40, 50):
            tracker.note_received(pn, DATA, 0)
        first = tracker.build_ack(1)
        assert first is not None
        tracker.mark_ack_sent(first)
        pending = tracker.build_ack(1)
        assert pending is not None
        tracker.note_received(60, DATA, 1)
        self.assertFalse(tracker.mark_ack_sent(pending))
        new = tracker.build_ack(2)
        assert new is not None
        self.assertEqual(new.ranges, ((60, 60), (50, 50)))

    def test_replayed_snapshot_rejected_after_progress(self):
        tracker = ReceivedPacketAckTracker(history_size=20, max_ranges_per_ack=1)
        tracker.note_received(5, DATA, 0)
        tracker.note_received(10, DATA, 0)
        a = tracker.build_ack(1)
        assert a is not None
        self.assertTrue(tracker.mark_ack_sent(a))
        self.assertFalse(tracker.mark_ack_sent(a))

    def test_default_history_never_exceeds_replay_window(self):
        tracker = ReceivedPacketAckTracker()
        for pn in range(5000):
            tracker.note_received(pn, DATA, 0)
        self.assertEqual(tracker.tracked_count, 4096)

    def test_max_packet_number_accepted(self):
        tracker = ReceivedPacketAckTracker()
        self.assertTrue(tracker.note_received((1 << 64) - 1, DATA, 1))


class TestSentPacketTracker(unittest.TestCase):
    def test_data_frame_metadata_retained(self):
        tracker = SentPacketTracker()
        f = frame(23, b"hello", fin=True)
        self.assertTrue(tracker.track_sent(1, DATA, 60, 100, frame=f))
        sent = tracker.get(1)
        assert sent is not None
        self.assertEqual(sent.frame, f)
        self.assertEqual(sent.sent_at_ms, 100.0)
        self.assertEqual(tracker.bytes_in_flight, 60)

    def test_ack_one_packet(self):
        tracker = SentPacketTracker()
        tracker.track_sent(10, DATA, 60, 1, frame=frame())
        receipt = tracker.process_ack(encode_ack_body(5, [(10, 10)]))
        self.assertEqual(receipt.ack_delay_ms, 5)
        self.assertEqual(receipt.largest_acked, 10)
        self.assertEqual(receipt.newly_acked_count, 1)
        self.assertEqual(receipt.bytes_acked, 60)
        self.assertEqual(tracker.outstanding_count, 0)
        self.assertEqual(tracker.bytes_in_flight, 0)

    def test_multiple_ack_ranges_selectively_retire(self):
        tracker = SentPacketTracker()
        for pn in range(10, 15):
            tracker.track_sent(pn, DATA, 60, pn, frame=frame(pn))
        receipt = tracker.process_ack(encode_ack_body(0, [(13, 14), (10, 11)]))
        self.assertEqual([p.packet_num for p in receipt.newly_acked], [10, 11, 13, 14])
        self.assertEqual(tracker.outstanding_count, 1)
        remaining = tracker.get(12)
        assert remaining is not None
        self.assertEqual(remaining.packet_num, 12)
        self.assertEqual(tracker.bytes_in_flight, 60)

    def test_duplicate_ack_idempotent(self):
        tracker = SentPacketTracker()
        tracker.track_sent(10, DATA, 60, 1, frame=frame())
        body = encode_ack_body(0, [(10, 10)])
        self.assertEqual(tracker.process_ack(body).newly_acked_count, 1)
        second = tracker.process_ack(body)
        self.assertEqual(second.newly_acked_count, 0)
        self.assertEqual(second.bytes_acked, 0)

    def test_unknown_and_ack_only_numbers_ignored(self):
        tracker = SentPacketTracker()
        tracker.track_sent(10, DATA, 60, 1, frame=frame())
        self.assertFalse(tracker.track_sent(11, ACK, 36, 2))
        receipt = tracker.process_ack(encode_ack_body(0, [(11, 11)]))
        self.assertEqual(receipt.newly_acked_count, 0)
        self.assertEqual(tracker.bytes_in_flight, 60)
        self.assertEqual(tracker.outstanding_count, 1)

    def test_ack_of_future_uint64_range_is_bounded(self):
        tracker = SentPacketTracker()
        tracker.track_sent(7, DATA, 60, 0, frame=frame())
        receipt = tracker.process_ack(encode_ack_body(0, [(0, (1 << 64) - 1)]))
        self.assertEqual(receipt.newly_acked_count, 1)
        self.assertEqual(tracker.bytes_in_flight, 0)

    def test_invalid_ack_body_does_not_mutate(self):
        tracker = SentPacketTracker()
        tracker.track_sent(7, DATA, 60, 0, frame=frame())
        for body in (
            b"",
            b"\x00\x00\x00",
            b"\x00\x00\x01",
            b"\x00\x00\x01" + b"\x00" * 32,
        ):
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                tracker.process_ack(body)
        self.assertEqual(tracker.bytes_in_flight, 60)
        self.assertEqual(tracker.outstanding_count, 1)

    def test_ack_only_not_tracked(self):
        tracker = SentPacketTracker()
        self.assertFalse(tracker.track_sent(1, ACK, 36, 0))
        self.assertEqual(tracker.outstanding_count, 0)
        self.assertEqual(tracker.bytes_in_flight, 0)

    def test_data_requires_retained_frame(self):
        tracker = SentPacketTracker()
        with self.assertRaises(ValueError):
            tracker.track_sent(1, DATA, 50, 0)
        self.assertEqual(tracker.outstanding_count, 0)

    def test_non_data_cannot_carry_frame(self):
        tracker = SentPacketTracker()
        with self.assertRaises(ValueError):
            tracker.track_sent(1, PING, 50, 0, frame=frame())

    def test_ping_and_window_update_tracked_without_frame(self):
        tracker = SentPacketTracker()
        tracker.track_sent(1, PING, 44, 1)
        tracker.track_sent(2, WINDOW_UPDATE, 48, 2)
        self.assertEqual(tracker.outstanding_count, 2)

    def test_can_track_preflight_before_popping_b2_frame(self):
        tracker = SentPacketTracker(max_outstanding_packets=1, max_pending_bytes=100)
        self.assertTrue(tracker.can_track(60))
        tracker.track_sent(1, DATA, 60, 0, frame=frame())
        self.assertFalse(tracker.can_track(36))
        self.assertEqual(tracker.outstanding_count, 1)
        self.assertEqual(tracker.bytes_in_flight, 60)

    def test_ack_only_packet_number_cannot_be_reused(self):
        tracker = SentPacketTracker()
        self.assertFalse(tracker.track_sent(5, ACK, 36, 0))
        with self.assertRaises(ValueError):
            tracker.track_sent(5, DATA, 60, 0, frame=frame())
        self.assertTrue(tracker.track_sent(6, DATA, 60, 1, frame=frame()))

    def test_count_limit_atomic(self):
        tracker = SentPacketTracker(max_outstanding_packets=1)
        tracker.track_sent(1, DATA, 50, 0, frame=frame())
        with self.assertRaises(BufferError):
            tracker.track_sent(2, DATA, 50, 0, frame=frame(5))
        self.assertEqual(tracker.bytes_in_flight, 50)
        self.assertEqual(tracker.outstanding_count, 1)

    def test_byte_limit_atomic(self):
        tracker = SentPacketTracker(max_pending_bytes=100)
        tracker.track_sent(1, DATA, 60, 0, frame=frame())
        with self.assertRaises(BufferError):
            tracker.track_sent(2, DATA, 60, 1, frame=frame(5))
        self.assertEqual(tracker.bytes_in_flight, 60)

    def test_cancel_packet_on_send_error(self):
        tracker = SentPacketTracker()
        tracker.track_sent(1, DATA, 60, 0, frame=frame())
        self.assertIsNotNone(tracker.cancel_sent(1))
        self.assertIsNone(tracker.cancel_sent(1))
        self.assertEqual(tracker.bytes_in_flight, 0)
        self.assertEqual(
            tracker.process_ack(encode_ack_body(0, [(1, 1)])).newly_acked_count, 0
        )

    def test_no_packet_number_reuse_after_ack(self):
        tracker = SentPacketTracker()
        tracker.track_sent(1, DATA, 60, 0, frame=frame())
        tracker.process_ack(encode_ack_body(0, [(1, 1)]))
        with self.assertRaises(ValueError):
            tracker.track_sent(1, DATA, 60, 1, frame=frame())

    def test_no_packet_number_reuse_after_cancel(self):
        tracker = SentPacketTracker()
        tracker.track_sent(1, DATA, 60, 0, frame=frame())
        tracker.cancel_sent(1)
        with self.assertRaises(ValueError):
            tracker.track_sent(1, DATA, 60, 1, frame=frame())

    def test_invalid_packet_numbers(self):
        tracker = SentPacketTracker()
        for pn in (-1, 1 << 64, True, 2.2, "1"):
            with self.subTest(pn=pn), self.assertRaises(ValueError):
                tracker.track_sent(cast(int, pn), DATA, 60, 0, frame=frame())

    def test_invalid_datagram_sizes(self):
        tracker = SentPacketTracker()
        for size in (35, 1201, 0, True, 60.0):
            with self.subTest(size=size), self.assertRaises(ValueError):
                tracker.track_sent(1, DATA, cast(int, size), 0, frame=frame())

    def test_invalid_send_clock(self):
        tracker = SentPacketTracker()
        for sent_at in (-1, True, float("nan"), float("inf"), "10"):
            with self.subTest(time=sent_at), self.assertRaises(ValueError):
                tracker.track_sent(1, DATA, 60, cast(float, sent_at), frame=frame())

    def test_invalid_packet_type(self):
        tracker = SentPacketTracker()
        with self.assertRaises(ValueError):
            tracker.track_sent(1, 999, 60, 0)

    def test_invalid_constructor_limits(self):
        for value in (0, -1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SentPacketTracker(max_outstanding_packets=cast(int, value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                SentPacketTracker(max_pending_bytes=cast(int, value))

    def test_timestamp_and_frame_survive_ack_receipt(self):
        tracker = SentPacketTracker()
        f = frame(12, b"data", fin=True)
        tracker.track_sent(42, DATA, 60, 123, frame=f)
        receipt = tracker.process_ack(encode_ack_body(7, [(42, 42)]))
        self.assertEqual(receipt.newly_acked[0].frame, f)
        self.assertEqual(receipt.newly_acked[0].sent_at_ms, 123)

    def test_future_ack_no_pending_is_noop(self):
        tracker = SentPacketTracker()
        receipt = tracker.process_ack(encode_ack_body(0, [(1234, 1234)]))
        self.assertEqual(receipt.newly_acked_count, 0)


class TestConnectionAckState(unittest.TestCase):
    def test_reuse_single_packet_number_allocator(self):
        state = TransportConnectionState(123)
        self.assertEqual(state.allocate_packet_number(), 0)  # REGISTER
        ack_state = ConnectionAckState(state)
        self.assertEqual(ack_state.allocate_packet_number(), 1)
        self.assertEqual(state.allocate_packet_number(), 2)
        self.assertEqual(ack_state.conn_id, 123)

    def test_distinct_connection_states_independent(self):
        a = ConnectionAckState(TransportConnectionState(100))
        b = ConnectionAckState(TransportConnectionState(200))
        self.assertEqual(a.allocate_packet_number(), 0)
        self.assertEqual(b.allocate_packet_number(), 0)
        a.received.note_received(3, DATA, 0)
        self.assertEqual(b.received.tracked_count, 0)

    def test_constructor_rejects_wrong_type(self):
        with self.assertRaises(TypeError):
            ConnectionAckState(cast(TransportConnectionState, 123))

    def test_encrypted_data_and_ack_codec_integration(self):
        sender = ConnectionAckState(TransportConnectionState(77))
        receiver = ConnectionAckState(TransportConnectionState(77))
        stream_frame = frame(0, b"hello")
        pkt_num = sender.allocate_packet_number()
        data_body = encode_data_body(
            stream_frame.stream_id,
            stream_frame.offset,
            stream_frame.flags,
            stream_frame.data,
        )
        packet = encode_packet(KEY, DATA, 77, pkt_num, data_body)
        sender.sent.track_sent(pkt_num, DATA, len(packet), 10, frame=stream_frame)
        kind, conn_id, received_pn, received_body = decode_packet(KEY, packet)
        self.assertEqual((kind, conn_id), (DATA, 77))
        self.assertEqual(received_body, data_body)
        self.assertTrue(receiver.transport_state.recv_replay.commit(received_pn))
        self.assertTrue(receiver.received.note_received(received_pn, kind, 20))
        snapshot = receiver.received.build_ack(25)
        assert snapshot is not None
        ack_pn = receiver.allocate_packet_number()
        ack_packet = encode_packet(KEY, ACK, 77, ack_pn, snapshot.body)
        self.assertFalse(receiver.sent.track_sent(ack_pn, ACK, len(ack_packet), 25))
        kind, _, pn, ack_body = decode_packet(KEY, ack_packet)
        self.assertEqual(kind, ACK)
        self.assertTrue(sender.transport_state.recv_replay.commit(pn))
        self.assertFalse(sender.received.note_received(pn, kind, 30))
        receipt = sender.sent.process_ack(ack_body)
        self.assertEqual(receipt.newly_acked[0].frame, stream_frame)
        self.assertEqual(sender.sent.bytes_in_flight, 0)

    def test_corrupted_encrypted_packet_cannot_reach_ack_tracking(self):
        receiver = ConnectionAckState(TransportConnectionState(77))
        packet = bytearray(
            encode_packet(KEY, DATA, 77, 10, encode_data_body(1, 0, 0, b"abc"))
        )
        packet[-1] ^= 1
        with self.assertRaises(Exception):
            decode_packet(KEY, bytes(packet))
        self.assertEqual(receiver.received.tracked_count, 0)

    def test_replay_duplicate_not_delivered_twice(self):
        receiver = ConnectionAckState(TransportConnectionState(77))
        pn = 10
        self.assertTrue(receiver.transport_state.recv_replay.commit(pn))
        self.assertTrue(receiver.received.note_received(pn, DATA, 1))
        self.assertFalse(receiver.transport_state.recv_replay.commit(pn))
        self.assertFalse(receiver.received.note_received(pn, DATA, 2))
        self.assertEqual(receiver.received.tracked_count, 1)
        self.assertTrue(receiver.received.request_reack(pn))


if __name__ == "__main__":
    unittest.main()
