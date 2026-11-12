"""B3.2.3 DATA retransmission: no sockets, fake monotonic milliseconds."""

import unittest
from dataclasses import replace
from typing import cast

from common.constants import ACK, DATA, PING, WINDOW_UPDATE
from common.streams import StreamSendFrame, StreamReceiveState
from common.transport_state import TransportConnectionState
from common.transport import (
    AckReceipt, DataRetransmissionQueue, LostPacket, PacketLossDetector,
    PreparedRetransmission, RttEstimator, SentPacket, SentPacketTracker,
)
from common.udp_packet import (
    decode_data_body, decode_packet, encode_ack_body,
)

KEY = bytes(range(32))
CONN_ID = 771


def make_setup(data=b"Hello!", *, fin=False, capacity=1024*1024, max_outstanding=1024, **kwargs):
    connection = TransportConnectionState(CONN_ID)
    sent = SentPacketTracker(max_pending_bytes=capacity, max_outstanding_packets=max_outstanding)
    queue = DataRetransmissionQueue(CONN_ID, **kwargs)
    frame = StreamSendFrame(2, 3072, data, fin)
    pn = connection.allocate_packet_number()
    sent.track_sent(pn, DATA, 64, 0, frame=frame)
    packet = sent.get(pn)
    assert packet is not None
    loss = LostPacket(packet, "rto", 500)
    return connection, sent, queue, frame, pn, loss


def one_loss(data=b"Hello!", **kwargs):
    connection, sent, queue, frame, pn, loss = make_setup(data, **kwargs)
    assert queue.note_loss(loss, sent)
    return connection, sent, queue, frame, pn, loss


def require_sent(sent: SentPacketTracker, pn: int) -> SentPacket:
    packet = sent.get(pn)
    assert packet is not None
    return packet


class TestDataRetransmission(unittest.TestCase):
    def test_first_handoff_is_safe_and_releases_original_bytes(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        self.assertEqual(sent.bytes_in_flight, 64)
        self.assertTrue(queue.note_loss(loss, sent))
        self.assertIsNone(sent.get(pn))
        self.assertEqual(sent.bytes_in_flight, 0)
        self.assertEqual(queue.queued_count, 1)
        self.assertEqual(queue.queued_bytes, len(frame.data))
        self.assertEqual(queue.tracked_frames, 1)

    def test_stale_loss_is_idempotent(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        self.assertFalse(queue.note_loss(loss, sent))
        self.assertEqual(queue.queued_count, 1)

    def test_fresh_packet_number_and_exact_frame_bytes(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        self.assertIsInstance(plan, PreparedRetransmission)
        assert plan is not None
        self.assertGreater(plan.packet_num, pn)
        packet_type, conn_id, new_pn, body = decode_packet(KEY, plan.datagram)
        self.assertEqual((packet_type, conn_id, new_pn), (DATA, CONN_ID, plan.packet_num))
        self.assertEqual(decode_data_body(body), (frame.stream_id, frame.offset, frame.flags, frame.data))
        self.assertEqual(plan.retry_number, 1)

    def test_fin_only_retries_and_keeps_flag(self):
        connection, sent, queue, frame, pn, loss = one_loss(b"", fin=True)
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        self.assertEqual(decode_data_body(decode_packet(KEY, plan.datagram)[3]), (2, 3072, 1, b""))

    def test_max_1024_bytes_and_datagram_limit(self):
        connection, sent, queue, frame, pn, loss = one_loss(b"X"*1024)
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        self.assertLessEqual(len(plan.datagram), 1200)
        self.assertEqual(decode_data_body(decode_packet(KEY, plan.datagram)[3])[3], b"X"*1024)

    def test_prepare_retains_queue_before_commit(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        self.assertEqual(queue.queued_count, 1)
        self.assertIs(queue.prepared, plan)
        self.assertIsNotNone(sent.get(plan.packet_num))
        self.assertEqual(queue._groups[frame].retry_count, 0)

    def test_commit_marks_retry_and_dequeues(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        self.assertIsNone(queue.prepared)
        self.assertEqual(queue.queued_count, 0)
        self.assertEqual(queue._groups[frame].retry_count, 1)
        self.assertIsNotNone(sent.get(plan.packet_num))
        self.assertEqual(sent.bytes_in_flight, len(plan.datagram))

    def test_abort_restores_queue_but_consumes_packet_num(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        first = queue.prepare_next(connection, sent, KEY, 600)
        assert first is not None
        queue.abort_send(first, sent)
        self.assertIsNone(sent.get(first.packet_num))
        self.assertEqual(queue.queued_count, 1)
        second = queue.prepare_next(connection, sent, KEY, 601)
        assert second is not None
        self.assertGreater(second.packet_num, first.packet_num)
        self.assertEqual(first.retry_number, second.retry_number)
        self.assertNotEqual(first.datagram, second.datagram)

    def test_abort_does_not_leak_in_flight_bytes(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        self.assertGreater(sent.bytes_in_flight, 0)
        queue.abort_send(plan, sent)
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_prepared_can_only_be_handled_once(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        with self.assertRaises(RuntimeError):
            queue.prepare_next(connection, sent, KEY, 601)
        queue.commit_sent(plan)
        with self.assertRaises(ValueError):
            queue.commit_sent(plan)
        with self.assertRaises(ValueError):
            queue.abort_send(plan, sent)

    def test_sender_capacity_preflight_does_not_allocate_pn(self):
        connection, sent, queue, frame, pn, loss = one_loss(b"X" * 100, capacity=64)
        before = connection._next_send_packet_num
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 600))
        self.assertEqual(connection._next_send_packet_num, before)
        self.assertEqual(queue.queued_count, 1)

    def test_max_outstanding_preflight_does_not_pop(self):
        connection, sent, queue, frame, pn, loss = one_loss(max_outstanding=1)
        other_pn = connection.allocate_packet_number()
        sent.track_sent(other_pn, PING, 64, 500)
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 600))
        self.assertEqual(queue.queued_count, 1)
        self.assertEqual(queue._groups[frame].retry_count, 0)

    def test_queue_full_preserves_second_original_packet(self):
        connection, sent, queue, frame, pn, loss = make_setup(max_queued_frames=1)
        self.assertTrue(queue.note_loss(loss, sent))
        second = StreamSendFrame(1, 0, b"world")
        second_pn = connection.allocate_packet_number()
        sent.track_sent(second_pn, DATA, 64, 10, frame=second)
        second_loss = LostPacket(require_sent(sent, second_pn), 'rto', 510)
        with self.assertRaises(BufferError):
            queue.note_loss(second_loss, sent)
        self.assertIsNotNone(sent.get(second_pn))
        self.assertEqual(queue.queued_count, 1)

    def test_byte_budget_preserves_original_if_no_space(self):
        connection, sent, queue, frame, pn, loss = make_setup(b"abcd", max_queued_bytes=3)
        with self.assertRaises(BufferError):
            queue.note_loss(loss, sent)
        self.assertIsNotNone(sent.get(pn))
        self.assertEqual(queue.queued_count, 0)

    def test_frame_history_cap_prevents_retirement(self):
        connection, sent, queue, frame, pn, loss = make_setup(max_tracked_frames=1)
        queue.note_loss(loss, sent)
        first = queue.prepare_next(connection, sent, KEY, 600)
        assert first is not None
        queue.commit_sent(first)
        another = StreamSendFrame(1, 0, b"another")
        p = connection.allocate_packet_number()
        sent.track_sent(p, DATA, 64, 650, frame=another)
        with self.assertRaises(BufferError):
            queue.note_loss(LostPacket(require_sent(sent, p), 'rto', 1200), sent)
        self.assertIsNotNone(sent.get(p))

    def test_late_ack_after_handoff_cancels_unsent_retry(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        receipt = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(receipt.newly_acked_count, 0)
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertEqual(queue.queued_count, 0)
        self.assertEqual(queue.tracked_frames, 0)
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 600))

    def test_late_ack_cancels_prepared_retry(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        receipt = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertIsNone(queue.prepared)
        self.assertIsNone(sent.get(plan.packet_num))

    def test_retry_ack_frees_bytes_and_finalizes_group(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        receipt = sent.process_ack(encode_ack_body(0, [(plan.packet_num, plan.packet_num)]))
        self.assertEqual(receipt.bytes_acked, len(plan.datagram))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertEqual(sent.bytes_in_flight, 0)
        self.assertEqual(queue.tracked_frames, 0)

    def test_original_ack_after_committed_retry_cancels_outstanding(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        receipt = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertIsNone(sent.get(plan.packet_num))
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_duplicate_old_ack_no_double_completion(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        receipt = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertEqual(queue.on_ack(receipt, sent), ())
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_unrelated_ack_does_not_cancel_queue(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        receipt = sent.process_ack(encode_ack_body(0, [(pn+10, pn+10)]))
        self.assertEqual(queue.on_ack(receipt, sent), ())
        self.assertEqual(queue.queued_count, 1)

    def test_repeated_loss_resends_same_stream_metadata(self):
        connection, sent, queue, frame, pn, loss = one_loss(b"z123", fin=True)
        first = queue.prepare_next(connection, sent, KEY, 600)
        assert first is not None
        queue.commit_sent(first)
        retry_loss = LostPacket(require_sent(sent, first.packet_num), 'rto', 1600)
        self.assertTrue(queue.note_loss(retry_loss, sent))
        second = queue.prepare_next(connection, sent, KEY, 1700)
        assert second is not None
        self.assertGreater(second.packet_num, first.packet_num)
        self.assertEqual(second.frame, first.frame)
        self.assertEqual(second.retry_number, 2)
        self.assertEqual(decode_data_body(decode_packet(KEY, second.datagram)[3]), (2, 3072, 1, b'z123'))

    def test_multiple_loss_reports_while_already_queued_do_not_duplicate(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        first = queue.prepare_next(connection, sent, KEY, 600)
        assert first is not None
        queue.commit_sent(first)
        packet = sent.get(first.packet_num)
        assert packet is not None
        same_loss = LostPacket(packet, 'rto', 1100)
        queue.note_loss(same_loss, sent)
        self.assertEqual(queue.queued_count, 1)
        self.assertFalse(queue.note_loss(same_loss, sent))
        self.assertEqual(queue.queued_count, 1)

    def test_timeout_budget_eight_retries_then_error(self):
        connection, sent, queue, frame, pn, loss = one_loss(max_retransmissions=8)
        for i in range(8):
            plan = queue.prepare_next(connection, sent, KEY, 600 + i * 1000)
            assert plan is not None
            self.assertEqual(plan.retry_number, i + 1)
            queue.commit_sent(plan)
            loss = LostPacket(require_sent(sent, plan.packet_num), 'rto', 1600 + i * 1000)
            if i < 7:
                self.assertTrue(queue.note_loss(loss, sent))
            else:
                with self.assertRaises(TimeoutError):
                    queue.note_loss(loss, sent)
                self.assertIsNotNone(sent.get(plan.packet_num))

    def test_ack_after_max_retry_still_recovers(self):
        connection, sent, queue, frame, pn, loss = one_loss(max_retransmissions=1)
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        with self.assertRaises(TimeoutError):
            queue.note_loss(LostPacket(require_sent(sent, plan.packet_num), 'rto', 1600), sent)
        receipt = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))

    def test_nondata_losses_not_silently_dropped(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        p = connection.allocate_packet_number()
        sent.track_sent(p, WINDOW_UPDATE, 64, 1)
        with self.assertRaises(NotImplementedError):
            queue.note_loss(LostPacket(require_sent(sent, p), 'rto', 501), sent)
        self.assertIsNotNone(sent.get(p))

    def test_ack_only_never_retransmitted(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        p = connection.allocate_packet_number()
        self.assertFalse(sent.track_sent(p, ACK, 36, 1))
        self.assertIsNone(sent.get(p))

    def test_empty_queue_does_not_allocate_packet_number(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        initial = connection._next_send_packet_num
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 500))
        self.assertEqual(connection._next_send_packet_num, initial)

    def test_wrong_connection_rejected_before_allocating_pn(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        other = TransportConnectionState(CONN_ID + 1)
        with self.assertRaises(ValueError):
            queue.prepare_next(other, sent, KEY, 500)
        self.assertEqual(other._next_send_packet_num, 0)

    def test_invalid_key_does_not_drop_frame(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        with self.assertRaises((ValueError, TypeError)):
            queue.prepare_next(connection, sent, b"short", 600)
        self.assertEqual(queue.queued_count, 1)
        self.assertEqual(sent.bytes_in_flight, 0)
        self.assertIsNone(queue.prepared)
        self.assertIsNotNone(queue.prepare_next(connection, sent, KEY, 601))

    def test_loss_snapshot_must_match_tracking(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        wrong = LostPacket(replace(loss.packet, datagram_size=999), 'rto', 500)
        with self.assertRaises(ValueError):
            queue.note_loss(wrong, sent)
        self.assertIsNotNone(sent.get(pn))

    def test_invalid_constructor_arguments(self):
        for bad in (0, -1, 1<<64, True, 1.5, None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                DataRetransmissionQueue(cast(int, bad))
        for name in ('max_tracked_frames', 'max_queued_frames', 'max_queued_bytes', 'max_retransmissions'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                DataRetransmissionQueue(CONN_ID, **{name: 0})

    def test_sending_second_frame_does_not_block_another_stream(self):
        connection, sent, queue, frame, pn, loss = one_loss(b'file missing')
        chat = StreamSendFrame(1, 0, b'hi')
        p = connection.allocate_packet_number()
        sent.track_sent(p, DATA, 64, 5, frame=chat)
        self.assertIsNotNone(sent.get(p))
        self.assertEqual(queue.queued_count, 1)
        self.assertNotEqual(chat.stream_id, frame.stream_id)

    def test_batch_loss_detector_timeout_handoff_end_to_end(self):
        connection = TransportConnectionState(CONN_ID)
        sent = SentPacketTracker()
        rtt = RttEstimator()
        detector = PacketLossDetector()
        queue = DataRetransmissionQueue(CONN_ID)
        frame = StreamSendFrame(0, 0, b'control', False)
        pn = connection.allocate_packet_number()
        sent.track_sent(pn, DATA, 64, 0, frame=frame)
        losses = detector.check_timeouts(sent, rtt, 500)
        self.assertEqual(len(losses), 1)
        self.assertTrue(queue.note_loss(losses[0], sent))
        plan = queue.prepare_next(connection, sent, KEY, 510)
        assert plan is not None
        self.assertEqual(plan.packet_num, 1)
        self.assertEqual(rtt.rto_ms, 1000)
        queue.commit_sent(plan)
        receipt = sent.process_ack(encode_ack_body(0, [(1, 1)]))
        self.assertEqual(queue.on_ack(receipt, sent), (frame,))
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_packet_threshold_loss_integration(self):
        connection = TransportConnectionState(CONN_ID)
        sent = SentPacketTracker()
        detector = PacketLossDetector()
        queue = DataRetransmissionQueue(CONN_ID)
        frame = StreamSendFrame(1, 0, b'hi')
        pn = connection.allocate_packet_number()
        sent.track_sent(pn, DATA, 64, 0, frame=frame)
        for i in range(3):
            num = connection.allocate_packet_number()
            sent.track_sent(num, PING, 64, 10 + i)
        receipt = sent.process_ack(encode_ack_body(0, [(1, 3)]))
        losses = detector.on_ack(receipt, sent, 100)
        self.assertEqual([x.packet.packet_num for x in losses], [0])
        self.assertTrue(queue.note_loss(losses[0], sent))
        self.assertIsNotNone(queue.prepare_next(connection, sent, KEY, 101))


    def test_delivery_once_after_original_and_retry_arrive(self):
        connection = TransportConnectionState(CONN_ID)
        sent = SentPacketTracker()
        queue = DataRetransmissionQueue(CONN_ID)
        frame = StreamSendFrame(1, 0, b"hello", True)
        pn = connection.allocate_packet_number()
        sent.track_sent(pn, DATA, 64, 0, frame=frame)
        queue.note_loss(LostPacket(require_sent(sent, pn), "rto", 500), sent)
        retry = queue.prepare_next(connection, sent, KEY, 600)
        assert retry is not None
        queue.commit_sent(retry)
        sid, off, flags, data = decode_data_body(decode_packet(KEY, retry.datagram)[3])
        self.assertEqual((sid, off, flags, data), (1, 0, 1, b"hello"))

        rx_original_first = StreamReceiveState(1)
        first = rx_original_first.receive(frame.offset, frame.data, frame.fin)
        assert first is not None
        self.assertEqual((first.data, first.fin), (b"hello", True))
        self.assertIsNone(rx_original_first.receive(off, data, bool(flags)))

        rx_retry_first = StreamReceiveState(1)
        first = rx_retry_first.receive(off, data, bool(flags))
        assert first is not None
        self.assertEqual((first.data, first.fin), (b"hello", True))
        self.assertIsNone(rx_retry_first.receive(frame.offset, frame.data, frame.fin))

    def test_two_queued_frames_fifo_and_independent_ack(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        second = StreamSendFrame(1, 0, b"chat")
        pn2 = connection.allocate_packet_number()
        sent.track_sent(pn2, DATA, 64, 1, frame=second)
        queue.note_loss(loss, sent)
        queue.note_loss(LostPacket(require_sent(sent, pn2), 'rto', 501), sent)
        self.assertEqual(queue.queued_count, 2)
        plan1 = queue.prepare_next(connection, sent, KEY, 600)
        assert plan1 is not None
        self.assertEqual(plan1.frame, frame)
        queue.commit_sent(plan1)
        plan2 = queue.prepare_next(connection, sent, KEY, 601)
        assert plan2 is not None
        self.assertEqual(plan2.frame, second)
        queue.commit_sent(plan2)
        ack = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(ack, sent), (frame,))
        self.assertIsNotNone(sent.get(plan2.packet_num))
        self.assertEqual(queue.tracked_frames, 1)

    def test_ack_other_stream_while_two_pending_does_not_reorder(self):
        connection, sent, queue, frame, pn, loss = make_setup()
        queue.note_loss(loss, sent)
        second = StreamSendFrame(1, 0, b"chat")
        pn2 = connection.allocate_packet_number()
        sent.track_sent(pn2, DATA, 64, 1, frame=second)
        queue.note_loss(LostPacket(require_sent(sent, pn2), 'rto', 501), sent)
        ack = sent.process_ack(encode_ack_body(0, [(pn2, pn2)]))
        self.assertEqual(queue.on_ack(ack, sent), (second,))
        self.assertEqual(queue.queued_count, 1)
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        self.assertEqual(plan.frame, frame)

    def test_queue_full_signal_can_be_retried_after_space_recovers(self):
        connection, sent, queue, frame, pn, loss = make_setup(max_queued_frames=1)
        queue.note_loss(loss, sent)
        other = StreamSendFrame(1, 0, b"second")
        pn2 = connection.allocate_packet_number()
        sent.track_sent(pn2, DATA, 64, 10, frame=other)
        signal = LostPacket(require_sent(sent, pn2), 'rto', 510)
        with self.assertRaises(BufferError):
            queue.note_loss(signal, sent)
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        self.assertTrue(queue.note_loss(signal, sent))
        self.assertEqual(queue.queued_count, 1)

    def test_on_ack_validates_argument_types(self):
        _, sent, queue, *_ = one_loss()
        with self.assertRaises(TypeError):
            queue.on_ack(cast(AckReceipt, b"invalid"), sent)
        with self.assertRaises(TypeError):
            queue.on_ack(AckReceipt(0, ((0, 0),), (), 0), cast(SentPacketTracker, None))

    def test_note_loss_validates_input_types_without_mutation(self):
        _, sent, queue, frame, pn, loss = make_setup()
        with self.assertRaises(TypeError):
            queue.note_loss(cast(LostPacket, None), sent)
        with self.assertRaises(TypeError):
            queue.note_loss(loss, cast(SentPacketTracker, None))
        self.assertIsNotNone(sent.get(pn))

    def test_sender_does_not_requeue_data_on_no_ack(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        self.assertEqual(queue.queued_count, 0)
        self.assertIsNotNone(sent.get(plan.packet_num))
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 700))

    def test_late_ack_of_prior_attempt_while_next_retry_queued(self):
        connection, sent, queue, frame, pn, loss = one_loss()
        plan = queue.prepare_next(connection, sent, KEY, 600)
        assert plan is not None
        queue.commit_sent(plan)
        queue.note_loss(LostPacket(require_sent(sent, plan.packet_num), 'rto', 1600), sent)
        self.assertEqual(queue.queued_count, 1)
        late = sent.process_ack(encode_ack_body(0, [(pn, pn)]))
        self.assertEqual(queue.on_ack(late, sent), (frame,))
        self.assertIsNone(queue.prepare_next(connection, sent, KEY, 1800))


if __name__ == '__main__':
    unittest.main()
