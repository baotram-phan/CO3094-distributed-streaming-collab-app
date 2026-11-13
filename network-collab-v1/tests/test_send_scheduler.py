"""B3.3.2 send scheduler/backpressure tests; no real socket or CUBIC required."""
import unittest
from typing import cast

from common.constants import DATA, WINDOW_UPDATE
from common.send_scheduler import ConnectionSendScheduler, PreparedScheduledSend
from common.streams import StreamManager, StreamSendFrame, StreamSendState
from common.transport import (
    DataRetransmissionQueue, LostPacket, SentPacket, SentPacketTracker,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    decode_data_body, decode_packet, decode_window_update_body, encode_ack_body,
)
from common.window_update_flow import WindowUpdateFlow

KEY = bytes(range(32))


class TestSendScheduler(unittest.TestCase):
    def setUp(self):
        self.conn_id = 745
        self.streams = StreamManager(self.conn_id)
        self.connection = TransportConnectionState(self.conn_id)
        self.sent = SentPacketTracker()
        self.retries = DataRetransmissionQueue(self.conn_id)
        self.flow = WindowUpdateFlow(self.streams)
        self.scheduler = ConnectionSendScheduler(
            self.streams, self.connection, self.sent, self.retries, self.flow
        )

    def maybe_prepare(self, *, cwnd: int = 3000, now: int = 100) -> PreparedScheduledSend | None:
        return self.scheduler.prepare_next(KEY, now_ms=now, cwnd_bytes=cwnd)

    def prepare(self, *, cwnd: int = 3000, now: int = 100) -> PreparedScheduledSend:
        plan = self.maybe_prepare(cwnd=cwnd, now=now)
        assert plan is not None
        return plan

    @staticmethod
    def data_frame(plan: PreparedScheduledSend) -> StreamSendFrame:
        frame = plan.frame
        assert frame is not None
        return frame

    def tracked(self, packet_num: int) -> SentPacket:
        packet = self.sent.get(packet_num)
        assert packet is not None
        return packet

    def confirm_ack(self, plan):
        receipt = self.sent.process_ack(encode_ack_body(0, [(plan.packet_num, plan.packet_num)]))
        self.retries.on_ack(receipt, self.sent)
        self.flow.on_ack(receipt, self.sent)
        return receipt

    def test_preview_never_pops_or_advances(self):
        s = StreamSendState(1)
        s.queue(b"abcdef", fin=True)
        self.assertEqual(s.peek_next_frame(max_payload=2), StreamSendFrame(1, 0, b"ab", False))
        self.assertEqual(s.peek_next_frame(max_payload=2), StreamSendFrame(1, 0, b"ab", False))
        self.assertEqual((s.queued_bytes, s.next_offset, s.finished_sending), (6, 0, False))
        self.assertEqual(s.next_frame(max_payload=2), StreamSendFrame(1, 0, b"ab", False))

    def test_preview_fin_only_not_emitted(self):
        s = StreamSendState(1)
        s.queue(b"", fin=True)
        self.assertEqual(s.peek_next_frame(), StreamSendFrame(1, 0, b"", True))
        self.assertFalse(s.finished_sending)
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 0, b"", True))
        self.assertTrue(s.finished_sending)

    def test_preview_file_no_credit(self):
        s = StreamSendState(2)
        s.queue(b"hello")
        self.assertIsNone(s.peek_next_frame())
        self.assertEqual(s.queued_bytes, 5)

    def test_manager_preview_rejects_unknown_file(self):
        with self.assertRaises(ValueError):
            self.streams.peek_send_frame(2)

    def test_basic_new_data_encrypted_roundtrip(self):
        self.streams.queue_bytes(1, b"hello")
        plan = self.prepare()
        self.assertEqual(plan.kind, "new_data")
        self.assertEqual(plan.stream_id, 1)
        kind, cid, pn, body = decode_packet(KEY, plan.datagram)
        self.assertEqual((kind, cid, pn), (DATA, self.conn_id, plan.packet_num))
        self.assertEqual(decode_data_body(body), (1, 0, 0, b"hello"))
        self.assertEqual(self.sent.bytes_in_flight, len(plan.datagram))
        self.scheduler.commit_sent(plan)
        self.assertEqual(self.streams.queued_send_bytes, 0)
        self.assertEqual(self.confirm_ack(plan).bytes_acked, len(plan.datagram))
        self.assertEqual(self.sent.bytes_in_flight, 0)

    def test_prepared_requires_commit_or_abort(self):
        self.streams.queue_bytes(1, b"a")
        plan = self.prepare()
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.scheduler.commit_sent(plan)
        with self.assertRaises(ValueError):
            self.scheduler.commit_sent(plan)

    def test_cwnd_zero_does_not_consume(self):
        self.streams.queue_bytes(1, b"hello")
        self.assertIsNone(self.maybe_prepare(cwnd=0))
        self.assertEqual(self.streams.queued_send_bytes, 5)
        self.assertEqual(self.streams._send_state(1).next_offset, 0)
        self.assertEqual(self.connection._next_send_packet_num, 0)

    def test_cwnd_smaller_than_overhead_does_not_consume(self):
        self.streams.queue_bytes(1, b"hello")
        self.assertIsNone(self.maybe_prepare(cwnd=51))
        self.assertEqual(self.streams.queued_send_bytes, 5)

    def test_cwnd_allows_exact_small_chunk(self):
        self.streams.queue_bytes(1, b"hello")
        plan = self.prepare(cwnd=53)
        self.assertEqual(self.data_frame(plan).data, b"he")
        self.assertEqual(len(plan.datagram), 53)
        self.scheduler.commit_sent(plan)
        self.assertEqual(self.streams._send_state(1).next_offset, 2)

    def test_cwnd_exact_full_packet(self):
        self.streams.queue_bytes(1, b"x" * 1024)
        plan = self.prepare(cwnd=1075)
        self.assertEqual(len(plan.datagram), 1075)
        self.scheduler.commit_sent(plan)

    def test_fin_only_minimum_51_byte_packet(self):
        self.streams.queue_bytes(1, b"", fin=True)
        plan = self.prepare(cwnd=51)
        self.assertTrue(self.data_frame(plan).fin)
        self.assertEqual(self.data_frame(plan).data, b"")
        self.assertEqual(len(plan.datagram), 51)
        self.scheduler.commit_sent(plan)

    def test_tracking_bytes_capacity_throttles_chunk(self):
        self.sent = SentPacketTracker(max_pending_bytes=56)
        self.scheduler = ConnectionSendScheduler(
            self.streams, self.connection, self.sent, self.retries, self.flow
        )
        self.streams.queue_bytes(1, b"0123456789")
        plan = self.prepare()
        self.assertEqual(len(self.data_frame(plan).data), 5)
        self.assertEqual(self.sent.bytes_in_flight, 56)
        self.scheduler.commit_sent(plan)
        self.assertIsNone(self.maybe_prepare())
        self.assertEqual(self.streams.queued_send_bytes, 5)
        self.confirm_ack(plan)
        next_plan = self.prepare(now=101)
        self.assertEqual(self.data_frame(next_plan).offset, 5)

    def test_tracking_packet_limit_blocks_without_pop(self):
        self.sent = SentPacketTracker(max_outstanding_packets=1)
        self.scheduler = ConnectionSendScheduler(
            self.streams, self.connection, self.sent, self.retries, self.flow
        )
        self.streams.queue_bytes(1, b"a" * 1025)
        first = self.prepare()
        self.scheduler.commit_sent(first)
        self.assertIsNone(self.maybe_prepare(now=101))
        self.assertEqual(self.streams._send_state(1).next_offset, 1024)

    def test_cwnd_counts_encrypted_packet_bytes_in_flight(self):
        self.streams.queue_bytes(1, b"a" * 120)
        first = self.prepare(cwnd=100)
        self.assertEqual(len(first.datagram), 100)
        self.scheduler.commit_sent(first)
        self.assertIsNone(self.maybe_prepare(cwnd=100, now=101))
        self.assertEqual(self.streams._send_state(1).next_offset, 49)
        self.confirm_ack(first)
        next_plan = self.prepare(cwnd=100, now=102)
        self.assertEqual(self.data_frame(next_plan).offset, 49)

    def test_no_credit_file_does_not_block_chat(self):
        self.streams.open_file_stream(2)
        self.streams.queue_bytes(2, b"F" * 10)
        self.streams.queue_bytes(1, b"chat")
        plan = self.prepare()
        self.assertEqual(plan.stream_id, 1)
        self.scheduler.commit_sent(plan)
        self.assertIsNone(self.maybe_prepare(now=101))
        self.assertEqual(self.streams._send_state(2).next_offset, 0)

    def test_file_can_send_after_window_update(self):
        self.streams.open_file_stream(2)
        self.streams.queue_bytes(2, b"file")
        self.assertIsNone(self.maybe_prepare())
        from common.udp_packet import encode_window_update_body
        self.assertTrue(self.flow.receive_peer_update(encode_window_update_body(2, 4)))
        plan = self.prepare(now=101)
        self.assertEqual((plan.stream_id, self.data_frame(plan).data), (2, b"file"))

    def test_fin_on_last_chunk_not_early(self):
        self.streams.queue_bytes(1, b"abcdef", fin=True)
        a = self.prepare(cwnd=53)
        self.assertFalse(self.data_frame(a).fin)
        self.scheduler.commit_sent(a)
        self.confirm_ack(a)
        b = self.prepare(cwnd=53, now=101)
        self.assertFalse(self.data_frame(b).fin)
        self.scheduler.commit_sent(b)
        self.confirm_ack(b)
        c = self.prepare(cwnd=53, now=102)
        self.assertTrue(self.data_frame(c).fin)
        self.scheduler.commit_sent(c)

    def test_send_failure_stages_original_frame_no_loss(self):
        self.streams.queue_bytes(1, b"retry me", fin=True)
        first = self.prepare()
        old_pn = first.packet_num
        self.scheduler.abort_send(first)
        self.assertEqual(self.scheduler.staged_count, 1)
        self.assertEqual(self.scheduler.staged_bytes, len(b"retry me"))
        self.assertEqual(self.sent.bytes_in_flight, 0)
        second = self.prepare(now=101)
        self.assertGreater(second.packet_num, old_pn)
        self.assertTrue(second.from_staged)
        self.assertEqual(second.frame, first.frame)
        self.scheduler.commit_sent(second)
        self.assertEqual(self.scheduler.staged_count, 0)
        self.assertEqual(self.streams.queued_send_bytes, 0)
        self.assertTrue(self.data_frame(second).fin)

    def test_repeated_abort_uses_fresh_nonce_each_time(self):
        self.streams.queue_bytes(0, b"A")
        nums = []
        for i in range(4):
            plan = self.prepare(now=100+i)
            nums.append(plan.packet_num)
            self.scheduler.abort_send(plan)
        self.assertEqual(nums, sorted(set(nums)))
        self.assertEqual(self.scheduler.staged_count, 1)

    def test_aborted_file_does_not_block_unrelated_chat(self):
        self.streams.open_file_stream(2)
        self.streams.update_send_credit(2, 1024)
        self.streams.queue_bytes(2, b"X" * 1024)
        file_plan = self.prepare(cwnd=1075)
        self.assertEqual(file_plan.stream_id, 2)
        self.scheduler.abort_send(file_plan)
        self.streams.queue_bytes(1, b"hi")
        chat_plan = self.prepare(cwnd=70, now=101)
        self.assertEqual(chat_plan.stream_id, 1)
        self.scheduler.commit_sent(chat_plan)
        self.assertEqual(self.scheduler.staged_count, 1)

    def test_wrong_key_never_consumes(self):
        self.streams.queue_bytes(1, b"good")
        with self.assertRaises(ValueError):
            self.scheduler.prepare_next(b"bad", now_ms=100, cwnd_bytes=3000)
        self.assertEqual(self.streams.queued_send_bytes, 4)
        self.assertEqual(self.connection._next_send_packet_num, 0)

    def test_invalid_cwnd_rejected(self):
        for value in (-1, 2.5, True, "1000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.scheduler.prepare_next(KEY, now_ms=100, cwnd_bytes=cast(int, value))

    def test_invalid_time_rejected(self):
        with self.assertRaises(ValueError):
            self.scheduler.prepare_next(KEY, now_ms=-100, cwnd_bytes=1000)

    def test_mismatched_conn_id_rejected(self):
        with self.assertRaises(ValueError):
            ConnectionSendScheduler(
                self.streams, TransportConnectionState(999), self.sent,
                self.retries, self.flow,
            )

    def test_bounded_failed_send_staging(self):
        self.scheduler = ConnectionSendScheduler(
            self.streams, self.connection, self.sent, self.retries, self.flow,
            max_staged_frames=1,
        )
        self.streams.queue_bytes(0, b"ctrl")
        self.streams.queue_bytes(1, b"chat")
        first = self.prepare()
        self.scheduler.abort_send(first)
        self.assertEqual(self.scheduler.staged_count, 1)
        second = self.prepare()
        self.assertTrue(second.from_staged)

    def test_pending_window_update_scheduled_first(self):
        delivery = self.streams.receive_frame(1, 0, b"abc")
        assert delivery is not None
        self.assertEqual(delivery.data, b"abc")
        self.flow.note_consumed(1, 3)
        self.streams.queue_bytes(1, b"chat")
        plan = self.prepare()
        self.assertEqual(plan.kind, "window_update")
        self.assertEqual(len(plan.datagram), 48)
        kind, _, _, body = decode_packet(KEY, plan.datagram)
        self.assertEqual(kind, WINDOW_UPDATE)
        self.assertEqual(decode_window_update_body(body), (1, 65539))
        self.scheduler.commit_sent(plan)
        next_plan = self.prepare(now=101)
        self.assertEqual(next_plan.kind, "new_data")

    def test_window_update_respects_cwnd_gate(self):
        self.streams.receive_frame(1, 0, b"a")
        self.flow.note_consumed(1, 1)
        self.assertIsNone(self.maybe_prepare(cwnd=47))
        self.assertEqual(self.flow.pending_stream_ids, (1,))
        plan = self.prepare(cwnd=48, now=101)
        self.assertEqual(plan.kind, "window_update")

    def test_failed_window_update_does_not_drop_credit(self):
        self.streams.receive_frame(1, 0, b"a")
        self.flow.note_consumed(1, 1)
        first = self.prepare()
        self.scheduler.abort_send(first)
        self.assertEqual(self.flow.pending_stream_ids, (1,))
        second = self.prepare(now=101)
        self.assertGreater(second.packet_num, first.packet_num)
        self.assertEqual(second.kind, "window_update")

    def test_window_update_ack_settlement(self):
        self.streams.receive_frame(1, 0, b"a")
        self.flow.note_consumed(1, 1)
        plan = self.prepare()
        self.scheduler.commit_sent(plan)
        receipt = self.confirm_ack(plan)
        self.assertEqual(receipt.newly_acked_count, 1)
        self.assertEqual(self.flow.pending_stream_ids, ())

    def test_real_retry_after_loss_uses_fresh_packet_number(self):
        self.streams.queue_bytes(1, b"lost-data")
        original = self.prepare()
        self.scheduler.commit_sent(original)
        packet = self.tracked(original.packet_num)
        lost = LostPacket(packet, "rto", 600)
        self.assertTrue(self.retries.note_loss(lost, self.sent))
        retry = self.prepare(now=601)
        self.assertEqual(retry.kind, "data_retry")
        self.assertGreater(retry.packet_num, original.packet_num)
        self.assertEqual(retry.frame, original.frame)
        self.scheduler.commit_sent(retry)
        self.assertEqual(self.retries.queued_count, 0)

    def test_retry_send_failure_remains_queued(self):
        self.streams.queue_bytes(1, b"abc")
        original = self.prepare()
        self.scheduler.commit_sent(original)
        self.retries.note_loss(LostPacket(self.tracked(original.packet_num), "rto", 600), self.sent)
        retry = self.prepare(now=601)
        self.scheduler.abort_send(retry)
        self.assertEqual(self.retries.queued_count, 1)
        again = self.prepare(now=602)
        self.assertGreater(again.packet_num, retry.packet_num)

    def test_cwnd_blocks_large_retry_but_allows_short_chat(self):
        self.streams.open_file_stream(2)
        self.streams.update_send_credit(2, 1024)
        self.streams.queue_bytes(2, b"F" * 1024)
        original = self.prepare(cwnd=1100)
        self.scheduler.commit_sent(original)
        self.retries.note_loss(LostPacket(self.tracked(original.packet_num), "rto", 600), self.sent)
        self.streams.queue_bytes(1, b"hi")
        plan = self.prepare(cwnd=60, now=601)
        self.assertEqual(plan.stream_id, 1)

    def test_fair_file_and_chat(self):
        self.streams.open_file_stream(2)
        self.streams.update_send_credit(2, 512)
        self.streams.queue_bytes(2, b"f" * 50)
        self.streams.queue_bytes(1, b"c" * 50)
        self.streams.queue_bytes(0, b"o" * 50)
        ids = []
        for i in range(10):
            plan = self.maybe_prepare(cwnd=54, now=100 + i)
            if plan is None:
                break
            ids.append(plan.stream_id)
            self.scheduler.commit_sent(plan)
            self.confirm_ack(plan)
        self.assertIn(2, ids)
        self.assertIn(1, ids)
        self.assertIn(0, ids)

    def test_two_file_streams_round_robin(self):
        for sid in (2,3):
            self.streams.open_file_stream(sid)
            self.streams.update_send_credit(sid, 1024)
            self.streams.queue_bytes(sid, b"a" * 20)
        seen = []
        for i in range(10):
            plan = self.maybe_prepare(cwnd=60, now=100+i)
            if plan is None: break
            seen.append(plan.stream_id)
            self.scheduler.commit_sent(plan)
            self.confirm_ack(plan)
        self.assertIn(2, seen)
        self.assertIn(3, seen)

    def test_control_bytes_unchanged(self):
        framed_auth_bytes = b"\x00\x00\x00\x04AUTH"
        self.streams.queue_bytes(0, framed_auth_bytes)
        plan = self.prepare()
        self.assertEqual(self.data_frame(plan).data, framed_auth_bytes)
        self.scheduler.commit_sent(plan)

    def test_no_socket_io_here(self):
        self.assertFalse(hasattr(self.scheduler, "sendto"))

    def test_abort_invalid_plan_leaves_state_untouched(self):
        self.streams.queue_bytes(0, b"hello")
        plan = self.prepare()
        with self.assertRaises(ValueError):
            self.scheduler.abort_send(cast(PreparedScheduledSend, object()))
        self.assertIs(self.scheduler.prepared, plan)
        self.scheduler.abort_send(plan)

    def test_staged_plan_must_be_committed_not_lost(self):
        self.streams.queue_bytes(0, b"hello")
        plan = self.prepare()
        self.scheduler.abort_send(plan)
        next_plan = self.prepare(now=101)
        self.scheduler.abort_send(next_plan)
        self.assertEqual(self.scheduler.staged_bytes, 5)


if __name__ == "__main__":
    unittest.main()