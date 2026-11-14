"""B2.3 StreamManager tests: per-ConnID stream isolation and bounded queues.

Only validates stream state, not UDP I/O or application callback integration.
"""

import struct
import unittest
from typing import cast

from common.constants import CONTROL_CHAT_INITIAL_WINDOW, MAX_DATA_PER_PACKET
from common.streams import StreamDelivery, StreamManager, StreamSendFrame


class TestStreamManager(unittest.TestCase):
    def test_initial_streams_are_control_and_chat(self):
        m = StreamManager(77)
        self.assertEqual(m.conn_id, 77)
        self.assertEqual(m.stream_ids, (0, 1))
        self.assertEqual(m.file_stream_count, 0)
        self.assertEqual(m.buffered_bytes, 0)

    def test_conn_id_boundary_values(self):
        self.assertEqual(StreamManager(0).conn_id, 0)
        self.assertEqual(StreamManager((1 << 64) - 1).conn_id, (1 << 64) - 1)

    def test_invalid_conn_id(self):
        for bad in (-1, 1 << 64, True, 1.5, "1", None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                StreamManager(cast(int, bad))

    def test_invalid_file_stream_limit(self):
        for bad in (-1, 1 << 32, True, 2.5):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                StreamManager(1, max_file_streams=cast(int, bad))

    def test_invalid_aggregate_buffer_limit(self):
        for bad in (0, -1, 1 << 64, True, 2.5):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                StreamManager(1, max_buffered_bytes=cast(int, bad))

    def test_open_file_requires_explicit_registration(self):
        m = StreamManager(1)
        self.assertTrue(m.open_file_stream(2))
        self.assertEqual(m.stream_ids, (0, 1, 2))
        self.assertEqual(m.file_stream_count, 1)
        m.queue_bytes(2, b"abc")
        self.assertIsNone(m.next_send_frame(2))  # Initial credit = 0.

    def test_duplicate_file_open_keeps_state(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.queue_bytes(2, b"abc")
        self.assertFalse(m.open_file_stream(2))
        self.assertEqual(m.queued_send_bytes, 3)
        m.update_send_credit(2, 3)
        self.assertEqual(m.next_send_frame(2), StreamSendFrame(2, 0, b"abc"))

    def test_control_and_chat_cannot_be_opened_as_file(self):
        m = StreamManager(1)
        for stream_id in (0, 1):
            with self.subTest(stream_id=stream_id), self.assertRaises(ValueError):
                m.open_file_stream(stream_id)

    def test_invalid_file_stream_ids(self):
        m = StreamManager(1)
        for value in (-1, True, 1 << 32, None, 1.2):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.open_file_stream(cast(int, value))

    def test_unknown_file_rejected_on_all_operations(self):
        m = StreamManager(1)
        with self.assertRaises(ValueError):
            m.queue_bytes(2, b"x")
        with self.assertRaises(ValueError):
            m.next_send_frame(2)
        with self.assertRaises(ValueError):
            m.receive_frame(2, 0, b"x")
        with self.assertRaises(ValueError):
            m.update_send_credit(2, 1)
        with self.assertRaises(ValueError):
            m.grant_receive_credit(2, 1)
        self.assertEqual(m.stream_ids, (0, 1))

    def test_file_count_limit_enforced(self):
        m = StreamManager(1, max_file_streams=2)
        self.assertTrue(m.open_file_stream(2))
        self.assertTrue(m.open_file_stream(99))
        with self.assertRaises(ValueError):
            m.open_file_stream(3)
        self.assertEqual(m.stream_ids, (0, 1, 2, 99))

    def test_file_count_zero_disables_files(self):
        m = StreamManager(1, max_file_streams=0)
        with self.assertRaises(ValueError):
            m.open_file_stream(2)
        self.assertEqual(m.file_stream_count, 0)

    def test_discard_file_stream_and_idempotency(self):
        m = StreamManager(1)
        self.assertTrue(m.open_file_stream(2))
        self.assertTrue(m.discard_file_stream(2))
        self.assertFalse(m.discard_file_stream(2))
        self.assertEqual(m.stream_ids, (0, 1))

    def test_cannot_discard_control_or_chat(self):
        m = StreamManager(1)
        for stream_id in (0, 1):
            with self.subTest(stream_id=stream_id), self.assertRaises(ValueError):
                m.discard_file_stream(stream_id)
        self.assertEqual(m.stream_ids, (0, 1))

    def test_discard_releases_buffers_and_file_slot(self):
        m = StreamManager(1, max_file_streams=1)
        m.open_file_stream(2)
        m.queue_bytes(2, b"queued")
        m.grant_receive_credit(2, 100)
        self.assertIsNone(m.receive_frame(2, 5, b"buffered"))
        self.assertEqual(m.buffered_bytes, len(b"queued") + len(b"buffered"))
        m.discard_file_stream(2)  # B3 must ensure this is a safe cancel/cleanup.
        self.assertEqual(m.buffered_bytes, 0)
        self.assertTrue(m.open_file_stream(3))

    def test_discarded_id_cannot_be_reused_due_to_delayed_data(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.queue_bytes(2, b"abc")
        m.update_send_credit(2, 3)
        self.assertEqual(m.next_send_frame(2), StreamSendFrame(2, 0, b"abc"))
        m.discard_file_stream(2)
        with self.assertRaisesRegex(ValueError, "cannot be reused"):
            m.open_file_stream(2)
        self.assertTrue(m.open_file_stream(3))
        m.update_send_credit(3, 3)
        m.queue_bytes(3, b"new")
        self.assertEqual(m.next_send_frame(3), StreamSendFrame(3, 0, b"new"))

    def test_total_used_file_ids_are_bounded(self):
        m = StreamManager(1, max_file_streams=1, max_file_stream_ids_total=2)
        m.open_file_stream(2)
        m.discard_file_stream(2)
        m.open_file_stream(3)
        m.discard_file_stream(3)
        with self.assertRaisesRegex(ValueError, "total file stream ID"):
            m.open_file_stream(4)
        self.assertEqual(m.file_stream_count, 0)

    def test_invalid_total_file_id_limit(self):
        for bad in (0, -1, True, 1.5, 1 << 32):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                StreamManager(1, max_file_stream_ids_total=cast(int, bad))

    def test_send_offsets_are_independent(self):
        m = StreamManager(1)
        m.queue_bytes(0, b"abc")
        m.queue_bytes(1, b"12345")
        self.assertEqual(m.next_send_frame(0), StreamSendFrame(0, 0, b"abc"))
        self.assertEqual(m.next_send_frame(1), StreamSendFrame(1, 0, b"12345"))
        m.queue_bytes(0, b"d")
        self.assertEqual(m.next_send_frame(0), StreamSendFrame(0, 3, b"d"))

    def test_receive_offsets_are_independent(self):
        m = StreamManager(1)
        self.assertEqual(m.receive_frame(0, 0, b"abc"), StreamDelivery(0, 0, b"abc"))
        self.assertEqual(m.receive_frame(1, 0, b"chat"), StreamDelivery(1, 0, b"chat"))
        self.assertEqual(m.receive_frame(0, 3, b"d"), StreamDelivery(0, 3, b"d"))

    def test_send_receive_directions_are_independent(self):
        m = StreamManager(1)
        m.queue_bytes(1, b"out")
        self.assertEqual(m.receive_frame(1, 0, b"in"), StreamDelivery(1, 0, b"in"))
        self.assertEqual(m.next_send_frame(1), StreamSendFrame(1, 0, b"out"))
        self.assertEqual(m.receive_frame(1, 2, b"!"), StreamDelivery(1, 2, b"!"))

    def test_file_sender_blocked_does_not_block_chat(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.queue_bytes(2, b"file")
        m.queue_bytes(1, b"chat")
        self.assertIsNone(m.next_send_frame(2))
        self.assertEqual(m.next_send_frame(1), StreamSendFrame(1, 0, b"chat"))
        m.update_send_credit(2, 4)
        self.assertEqual(m.next_send_frame(2), StreamSendFrame(2, 0, b"file"))

    def test_file_receive_gap_does_not_block_chat(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 100)
        self.assertIsNone(m.receive_frame(2, 5, b"world", fin=True))
        self.assertEqual(m.receive_frame(1, 0, b"hi"), StreamDelivery(1, 0, b"hi"))
        self.assertEqual(
            m.receive_frame(2, 0, b"hello"),
            StreamDelivery(2, 0, b"helloworld", True),
        )

    def test_duplicate_data_never_redelivered(self):
        m = StreamManager(1)
        self.assertEqual(m.receive_frame(0, 0, b"abc"), StreamDelivery(0, 0, b"abc"))
        self.assertIsNone(m.receive_frame(0, 0, b"abc"))
        self.assertEqual(m.receive_frame(0, 3, b"d"), StreamDelivery(0, 3, b"d"))

    def test_fin_only_reported_once(self):
        m = StreamManager(1)
        self.assertEqual(
            m.receive_frame(1, 0, b"", fin=True), StreamDelivery(1, 0, b"", True)
        )
        self.assertIsNone(m.receive_frame(1, 0, b"", fin=True))

    def test_control_frame_prefix_preserved_as_raw_bytes(self):
        m = StreamManager(1)
        payload = b'{"v":1,"type":"AUTH"}'
        framed = struct.pack("!I", len(payload)) + payload
        m.queue_bytes(0, framed)
        frame = m.next_send_frame(0)
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.data, framed)  # No second length prefix.
        self.assertFalse(frame.fin)  # Stream 0 continues for other messages.

    def test_large_control_payload_split_and_reassemble(self):
        m = StreamManager(1)
        blob = b"A" * 2187
        m.queue_bytes(0, blob)
        parts: list[StreamSendFrame] = []
        while (part := m.next_send_frame(0)) is not None:
            parts.append(part)
        self.assertEqual([len(p.data) for p in parts], [1024, 1024, 139])
        delivered: list[bytes] = []
        for part in reversed(parts):
            item = m.receive_frame(0, part.offset, part.data, fin=part.fin)
            if item is not None:
                delivered.append(item.data)
        self.assertEqual(b"".join(delivered), blob)

    def test_send_credit_is_per_stream(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.open_file_stream(3)
        m.queue_bytes(2, b"abc")
        m.queue_bytes(3, b"xyz")
        m.update_send_credit(3, 3)
        self.assertIsNone(m.next_send_frame(2))
        self.assertEqual(m.next_send_frame(3), StreamSendFrame(3, 0, b"xyz"))

    def test_send_credit_decrease_rejected(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        self.assertTrue(m.update_send_credit(2, 100))
        self.assertFalse(m.update_send_credit(2, 100))
        with self.assertRaises(ValueError):
            m.update_send_credit(2, 99)

    def test_receive_credit_enforced_for_file(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        with self.assertRaises(ValueError):
            m.receive_frame(2, 0, b"abc")
        self.assertTrue(m.grant_receive_credit(2, 3))
        self.assertFalse(m.grant_receive_credit(2, 3))
        self.assertEqual(m.receive_frame(2, 0, b"abc"), StreamDelivery(2, 0, b"abc"))

    def test_receive_credit_decrease_rejected(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 20)
        with self.assertRaises(ValueError):
            m.grant_receive_credit(2, 19)

    def test_queued_and_receive_buffer_accounting(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 10)
        m.queue_bytes(1, b"abc")
        self.assertIsNone(m.receive_frame(2, 5, b"world"))
        self.assertEqual(m.queued_send_bytes, 3)
        self.assertEqual(m.buffered_receive_bytes, 5)
        self.assertEqual(m.buffered_bytes, 8)

    def test_global_buffer_limit_blocks_queue_atomically(self):
        m = StreamManager(1, max_buffered_bytes=5)
        m.queue_bytes(0, b"abc")
        with self.assertRaises(ValueError):
            m.queue_bytes(1, b"def", fin=True)
        self.assertEqual(m.queued_send_bytes, 3)
        m.queue_bytes(1, b"de", fin=True)
        self.assertEqual(m.next_send_frame(1), StreamSendFrame(1, 0, b"de", True))

    def test_global_buffer_limit_combines_streams(self):
        m = StreamManager(1, max_buffered_bytes=5)
        m.queue_bytes(0, b"abc")
        m.queue_bytes(1, b"de")
        with self.assertRaises(ValueError):
            m.queue_bytes(1, b"!")
        self.assertEqual(m.buffered_bytes, 5)

    def test_global_receive_limit_rollback_is_atomic(self):
        m = StreamManager(1, max_buffered_bytes=1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 4)
        self.assertIsNone(m.receive_frame(2, 3, b"d"))
        self.assertEqual(m.buffered_receive_bytes, 1)
        with self.assertRaisesRegex(ValueError, "connection-wide"):
            m.receive_frame(2, 1, b"bc")
        self.assertEqual(m.buffered_receive_bytes, 1)
        # If frame had partly committed, next deliveries would be incorrect.
        self.assertEqual(m.receive_frame(2, 0, b"a"), StreamDelivery(2, 0, b"a"))
        self.assertEqual(m.receive_frame(2, 1, b"bc"), StreamDelivery(2, 1, b"bcd"))

    def test_global_receive_overflow_does_not_commit_fin(self):
        m = StreamManager(1, max_buffered_bytes=1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 5)
        self.assertIsNone(m.receive_frame(2, 3, b"d"))
        with self.assertRaisesRegex(ValueError, "connection-wide"):
            # This FIN would be internally valid but exceed the aggregate cap.
            m.receive_frame(2, 1, b"bcd", fin=True)
        self.assertEqual(m.receive_frame(2, 0, b"a"), StreamDelivery(2, 0, b"a"))
        self.assertEqual(m.receive_frame(2, 1, b"bc"), StreamDelivery(2, 1, b"bcd"))
        # If the failed FIN had committed final_offset=4, this would fail.
        self.assertEqual(
            m.receive_frame(2, 4, b"e", fin=True), StreamDelivery(2, 4, b"e", True)
        )

    def test_contiguous_receive_does_not_occupy_b2_buffer(self):
        m = StreamManager(1, max_buffered_bytes=1)
        self.assertEqual(
            m.receive_frame(0, 0, b"hello"), StreamDelivery(0, 0, b"hello")
        )
        self.assertEqual(m.buffered_receive_bytes, 0)

    def test_send_and_receive_share_one_connection_memory_limit(self):
        m = StreamManager(1, max_buffered_bytes=4)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 6)
        m.queue_bytes(0, b"abc")
        self.assertIsNone(m.receive_frame(2, 5, b"f"))
        self.assertEqual(m.buffered_bytes, 4)
        with self.assertRaisesRegex(ValueError, "connection-wide"):
            m.receive_frame(2, 4, b"e")
        self.assertEqual(m.buffered_receive_bytes, 1)
        self.assertEqual(m.next_send_frame(0), StreamSendFrame(0, 0, b"abc"))
        self.assertIsNone(m.receive_frame(2, 4, b"e"))
        self.assertEqual(
            m.receive_frame(2, 0, b"abcd"), StreamDelivery(2, 0, b"abcdef")
        )

    def test_two_conn_ids_have_no_shared_offsets_or_file_tombstones(self):
        a = StreamManager(10)
        b = StreamManager(11)
        a.open_file_stream(2)
        a.discard_file_stream(2)
        with self.assertRaises(ValueError):
            a.open_file_stream(2)
        self.assertTrue(b.open_file_stream(2))
        a.queue_bytes(1, b"a")
        b.queue_bytes(1, b"b")
        self.assertEqual(a.next_send_frame(1), StreamSendFrame(1, 0, b"a"))
        self.assertEqual(b.next_send_frame(1), StreamSendFrame(1, 0, b"b"))

    def test_aggregate_capacity_freed_by_next_send_frame(self):
        m = StreamManager(1, max_buffered_bytes=3)
        m.queue_bytes(0, b"abc")
        with self.assertRaises(ValueError):
            m.queue_bytes(1, b"!")
        self.assertEqual(m.next_send_frame(0), StreamSendFrame(0, 0, b"abc"))
        m.queue_bytes(1, b"!")
        self.assertEqual(m.buffered_bytes, 1)

    def test_receive_capacity_freed_when_gap_is_filled(self):
        m = StreamManager(1, max_buffered_bytes=3)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 5)
        self.assertIsNone(m.receive_frame(2, 3, b"de"))
        self.assertEqual(m.buffered_bytes, 2)
        self.assertEqual(m.receive_frame(2, 0, b"abc"), StreamDelivery(2, 0, b"abcde"))
        self.assertEqual(m.buffered_bytes, 0)

    def test_invalid_send_input_does_not_mutate(self):
        m = StreamManager(1)
        for bad in (None, bytearray(b"x"), 1, "x"):
            with self.subTest(value=bad), self.assertRaises(TypeError):
                m.queue_bytes(0, cast(bytes, bad))
        self.assertEqual(m.buffered_bytes, 0)

    def test_invalid_next_frame_payload_does_not_consume_queue(self):
        m = StreamManager(1)
        m.queue_bytes(0, b"hi")
        for bad in (0, MAX_DATA_PER_PACKET + 1, True, 1.5):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                m.next_send_frame(0, max_payload=cast(int, bad))
        self.assertEqual(m.queued_send_bytes, 2)

    def test_invalid_received_payload_does_not_mutate(self):
        m = StreamManager(1)
        with self.assertRaises(TypeError):
            m.receive_frame(0, 0, cast(bytes, "hi"))
        with self.assertRaises(ValueError):
            m.receive_frame(0, -1, b"hi")
        self.assertEqual(
            m.receive_frame(0, 0, b"hello"), StreamDelivery(0, 0, b"hello")
        )

    def test_conflicting_overlap_does_not_corrupt_other_stream(self):
        m = StreamManager(1)
        m.open_file_stream(2)
        m.grant_receive_credit(2, 10)
        self.assertIsNone(m.receive_frame(2, 2, b"cd"))
        with self.assertRaises(ValueError):
            m.receive_frame(2, 3, b"X")
        self.assertEqual(m.receive_frame(1, 0, b"chat"), StreamDelivery(1, 0, b"chat"))
        self.assertEqual(m.receive_frame(2, 0, b"ab"), StreamDelivery(2, 0, b"abcd"))

    def test_file_stream_at_maximum_uint32(self):
        m = StreamManager(1)
        self.assertTrue(m.open_file_stream((1 << 32) - 1))
        self.assertEqual(m.stream_ids, (0, 1, (1 << 32) - 1))

    def test_no_automatic_ack_or_retransmission_in_b2(self):
        m = StreamManager(1)
        m.queue_bytes(1, b"hello", fin=True)
        self.assertEqual(m.next_send_frame(1), StreamSendFrame(1, 0, b"hello", True))
        self.assertIsNone(m.next_send_frame(1))
        self.assertEqual(m.queued_send_bytes, 0)
        # No claim that the DATA packet arrived at the remote peer.


if __name__ == "__main__":
    unittest.main()
