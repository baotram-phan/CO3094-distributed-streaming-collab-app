"""B2.2: bounded per-stream sender, DATA framing, credit and FIN semantics."""

import unittest
from typing import cast

from common.constants import CONTROL_CHAT_INITIAL_WINDOW, FILE_INITIAL_WINDOW, MAX_DATA_PER_PACKET
from common.streams import StreamSendFrame, StreamSendState
from common.udp_packet import decode_data_body, encode_data_body


class TestStreamSendState(unittest.TestCase):
    def test_chat_default_credit(self):
        s = StreamSendState(1)
        self.assertEqual(s.advertised_max_offset, CONTROL_CHAT_INITIAL_WINDOW)
        self.assertEqual(s.buffer_limit_bytes, CONTROL_CHAT_INITIAL_WINDOW)

    def test_control_default_credit(self):
        self.assertEqual(StreamSendState(0).advertised_max_offset, 65536)

    def test_file_initial_credit_zero(self):
        s = StreamSendState(2)
        self.assertEqual(s.advertised_max_offset, 0)
        self.assertEqual(s.buffer_limit_bytes, FILE_INITIAL_WINDOW)
        s.queue(b"abc")
        self.assertIsNone(s.next_frame())
        self.assertEqual(s.queued_bytes, 3)
        self.assertTrue(s.update_credit(3))
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 0, b"abc"))

    def test_basic_roundtrip_via_data_codec(self):
        s = StreamSendState(1)
        s.queue(b"hello", fin=True)
        f = s.next_frame()
        assert f is not None
        self.assertEqual(decode_data_body(encode_data_body(f.stream_id, f.offset, f.flags, f.data)),
                         (1, 0, 1, b"hello"))

    def test_empty_queue(self):
        self.assertIsNone(StreamSendState(1).next_frame())

    def test_queue_empty_not_fin_is_noop(self):
        s = StreamSendState(1)
        s.queue(b"")
        self.assertIsNone(s.next_frame())

    def test_small_chunks_offset_advances(self):
        s = StreamSendState(1)
        s.queue(b"abcdefgh")
        self.assertEqual(s.next_frame(max_payload=3), StreamSendFrame(1, 0, b"abc"))
        self.assertEqual(s.next_frame(max_payload=3), StreamSendFrame(1, 3, b"def"))
        self.assertEqual(s.next_frame(max_payload=3), StreamSendFrame(1, 6, b"gh"))
        self.assertEqual(s.next_offset, 8)
        self.assertIsNone(s.next_frame())

    def test_max_packet_size(self):
        s = StreamSendState(1)
        s.queue(b"z" * 2049)
        sizes = []

        for _ in range(3):
            frame = s.next_frame()
            assert frame is not None
            sizes.append(len(frame.data))

        self.assertEqual(sizes, [1024, 1024, 1])

    def test_credit_limits_chunk(self):
        s = StreamSendState(2)
        s.queue(b"abcdef")
        s.update_credit(2)
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 0, b"ab"))
        self.assertIsNone(s.next_frame())
        self.assertEqual(s.queued_bytes, 4)
        s.update_credit(6)
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 2, b"cdef"))

    def test_fin_on_last_chunk_only(self):
        s = StreamSendState(1)
        s.queue(b"abcdef", fin=True)
        first = s.next_frame(max_payload=2)
        second = s.next_frame(max_payload=2)
        third = s.next_frame(max_payload=2)

        assert first is not None
        assert second is not None
        assert third is not None

        self.assertFalse(first.fin)
        self.assertFalse(second.fin)
        self.assertTrue(third.fin)
        self.assertEqual(third.offset + len(third.data), 6)

    def test_fin_after_credit_update(self):
        s = StreamSendState(2)
        s.queue(b"abcdef", fin=True)
        s.update_credit(3)
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 0, b"abc"))
        self.assertIsNone(s.next_frame())
        self.assertFalse(s.finished_sending)
        s.update_credit(6)
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 3, b"def", True))

    def test_empty_fin_only_once(self):
        s = StreamSendState(1)
        s.queue(b"", fin=True)
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 0, b"", True))
        self.assertIsNone(s.next_frame())
        self.assertTrue(s.finished_sending)

    def test_file_empty_fin_with_zero_credit(self):
        s = StreamSendState(2)
        s.queue(b"", fin=True)
        self.assertEqual(s.next_frame(), StreamSendFrame(2, 0, b"", True))

    def test_delayed_fin_after_previously_emitted_bytes(self):
        s = StreamSendState(1)
        s.queue(b"abc")
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 0, b"abc"))
        s.queue(b"", fin=True)
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 3, b"", True))

    def test_no_queue_after_fin(self):
        s = StreamSendState(1)
        s.queue(b"abc", fin=True)
        with self.assertRaises(ValueError):
            s.queue(b"x")
        with self.assertRaises(ValueError):
            s.queue(b"")

    def test_buffer_bounded_and_atomic(self):
        s = StreamSendState(1, buffer_limit_bytes=3)
        s.queue(b"ab")
        with self.assertRaises(ValueError):
            s.queue(b"cd", fin=True)
        self.assertEqual(s.queued_bytes, 2)
        self.assertFalse(s.fin_queued)
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 0, b"ab"))

    def test_queue_space_freed_on_emission_not_ack(self):
        s = StreamSendState(1, buffer_limit_bytes=4)
        s.queue(b"abcd")
        s.next_frame()
        self.assertEqual(s.queued_bytes, 0)
        s.queue(b"efgh")
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 4, b"efgh"))

    def test_duplicate_credit_update(self):
        s = StreamSendState(2)
        self.assertTrue(s.update_credit(10))
        self.assertFalse(s.update_credit(10))

    def test_credit_decrease_rejected(self):
        s = StreamSendState(2)
        s.update_credit(10)
        with self.assertRaises(ValueError):
            s.update_credit(9)
        self.assertEqual(s.advertised_max_offset, 10)

    def test_default_credit_can_be_customized(self):
        s = StreamSendState(1, initial_max_offset=2)
        s.queue(b"abc")
        self.assertEqual(s.next_frame(), StreamSendFrame(1, 0, b"ab"))
        self.assertIsNone(s.next_frame())

    def test_max_uint64_credit(self):
        s = StreamSendState(2)
        self.assertTrue(s.update_credit((1 << 64) - 1))
        self.assertEqual(s.advertised_max_offset, (1 << 64) - 1)

    def test_invalid_stream_id(self):
        for bad in (-1, 1 << 32, True, None, "1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                StreamSendState(cast(int, bad))

    def test_invalid_buffer_limits(self):
        for bad in (0, -1, 1 << 64, True, 1.2):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                StreamSendState(1, buffer_limit_bytes=cast(int, bad))

    def test_invalid_initial_credit(self):
        for bad in (-1, 1 << 64, True, 1.2):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                StreamSendState(1, initial_max_offset=cast(int, bad))

    def test_invalid_data_types(self):
        s = StreamSendState(1)
        for bad in (None, "hello", bytearray(b"abc"), 123):
            with self.subTest(bad=repr(bad)), self.assertRaises(TypeError):
                s.queue(cast(bytes, bad))
        self.assertEqual(s.queued_bytes, 0)

    def test_invalid_fin_flag(self):
        s = StreamSendState(1)
        with self.assertRaises(ValueError):
            s.queue(b"a", fin=cast(bool, 1))
        self.assertEqual(s.queued_bytes, 0)

    def test_invalid_chunk_sizes(self):
        s = StreamSendState(1)
        s.queue(b"hello")
        for bad in (0, -1, 1025, True, 1.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                s.next_frame(max_payload=cast(int, bad))
        self.assertEqual(s.queued_bytes, 5)

    def test_streams_do_not_share_offsets(self):
        file = StreamSendState(2)
        chat = StreamSendState(1)
        file.queue(b"file")
        self.assertIsNone(file.next_frame())
        chat.queue(b"hi")
        self.assertEqual(chat.next_frame(), StreamSendFrame(1, 0, b"hi"))
        self.assertEqual(file.next_offset, 0)

    def test_sending_frame_not_equivalent_to_remote_ack(self):
        s = StreamSendState(1)
        s.queue(b"hi", fin=True)
        frame = s.next_frame()

        assert frame is not None

        self.assertTrue(s.finished_sending)
        self.assertEqual(frame.offset, 0)
        # No ACK state exists in StreamSendState; B3 tracks in-flight frames.

    def test_credit_no_data_does_not_emit(self):
        s = StreamSendState(2)
        s.update_credit(200)
        self.assertIsNone(s.next_frame())

    def test_fin_flags_match_packet_codec(self):
        s = StreamSendState(1)
        s.queue(b"A", fin=True)
        frame = s.next_frame()
        assert frame is not None
        self.assertEqual(frame.flags, 1)
        self.assertEqual(decode_data_body(encode_data_body(frame.stream_id, frame.offset,
                                                           frame.flags, frame.data)), (1, 0, 1, b"A"))


if __name__ == "__main__":
    unittest.main()