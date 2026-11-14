"""B2.1 tests: one-direction, per-stream bounded reassembly (§5–§6)."""

import random
import unittest
from typing import cast

from common.constants import CONTROL_CHAT_INITIAL_WINDOW, FILE_INITIAL_WINDOW
from common.streams import StreamDelivery, StreamReceiveState
from common.udp_packet import decode_data_body, encode_data_body


class TestStreamReceiveState(unittest.TestCase):
    def test_control_initial_credit(self):
        state = StreamReceiveState(0)
        self.assertEqual(state.advertised_max_offset, CONTROL_CHAT_INITIAL_WINDOW)
        self.assertEqual(state.buffer_limit_bytes, 65536)
        self.assertEqual(state.delivered_offset, 0)

    def test_chat_initial_credit(self):
        state = StreamReceiveState(1)
        self.assertEqual(state.advertised_max_offset, 65536)

    def test_file_starts_with_zero_credit_and_larger_buffer(self):
        state = StreamReceiveState(2)
        self.assertEqual(state.advertised_max_offset, 0)
        self.assertEqual(state.buffer_limit_bytes, FILE_INITIAL_WINDOW)
        with self.assertRaises(ValueError):
            state.receive(0, b"A")
        self.assertTrue(state.grant_credit(FILE_INITIAL_WINDOW))
        delivery = state.receive(0, b"A")
        assert delivery is not None
        self.assertEqual(delivery.data, b"A")

    def test_in_order_two_chunks(self):
        state = StreamReceiveState(1)
        self.assertEqual(state.receive(0, b"Hi"), StreamDelivery(1, 0, b"Hi"))
        self.assertEqual(state.receive(2, b"!"), StreamDelivery(1, 2, b"!"))
        self.assertEqual(state.delivered_offset, 3)

    def test_out_of_order_buffer_then_flush(self):
        state = StreamReceiveState(0)
        self.assertIsNone(state.receive(5, b"world"))
        self.assertEqual(state.buffered_bytes, 5)
        self.assertEqual(
            state.receive(0, b"hello"), StreamDelivery(0, 0, b"helloworld")
        )
        self.assertEqual(state.buffered_bytes, 0)
        self.assertEqual(state.delivered_offset, 10)

    def test_gap_preserves_pending(self):
        state = StreamReceiveState(0)
        self.assertIsNone(state.receive(6, b"g"))
        self.assertEqual(state.receive(0, b"a"), StreamDelivery(0, 0, b"a"))
        self.assertEqual(state.delivered_offset, 1)
        self.assertEqual(state.buffered_bytes, 1)
        self.assertEqual(state.receive(1, b"bcdef"), StreamDelivery(0, 1, b"bcdefg"))

    def test_duplicates_never_redelivered(self):
        state = StreamReceiveState(1)
        self.assertIsNotNone(state.receive(0, b"hello"))
        self.assertIsNone(state.receive(0, b"hello"))
        self.assertEqual(state.delivered_offset, 5)

    def test_duplicate_pending_does_not_inflate_memory(self):
        state = StreamReceiveState(1)
        self.assertIsNone(state.receive(10, b"abc"))
        self.assertIsNone(state.receive(10, b"abc"))
        self.assertEqual(state.buffered_bytes, 3)

    def test_partial_duplicate_prefix_is_trimmed(self):
        state = StreamReceiveState(0)
        state.receive(0, b"hello")
        self.assertEqual(state.receive(3, b"lo world"), StreamDelivery(0, 5, b" world"))
        self.assertEqual(state.delivered_offset, 11)

    def test_overlap_in_pending_with_identical_bytes(self):
        state = StreamReceiveState(1)
        state.receive(4, b"efgh")
        state.receive(2, b"cdef")
        self.assertEqual(state.buffered_bytes, 6)
        self.assertEqual(state.receive(0, b"ab"), StreamDelivery(1, 0, b"abcdefgh"))

    def test_conflicting_pending_overlap_rejected_without_mutation(self):
        state = StreamReceiveState(1)
        state.receive(5, b"world")
        with self.assertRaises(ValueError):
            state.receive(7, b"XX")
        self.assertEqual(state.buffered_bytes, 5)
        self.assertEqual(
            state.receive(0, b"hello"), StreamDelivery(1, 0, b"helloworld")
        )

    def test_fin_with_final_data_in_order(self):
        state = StreamReceiveState(1)
        self.assertEqual(
            state.receive(0, b"ok", fin=True), StreamDelivery(1, 0, b"ok", True)
        )
        self.assertTrue(state.finished)
        self.assertEqual(state.final_offset, 2)
        self.assertIsNone(state.receive(0, b"ok", fin=True))

    def test_fin_only_empty_stream(self):
        state = StreamReceiveState(0)
        self.assertEqual(
            state.receive(0, b"", fin=True), StreamDelivery(0, 0, b"", True)
        )
        self.assertTrue(state.finished)
        self.assertIsNone(state.receive(0, b"", fin=True))

    def test_fin_held_until_gap_filled(self):
        state = StreamReceiveState(1)
        self.assertIsNone(state.receive(5, b"world", fin=True))
        self.assertEqual(state.final_offset, 10)
        self.assertFalse(state.finished)
        self.assertEqual(
            state.receive(0, b"hello"), StreamDelivery(1, 0, b"helloworld", True)
        )
        self.assertTrue(state.finished)

    def test_fin_only_out_of_order_then_reaches_end(self):
        state = StreamReceiveState(1)
        self.assertIsNone(state.receive(3, b"", fin=True))
        self.assertEqual(state.receive(0, b"abc"), StreamDelivery(1, 0, b"abc", True))

    def test_fin_with_already_delivered_bytes(self):
        state = StreamReceiveState(0)
        state.receive(0, b"abc")
        self.assertEqual(
            state.receive(0, b"abc", fin=True), StreamDelivery(0, 3, b"", True)
        )

    def test_conflicting_fin_rejected(self):
        state = StreamReceiveState(0)
        state.receive(5, b"world", fin=True)
        with self.assertRaises(ValueError):
            state.receive(3, b"", fin=True)
        self.assertEqual(state.final_offset, 10)

    def test_fin_shorter_than_buffered_data_rejected_without_commit(self):
        state = StreamReceiveState(0)
        state.receive(10, b"x")
        with self.assertRaises(ValueError):
            state.receive(5, b"", fin=True)
        self.assertIsNone(state.final_offset)
        self.assertEqual(state.buffered_bytes, 1)

    def test_fin_shorter_than_delivered_data_rejected(self):
        state = StreamReceiveState(0)
        state.receive(0, b"abcdef")
        with self.assertRaises(ValueError):
            state.receive(1, b"", fin=True)
        self.assertIsNone(state.final_offset)

    def test_data_past_fin_rejected(self):
        state = StreamReceiveState(0)
        state.receive(2, b"c", fin=True)
        with self.assertRaises(ValueError):
            state.receive(3, b"d")
        self.assertEqual(state.final_offset, 3)

    def test_receive_credit_boundary_and_gap(self):
        state = StreamReceiveState(0, buffer_limit_bytes=8, initial_max_offset=8)
        self.assertIsNone(state.receive(7, b"z"))
        with self.assertRaises(ValueError):
            state.receive(8, b"X")
        self.assertEqual(state.buffered_bytes, 1)

    def test_grant_credit_only_when_delivered(self):
        state = StreamReceiveState(0, buffer_limit_bytes=4, initial_max_offset=4)
        with self.assertRaises(ValueError):
            state.grant_credit(5)
        state.receive(0, b"ab")
        self.assertTrue(state.grant_credit(6))
        self.assertFalse(state.grant_credit(6))
        with self.assertRaises(ValueError):
            state.grant_credit(5)
        self.assertEqual(state.advertised_max_offset, 6)
        self.assertEqual(state.receive(4, b"cd"), None)
        self.assertEqual(state.receive(2, b"cd"), StreamDelivery(0, 2, b"cdcd"))

    def test_fin_must_be_within_credit_even_when_empty(self):
        state = StreamReceiveState(2)
        with self.assertRaises(ValueError):
            state.receive(1, b"", fin=True)
        self.assertIsNone(state.final_offset)

    def test_invalid_types_and_offsets(self):
        for value in (-1, 1 << 64, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    StreamReceiveState(1).receive(cast(int, value), b"x")
        for value in (-1, 1 << 32, True, 1.5):
            with self.subTest(stream_id=value):
                with self.assertRaises(ValueError):
                    StreamReceiveState(cast(int, value))
        with self.assertRaises(TypeError):
            StreamReceiveState(0).receive(0, cast(bytes, "x"))
        with self.assertRaises(ValueError):
            StreamReceiveState(0).receive(0, b"x", fin=cast(bool, 1))

    def test_excess_packet_size_rejected(self):
        state = StreamReceiveState(0)
        with self.assertRaises(ValueError):
            state.receive(0, b"x" * 1025)

    def test_byte_range_u64_overflow(self):
        state = StreamReceiveState(0)
        with self.assertRaises(ValueError):
            state.receive((1 << 64) - 1, b"x")

    def test_limits_are_validated(self):
        with self.assertRaises(ValueError):
            StreamReceiveState(0, buffer_limit_bytes=0)
        with self.assertRaises(ValueError):
            StreamReceiveState(0, buffer_limit_bytes=5, initial_max_offset=6)
        with self.assertRaises(ValueError):
            StreamReceiveState(0, initial_max_offset=-1)

    def test_streams_do_not_block_each_other(self):
        chat = StreamReceiveState(1)
        file = StreamReceiveState(2)
        file.grant_credit(512 * 1024)
        self.assertIsNone(file.receive(4, b"file", fin=True))
        self.assertEqual(chat.receive(0, b"Hi"), StreamDelivery(1, 0, b"Hi"))
        self.assertEqual(
            file.receive(0, b"1234"), StreamDelivery(2, 0, b"1234file", True)
        )

    def test_decoded_data_body_feeds_receiver(self):
        wire_body = encode_data_body(1, 0, 1, b"hello")
        stream_id, offset, flags, data = decode_data_body(wire_body)
        state = StreamReceiveState(stream_id)
        self.assertEqual(
            state.receive(offset, data, fin=bool(flags & 1)),
            StreamDelivery(1, 0, b"hello", True),
        )

    def test_permutation_of_ooo_chunks(self):
        payload = bytes(range(200)) * 5  # 1000 bytes
        chunks = [
            (idx, payload[idx : idx + 100]) for idx in range(0, len(payload), 100)
        ]
        rng = random.Random(20261111)
        for _ in range(20):
            state = StreamReceiveState(1)
            ordered = list(chunks)
            rng.shuffle(ordered)
            outputs = []
            for offset, data in ordered:
                delivery = state.receive(
                    offset, data, fin=offset + len(data) == len(payload)
                )
                if delivery is not None:
                    outputs.append(delivery.data)
            self.assertTrue(state.finished)
            self.assertEqual(b"".join(outputs), payload)
            self.assertEqual(state.buffered_bytes, 0)


if __name__ == "__main__":
    unittest.main()
