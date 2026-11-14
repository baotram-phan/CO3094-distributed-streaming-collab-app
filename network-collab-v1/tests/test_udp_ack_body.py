"""B1.2 ACK codec tests; run with python -m unittest tests.test_udp_ack_body -v."""

import struct
import unittest

from typing import cast
from common.constants import ACK, REGISTER
from common.crypto import encrypt_payload
from common.udp_packet import (
    ACK_HEADER_STRUCT,
    ACK_RANGE_STRUCT,
    decode_ack_body,
    decode_packet,
    encode_ack_body,
    encode_header,
    encode_packet,
)


class TestAckBodyCodec(unittest.TestCase):
    def test_struct_sizes(self):
        self.assertEqual(ACK_HEADER_STRUCT.size, 3)
        self.assertEqual(ACK_RANGE_STRUCT.size, 16)

    def test_single_range_roundtrip(self):
        body = encode_ack_body(0, [(10, 12)])
        self.assertEqual(len(body), 19)
        self.assertEqual(decode_ack_body(body), (0, [(10, 12)]))

    def test_multiple_descending_ranges_roundtrip(self):
        ranges = [(10, 12), (4, 7), (0, 0)]
        body = encode_ack_body(25, ranges)
        self.assertEqual(len(body), 3 + 16 * 3)
        self.assertEqual(decode_ack_body(body), (25, ranges))

    def test_adjacent_ranges_allowed_by_proposed_spec(self):
        # The spec says descending/nonoverlapping; it does not require merging.
        ranges = [(10, 12), (7, 9)]
        self.assertEqual(decode_ack_body(encode_ack_body(0, ranges)), (0, ranges))

    def test_16_ranges_and_max_uints(self):
        ranges = [((1 << 64) - 1 - 2 * n, (1 << 64) - 1 - 2 * n) for n in range(16)]
        self.assertEqual(
            decode_ack_body(encode_ack_body(65535, ranges)), (65535, ranges)
        )

    def test_zero_and_17_ranges_rejected_on_encode(self):
        with self.assertRaises(ValueError):
            encode_ack_body(0, [])
        with self.assertRaises(ValueError):
            encode_ack_body(0, [(2 * n, 2 * n) for n in reversed(range(17))])

    def test_ack_delay_out_of_u16_and_bool_rejected(self):
        for value in (-1, 65536, True, 2.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                encode_ack_body(cast(int, value), [(1, 1)])

    def test_bad_range_bounds_and_bool_rejected(self):
        for ranges in ([(3, 2)], [(-1, 0)], [(0, 1 << 64)], [(True, 5)]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                encode_ack_body(1, cast(list[tuple[int, int]], ranges))

    def test_unsorted_and_overlapping_ranges_rejected(self):
        for ranges in ([(0, 1), (10, 12)], [(10, 12), (11, 11)], [(10, 12), (8, 10)]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                encode_ack_body(0, ranges)

    def test_malformed_lengths_rejected(self):
        body = encode_ack_body(5, [(10, 12)])
        for candidate in (b"", b"\x00", b"\x00\x01", body[:-1], body + b"\x00"):
            with self.subTest(body=candidate), self.assertRaises(ValueError):
                decode_ack_body(candidate)

    def test_zero_or_17_range_count_rejected_on_decode(self):
        for count in (0, 17):
            body = ACK_HEADER_STRUCT.pack(0, count) + b"\x00" * (16 * count)
            with self.subTest(count=count), self.assertRaises(ValueError):
                decode_ack_body(body)

    def test_unsorted_and_overlapping_rejected_on_decode(self):
        for a, b in (((0, 1), (4, 5)), ((10, 12), (11, 11)), ((10, 12), (8, 10))):
            body = (
                ACK_HEADER_STRUCT.pack(0, 2)
                + ACK_RANGE_STRUCT.pack(*a)
                + ACK_RANGE_STRUCT.pack(*b)
            )
            with self.subTest(first=a, second=b), self.assertRaises(ValueError):
                decode_ack_body(body)

    def test_ack_packet_aes_gcm_roundtrip(self):
        key = bytes(range(32))
        plain = encode_ack_body(20, [(15, 20), (9, 11)])
        packet = encode_packet(key, ACK, 100, 42, plain)
        typ, conn, pn, decoded = decode_packet(key, packet)
        self.assertEqual((typ, conn, pn), (ACK, 100, 42))
        self.assertEqual(decode_ack_body(decoded), (20, [(15, 20), (9, 11)]))

    def test_authenticated_but_invalid_ack_rejected(self):
        key = bytes(range(32))
        header = encode_header(ACK, 100, 42)
        # Valid GCM authentication tag, but zero ranges is invalid structure.
        invalid_body = ACK_HEADER_STRUCT.pack(0, 0)
        packet = header + encrypt_payload(key, 42, invalid_body, header)
        with self.assertRaises(ValueError):
            decode_packet(key, packet)
        with self.assertRaises(ValueError):
            encode_packet(key, ACK, 100, 42, invalid_body)

    def test_register_packet_is_unchanged(self):
        key = bytes(range(32))
        packet = encode_packet(key, REGISTER, 100, 42, b"")
        self.assertEqual(decode_packet(key, packet), (REGISTER, 100, 42, b""))


if __name__ == "__main__":
    unittest.main()
