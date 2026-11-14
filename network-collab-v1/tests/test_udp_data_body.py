"""A1.6 B1: DATA plaintext body codec tests against Protocol §4.2.

No socket, ACK, retransmission or application state in this unit-test module.
"""

import struct
import unittest

from common.constants import DATA, MAX_DATA_PER_PACKET, REGISTER
from common.udp_packet import (
    DATA_STRUCT,
    decode_data_body,
    decode_packet,
    encode_data_body,
    encode_packet,
)
from common.crypto import encrypt_payload
from common.udp_packet import encode_header


class TestDataBodyCodec(unittest.TestCase):
    def test_metadata_size_is_15_bytes(self):
        self.assertEqual(DATA_STRUCT.size, 15)

    def test_normal_roundtrip(self):
        body = encode_data_body(0, 0, 0, b"hello")
        self.assertEqual(len(body), 20)
        self.assertEqual(body, struct.pack("!IQBH", 0, 0, 0, 5) + b"hello")
        self.assertEqual(decode_data_body(body), (0, 0, 0, b"hello"))

    def test_empty_fin_only_is_legal(self):
        body = encode_data_body(2, 1024, 1, b"")
        self.assertEqual(decode_data_body(body), (2, 1024, 1, b""))

    def test_max_data_1024_is_legal(self):
        data = bytes(range(256)) * 4
        self.assertEqual(len(data), MAX_DATA_PER_PACKET)
        body = encode_data_body(1, 100, 0, data)
        self.assertEqual(decode_data_body(body), (1, 100, 0, data))

    def test_max_field_values_roundtrip(self):
        body = encode_data_body((1 << 32) - 1, (1 << 64) - 1, 1, b"")
        self.assertEqual(decode_data_body(body), ((1 << 32) - 1, (1 << 64) - 1, 1, b""))

    def test_wrong_fields_rejected_on_encode(self):
        bad_args = [
            (-1, 0, 0, b"x"),
            (1 << 32, 0, 0, b"x"),
            (True, 0, 0, b"x"),
            (0, -1, 0, b"x"),
            (0, 1 << 64, 0, b"x"),
            (0, True, 0, b"x"),
            (0, 0, 2, b"x"),
            (0, 0, True, b"x"),
            (0, 0, 0, b"x" * 1025),
        ]
        for args in bad_args:
            with self.subTest(args=args), self.assertRaises(ValueError):
                encode_data_body(*args)
        with self.assertRaises(TypeError):
            encode_data_body(0, 0, 0, "text")  # type: ignore[arg-type]

    def test_malformed_decoded_body_rejected(self):
        bad_bodies = [
            b"" * 0,
            b"\x00" * 14,
            struct.pack("!IQBH", 0, 0, 2, 1) + b"x",  # illegal flags
            struct.pack("!IQBH", 0, 0, 0, 4) + b"abc",  # short data
            struct.pack("!IQBH", 0, 0, 0, 2) + b"abc",  # extra data
            struct.pack("!IQBH", 0, 0, 0, 1025) + b"x" * 1025,
        ]
        for body in bad_bodies:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                decode_data_body(body)

    def test_encrypted_data_packet_roundtrip(self):
        key = bytes(range(32))
        body = encode_data_body(0, 10, 1, b"hello")
        packet = encode_packet(key, DATA, 100, 7, body)
        self.assertEqual(len(packet), 20 + len(body) + 16)
        typ, conn_id, pkt_num, decoded_body = decode_packet(key, packet)
        self.assertEqual((typ, conn_id, pkt_num), (DATA, 100, 7))
        self.assertEqual(decode_data_body(decoded_body), (0, 10, 1, b"hello"))

    def test_valid_aes_gcm_but_invalid_data_body_is_rejected(self):
        key = bytes(range(32))
        header = encode_header(DATA, 100, 1)
        # Deliberately construct an authenticated but malformed DATA body:
        # this bypasses encode_packet()'s new structural validation.
        invalid_body = struct.pack("!IQBH", 0, 0, 0, 6) + b"hello"
        packet = header + encrypt_payload(key, 1, invalid_body, header)
        with self.assertRaises(ValueError):
            decode_packet(key, packet)
        with self.assertRaises(ValueError):
            encode_packet(key, DATA, 100, 1, invalid_body)

    def test_register_existing_flow_is_unchanged(self):
        key = bytes(range(32))
        original = encode_packet(key, REGISTER, 100, 0, b"")
        self.assertEqual(decode_packet(key, original), (REGISTER, 100, 0, b""))


if __name__ == "__main__":
    unittest.main()
