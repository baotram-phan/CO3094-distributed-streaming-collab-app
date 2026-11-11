"""A1.6/B1.4 CLOSE body codec tests (Protocol Specification §4.2)."""
import unittest
from typing import cast

from common.constants import ACK, CLOSE, DATA, REGISTER, WINDOW_UPDATE
from common.crypto import encrypt_payload
from common.udp_packet import (
    CLOSE_STRUCT,
    decode_ack_body,
    decode_close_body,
    decode_data_body,
    decode_packet,
    decode_window_update_body,
    encode_ack_body,
    encode_close_body,
    encode_data_body,
    encode_header,
    encode_packet,
    encode_window_update_body,
)


class TestCloseBodyCodec(unittest.TestCase):
    def test_struct_size_is_two_bytes(self):
        self.assertEqual(CLOSE_STRUCT.size, 2)

    def test_roundtrip_code_zero(self):
        self.assertEqual(decode_close_body(encode_close_body(0)), 0)

    def test_roundtrip_nonzero_code(self):
        self.assertEqual(decode_close_body(encode_close_body(42)), 42)

    def test_roundtrip_max_uint16_code(self):
        self.assertEqual(decode_close_body(encode_close_body(65535)), 65535)

    def test_known_big_endian_representation(self):
        self.assertEqual(encode_close_body(0x1234), bytes.fromhex('1234'))
        self.assertEqual(decode_close_body(bytes.fromhex('1234')), 0x1234)

    def test_reject_negative_code(self):
        with self.assertRaises(ValueError):
            encode_close_body(-1)

    def test_reject_code_exceeding_uint16(self):
        with self.assertRaises(ValueError):
            encode_close_body(65536)

    def test_reject_wrong_code_types_and_bool(self):
        for invalid in (True, False, 2.0, '1', None):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                encode_close_body(cast(int, invalid))

    def test_reject_short_bodies(self):
        for invalid in (b'', b'\x00'):
            with self.subTest(body=invalid), self.assertRaises(ValueError):
                decode_close_body(invalid)

    def test_reject_extra_bytes(self):
        for invalid in (b'\x00' * 3, b'\x00' * 16):
            with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                decode_close_body(invalid)

    def test_reject_wrong_body_types(self):
        for invalid in (None, 'hello', bytearray(2), 12):
            with self.subTest(value=invalid), self.assertRaises(TypeError):
                decode_close_body(cast(bytes, invalid))

    def test_encrypted_close_roundtrip(self):
        key = bytes(range(32))
        body = encode_close_body(7)
        packet = encode_packet(key, CLOSE, 101, 99, body)
        packet_type, conn_id, pkt_num, plaintext = decode_packet(key, packet)
        self.assertEqual((packet_type, conn_id, pkt_num), (CLOSE, 101, 99))
        self.assertEqual(decode_close_body(plaintext), 7)

    def test_encode_packet_rejects_invalid_close_body(self):
        key = bytes(range(32))
        for invalid in (b'', b'\x00', b'\x00' * 3):
            with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                encode_packet(key, CLOSE, 101, 99, invalid)

    def test_decode_packet_rejects_authenticated_invalid_close_body(self):
        key = bytes(range(32))
        header = encode_header(CLOSE, 101, 99)
        invalid_body = b'\x00'
        packet = header + encrypt_payload(key, 99, invalid_body, header)
        # AES-GCM tag is valid; plaintext CLOSE structure is invalid.
        with self.assertRaises(ValueError):
            decode_packet(key, packet)

    def test_existing_register_data_ack_and_window_update_unchanged(self):
        key = bytes(range(32))
        self.assertEqual(
            decode_packet(key, encode_packet(key, REGISTER, 101, 1)),
            (REGISTER, 101, 1, b''),
        )
        data = encode_data_body(1, 0, 0, b'hello')
        self.assertEqual(
            decode_data_body(decode_packet(key, encode_packet(key, DATA, 101, 2, data))[3]),
            (1, 0, 0, b'hello'),
        )
        ack = encode_ack_body(10, [(10, 12)])
        self.assertEqual(
            decode_ack_body(decode_packet(key, encode_packet(key, ACK, 101, 3, ack))[3]),
            (10, [(10, 12)]),
        )
        window = encode_window_update_body(0, 65536)
        self.assertEqual(
            decode_window_update_body(
                decode_packet(key, encode_packet(key, WINDOW_UPDATE, 101, 4, window))[3]
            ),
            (0, 65536),
        )


if __name__ == '__main__':
    unittest.main()