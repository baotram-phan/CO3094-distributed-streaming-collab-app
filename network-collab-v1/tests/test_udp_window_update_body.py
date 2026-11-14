"""Unit tests for WINDOW_UPDATE body codec (Protocol §4.2)."""

import unittest
from typing import cast

from common.constants import ACK, DATA, REGISTER, WINDOW_UPDATE
from common.crypto import encrypt_payload
from common.udp_packet import (
    WINDOW_UPDATE_STRUCT,
    decode_ack_body,
    decode_data_body,
    decode_packet,
    decode_window_update_body,
    encode_ack_body,
    encode_data_body,
    encode_header,
    encode_packet,
    encode_window_update_body,
)


class TestWindowUpdateBodyCodec(unittest.TestCase):

    def test_struct_size_is_12_bytes(self):
        self.assertEqual(WINDOW_UPDATE_STRUCT.size, 12)

    def test_roundtrip_control_stream(self):
        body = encode_window_update_body(0, 65536)
        self.assertEqual(len(body), 12)
        self.assertEqual(decode_window_update_body(body), (0, 65536))

    def test_known_big_endian_binary_representation(self):
        body = encode_window_update_body(1, 65536)
        self.assertEqual(body.hex(), "000000010000000000010000")
        self.assertEqual(
            decode_window_update_body(bytes.fromhex("000000010000000000010000")),
            (1, 65536),
        )

    def test_zero_values_are_well_formed(self):
        body = encode_window_update_body(0, 0)
        self.assertEqual(decode_window_update_body(body), (0, 0))

    def test_maximum_uint32_and_uint64(self):
        stream_id = (1 << 32) - 1
        max_offset = (1 << 64) - 1

        body = encode_window_update_body(stream_id, max_offset)

        self.assertEqual(decode_window_update_body(body), (stream_id, max_offset))

    def test_invalid_stream_id_rejected(self):
        for bad in (-1, 1 << 32, True, 1.5, "0", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    encode_window_update_body(cast(int, bad), 10)

    def test_invalid_max_offset_rejected(self):
        for bad in (-1, 1 << 64, True, 2.5, "10", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    encode_window_update_body(0, cast(int, bad))

    def test_truncated_body_rejected(self):
        full = encode_window_update_body(2, 500)

        for size in (0, 1, 4, 8, 11):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    decode_window_update_body(full[:size])

    def test_extra_bytes_rejected(self):
        full = encode_window_update_body(2, 500)

        for extra in (b"\0", b"\0" * 10):
            with self.subTest(extra_len=len(extra)):
                with self.assertRaises(ValueError):
                    decode_window_update_body(full + extra)

    def test_non_bytes_body_rejected(self):
        for bad in (None, "abcdef", bytearray(12), 123):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    decode_window_update_body(cast(bytes, bad))

    def test_encrypted_window_update_roundtrip(self):
        key = bytes(range(32))
        body = encode_window_update_body(3, 200000)

        packet = encode_packet(key, WINDOW_UPDATE, 101, 7, body)

        kind, conn_id, pn, plaintext = decode_packet(key, packet)

        self.assertEqual((kind, conn_id, pn), (WINDOW_UPDATE, 101, 7))
        self.assertEqual(decode_window_update_body(plaintext), (3, 200000))

    def test_encode_packet_rejects_malformed_window_update(self):
        key = bytes(range(32))

        for body in (b"", b"\0" * 11, b"\0" * 13):
            with self.subTest(size=len(body)):
                with self.assertRaises(ValueError):
                    encode_packet(key, WINDOW_UPDATE, 101, 7, body)

    def test_authenticated_malformed_window_update_rejected_on_decode(self):
        key = bytes(range(32))
        header = encode_header(WINDOW_UPDATE, 101, 7)

        bad_body = b"\0" * 11

        # Tag AES-GCM hợp lệ, nhưng body sai độ dài.
        datagram = header + encrypt_payload(key, 7, bad_body, header)

        with self.assertRaises(ValueError):
            decode_packet(key, datagram)

    def test_codec_does_not_enforce_monotonic_credit(self):
        # Kiểm tra credit tăng/giảm thuộc streams/transport.
        body1 = encode_window_update_body(0, 1000)
        body2 = encode_window_update_body(0, 500)

        self.assertEqual(decode_window_update_body(body1), (0, 1000))
        self.assertEqual(decode_window_update_body(body2), (0, 500))

    def test_existing_register_still_works(self):
        key = bytes(range(32))

        packet = encode_packet(key, REGISTER, 101, 7)

        self.assertEqual(decode_packet(key, packet), (REGISTER, 101, 7, b""))

    def test_existing_data_and_ack_still_work(self):
        key = bytes(range(32))

        data = encode_data_body(0, 0, 0, b"hello")
        ack = encode_ack_body(12, [(4, 7)])

        data_packet = encode_packet(key, DATA, 101, 8, data)
        ack_packet = encode_packet(key, ACK, 101, 9, ack)

        self.assertEqual(
            decode_data_body(decode_packet(key, data_packet)[3]), (0, 0, 0, b"hello")
        )

        self.assertEqual(
            decode_ack_body(decode_packet(key, ack_packet)[3]), (12, [(4, 7)])
        )


if __name__ == "__main__":
    unittest.main()
