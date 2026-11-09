import unittest

from common.constants import (
    REGISTER,
    REGISTER_OK,
    PING, 
    PONG
)

from common.udp_packet import (
    encode_header,
    decode_header,
    encode_packet,
    decode_packet,
    validate_packet_body
)

from cryptography.exceptions import InvalidTag

class TestUDPHeader(unittest.TestCase):

    def test_header_size(self):
        header = encode_header(0x01, 42, 0)

        self.assertEqual(len(header), 20)

    def test_encode_decode(self):
        header = encode_header(0x01, 42, 0)

        packet_type, conn_id, pkt_num = decode_header(header)

        self.assertEqual(packet_type, 0x01)
        self.assertEqual(conn_id, 42)
        self.assertEqual(pkt_num, 0)

    
    def test_boolean_packet_type_rejected(self):
        with self.assertRaises(ValueError):
            encode_header(True, 42, 0)

    def test_invalid_header_size(self):
        header = encode_header(0x01, 42, 0)

        invalid_header = header[:10]

        with self.assertRaises(ValueError):
            decode_header(invalid_header)

    
    def test_invalid_magic(self):
        header = encode_header(0x01, 42, 0)

        # Chuyển bytes thành bytearray để sửa nội dung
        invalid_header = bytearray(header)

        # Byte đầu tiên thuộc trường magic
        invalid_header[0] = 0x00

        with self.assertRaises(ValueError):
            decode_header(bytes(invalid_header))

        
    def test_invalid_version(self):
        header = encode_header(0x01, 42, 0)

        invalid_header = bytearray(header)

        # Version nằm ở byte thứ 3 (index 2)
        invalid_header[2] = 0x02

        with self.assertRaises(ValueError):
            decode_header(bytes(invalid_header))

        
    def test_encode_invalid_packet_type(self):
        with self.assertRaises(ValueError):
            encode_header(0x99, 42, 0)


    def test_decode_invalid_packet_type(self):
        header = bytearray(encode_header(0x01, 42, 0))

        # Packet type nằm ở index 3
        header[3] = 0x99

        with self.assertRaises(ValueError):
            decode_header(bytes(header))

            
    def test_invalid_conn_id(self):
        with self.assertRaises(ValueError):
            encode_header(0x01, -10, 0)


    def test_zero_conn_id(self):
        with self.assertRaises(ValueError):
            encode_header(0x01, 0, 0)


    def test_invalid_pkt_num(self):
        with self.assertRaises(ValueError):
            encode_header(0x01, 42, -1)


    def test_pkt_num_overflow(self):
        with self.assertRaises(ValueError):
            encode_header(0x01, 42, 1 << 64)

    
    def test_encode_register_packet(self):
        key = bytes(range(32))

        packet = encode_packet(
            key=key,
            packet_type=0x01,
            conn_id=42,
            pkt_num=1,
            plaintext=b""
        )

        # Header 20 byte + GCM tag 16 byte
        self.assertEqual(len(packet), 36)

        # Kiểm tra các trường header
        packet_type, conn_id, pkt_num = decode_header(
            packet[:20]
        )

        self.assertEqual(packet_type, 0x01)
        self.assertEqual(conn_id, 42)
        self.assertEqual(pkt_num, 1)

        
    def test_packet_roundtrip(self):
        key = bytes(range(32))

        original_packet = encode_packet(
            key=key,
            packet_type=0x01,
            conn_id=42,
            pkt_num=1,
            plaintext=b""
        )

        packet_type, conn_id, pkt_num, plaintext = decode_packet(
            key,
            original_packet
        )

        self.assertEqual(packet_type, 0x01)
        self.assertEqual(conn_id, 42)
        self.assertEqual(pkt_num, 1)
        self.assertEqual(plaintext, b"")

    def test_packet_too_short(self):
        key = bytes(range(32))

        packet = b"\x00" * 35

        with self.assertRaises(ValueError):
            decode_packet(key, packet)


    def test_packet_too_large(self):
        key = bytes(range(32))

        packet = b"\x00" * 1201

        with self.assertRaises(ValueError):
            decode_packet(key, packet)


    def test_packet_modified_tag(self):
        key = bytes(range(32))

        packet = encode_packet(
            key=key,
            packet_type=0x01,
            conn_id=42,
            pkt_num=1,
            plaintext=b""
        )

        modified_packet = bytearray(packet)

        modified_packet[-1] ^= 0x01

        with self.assertRaises(InvalidTag):
            decode_packet(key, bytes(modified_packet))

        def test_ping_invalid_body(self):
            with self.assertRaises(ValueError):
                validate_packet_body(PING, b"abc")


        def test_ping_valid_body(self):
            validate_packet_body(PING, b"\x00" * 8)


        def test_register_invalid_body(self):
            with self.assertRaises(ValueError):
                validate_packet_body(REGISTER, b"abc")


        def test_register_valid_body(self):
            validate_packet_body(REGISTER, b"")


if __name__ == "__main__":
    unittest.main()
