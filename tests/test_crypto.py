
import unittest

from common.crypto import (
    make_nonce,
    encrypt_payload,
    decrypt_payload,
)

from common.udp_packet import (
    encode_header,
    encode_packet
)

from cryptography.exceptions import InvalidTag

class TestNonce(unittest.TestCase):

    def test_nonce_zero(self):
        nonce = make_nonce(0)

        self.assertEqual(len(nonce), 12)
        self.assertEqual(nonce, b"\x00" * 12)

    def test_nonce_one(self):
        nonce = make_nonce(1)

        self.assertEqual(
            nonce.hex(),
            "000000000000000000000001"
        )

    def test_nonce_uniqueness(self):
        nonce1 = make_nonce(1)
        nonce2 = make_nonce(2)

        self.assertNotEqual(nonce1, nonce2)

    def test_invalid_packet_number(self):
        with self.assertRaises(ValueError):
            make_nonce(-1)


class TestAESGCM(unittest.TestCase):

    def test_encrypt_decrypt(self):
        # Khóa cố định chỉ dùng cho unit test
        key = bytes(range(32))

        pkt_num = 1
        header = encode_header(0x01, 42, pkt_num)
        plaintext = b"Hello UDP"

        encrypted = encrypt_payload(
            key, pkt_num, plaintext, header
        )

        decrypted = decrypt_payload(
            key, pkt_num, encrypted, header
        )

        self.assertEqual(decrypted, plaintext)

        self.assertEqual(
            len(encrypted),
            len(plaintext) + 16
        )

    
    def test_wrong_key(self):
        key = bytes(range(32))
        wrong_key = bytes([99]) * 32

        pkt_num = 2
        header = encode_header(0x01, 42, pkt_num)

        encrypted = encrypt_payload(
            key, pkt_num, b"Hello UDP", header
        )

        with self.assertRaises(InvalidTag):
            decrypt_payload(
                wrong_key, pkt_num, encrypted, header
            )

    def test_modified_ciphertext(self):
        key = bytes(range(32))
        pkt_num = 3
        header = encode_header(0x01, 42, pkt_num)

        encrypted = encrypt_payload(
            key, pkt_num, b"Hello UDP", header
        )

        modified = bytearray(encrypted)
        modified[0] ^= 0x01

        with self.assertRaises(InvalidTag):
            decrypt_payload(
                key, pkt_num, bytes(modified), header
            )

    def test_modified_header(self):
        key = bytes(range(32))
        pkt_num = 4
        header = encode_header(0x01, 42, pkt_num)

        encrypted = encrypt_payload(
            key, pkt_num, b"Hello UDP", header
        )

        modified_header = bytearray(header)
        modified_header[11] ^= 0x01

        with self.assertRaises(InvalidTag):
            decrypt_payload(
                key, pkt_num, encrypted,
                bytes(modified_header)
            )

if __name__ == "__main__":
    unittest.main()
