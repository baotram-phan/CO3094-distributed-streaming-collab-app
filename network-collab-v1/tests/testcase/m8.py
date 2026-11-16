import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from common.constants import DATA
from common.replay import ReplayWindow
from common.udp_packet import encode_packet, decode_packet, encode_data_body
from examples.bootstrap_client import bootstrap
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer


class TestM8(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.wrong_cert, _ = generate_certificate(Path(cls.temp.name) / "other")
        cls.server = CollaborationServer(
            host="127.0.0.1", tcp_port=0, udp_port=0,
            logger=None, enable_reliable_bridge=False,
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def setUp(self):
        self.key = bytes(range(32))  # Khoa thu nghiem, khong dung trong thuc te
        body = encode_data_body(1, 0, 0, b"Chao Binh")
        self.packet = encode_packet(self.key, DATA, 42, 1, body)

    def test_01_tls_hop_le(self):
        print("\n[TC8.1] Client tin cay chung chi Server", flush=True)
        result = bootstrap(port=self.server.tcp_port)
        self.assertGreater(result["conn_id"], 0)
        self.assertEqual(len(result["c2s_key"]), 32)
        self.assertEqual(len(result["s2c_key"]), 32)
        print("  TLS va HELLO_ACK thanh cong => PASS", flush=True)

    def test_02_tls_sai_chung_chi(self):
        print("\n[TC8.2] Client dung chung chi khong dung", flush=True)
        with self.assertRaises(ssl.SSLCertVerificationError):
            bootstrap(port=self.server.tcp_port, trusted_cert=self.wrong_cert)
        print("  TLS tu choi chung chi sai => PASS", flush=True)

    def test_03_ma_hoa_giai_ma(self):
        print("\n[TC8.3] Ma hoa va giai ma tin nhan UDP", flush=True)
        self.assertNotIn(b"Chao Binh", self.packet)
        kind, conn_id, number, body = decode_packet(self.key, self.packet)
        self.assertEqual((kind, conn_id, number), (DATA, 42, 1))
        self.assertEqual(body, encode_data_body(1, 0, 0, b"Chao Binh"))
        print("  Du lieu duoc giai ma chinh xac => PASS", flush=True)

    def test_04_sua_du_lieu(self):
        print("\n[TC8.4] Ke xau sua 1 byte du lieu ma hoa", flush=True)
        bad = bytearray(self.packet)
        bad[-1] ^= 1
        with self.assertRaises(InvalidTag):
            decode_packet(self.key, bytes(bad))
        print("  AES-GCM phat hien packet bi sua => PASS", flush=True)

    def test_05_sai_khoa(self):
        print("\n[TC8.5] Client giai ma bang khoa khac", flush=True)
        wrong_key = b"B" * 32
        with self.assertRaises(InvalidTag):
            decode_packet(wrong_key, self.packet)
        print("  Giai ma that bai => PASS", flush=True)

    def test_06_sua_header(self):
        print("\n[TC8.6] Sua ConnID trong header UDP", flush=True)
        bad = bytearray(self.packet)
        bad[11] ^= 1  # Byte cuoi cua ConnID, van dung format
        with self.assertRaises(InvalidTag):
            decode_packet(self.key, bytes(bad))
        print("  Header duoc AES-GCM bao ve => PASS", flush=True)

    def test_07_goi_trung(self):
        print("\n[TC8.7] Nhan packet number 10 hai lan", flush=True)
        replay = ReplayWindow()
        self.assertTrue(replay.commit(10))
        self.assertFalse(replay.commit(10))
        self.assertTrue(replay.commit(11))
        print("  Packet trung bi chan, packet moi duoc nhan => PASS", flush=True)

    def test_08_khoa_sai_do_dai(self):
        print("\n[TC8.8] Su dung khoa AES chi co 31 byte", flush=True)
        with self.assertRaises(ValueError):
            encode_packet(b"A" * 31, DATA, 42, 1,
                          encode_data_body(1, 0, 0, b"hello"))
        print("  He thong tu choi khoa sai do dai => PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
