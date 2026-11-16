import io
import socket
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from common.tls import client_context
from examples.bootstrap_client import bootstrap
from server.main import CollaborationServer, ROOT
from server.sessions import SessionRegistry
from tests import test_b51_loss_recovery as loss_tests


class TestM7(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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

    def check_server(self):
        result = bootstrap(port=self.server.tcp_port)
        self.assertGreater(result["conn_id"], 0)
        self.assertTrue(self.thread.is_alive())

    def test_01_timeout(self):
        print("\n[TC7.1] Server cho ket noi qua thoi gian cho", flush=True)
        time.sleep(0.25)  # Server accept() co timeout 0.1 giay
        self.check_server()
        print("  Server van nhan ket noi moi => PASS", flush=True)

    def test_02_client_disconnect(self):
        print("\n[TC7.2] Client ngat TCP dot ngot", flush=True)
        with socket.create_connection(("127.0.0.1", self.server.tcp_port)):
            pass  # Dong socket truoc khi TLS handshake
        self.check_server()
        print("  Server khong crash => PASS", flush=True)

    def test_03_invalid_tls(self):
        print("\n[TC7.3] Client gui du lieu TLS sai", flush=True)
        with socket.create_connection(("127.0.0.1", self.server.tcp_port)) as sock:
            sock.sendall(b"NOT A TLS HANDSHAKE")
        self.check_server()
        print("  Server tu choi va van hoat dong => PASS", flush=True)

    def test_04_exit_during_hello(self):
        print("\n[TC7.4] Client thoat sau TLS, chua gui HELLO", flush=True)
        with socket.create_connection(("127.0.0.1", self.server.tcp_port)) as raw:
            ctx = client_context(ROOT / "certs/server.crt")
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1"):
                pass  # Khong gui HELLO
        self.check_server()
        print("  Server van nhan HELLO tu Client khac => PASS", flush=True)

    def test_05_broken_pipe(self):
        print("\n[TC7.5] Gia lap BrokenPipeError", flush=True)
        with patch.object(self.server.tls_context, "wrap_socket",
                          side_effect=BrokenPipeError("client disconnected")):
            with socket.socket() as raw:
                self.server._handle_tls(raw, ("127.0.0.1", 50000))
        self.check_server()
        print("  Server da bat loi, khong crash => PASS", flush=True)

    def test_06_session_timeout(self):
        print("\n[TC7.6] Client khong hoat dong du 10 giay", flush=True)
        now = [0.0]
        registry = SessionRegistry(clock=lambda: now[0])
        session = registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=b"A" * 32, s2c_key=b"B" * 32
        )
        registry.bind_udp_verified(session.conn_id, ("127.0.0.1", 59001))
        now[0] = 10.0  # Gia lap thoi gian, khong can doi that
        self.assertIn(session.conn_id, registry.cleanup_expired())
        self.assertIsNone(registry.get(session.conn_id))
        print("  Phien het han duoc don dep => PASS", flush=True)

    def test_07_lost_udp_packet(self):
        print("\n[TC7.7] Mat packet DATA dau tien", flush=True)
        network = loss_tests.LossyUdpReliableLoopback("runTest")
        network.setUp()
        try:
            with redirect_stdout(io.StringIO()):
                sent, _ = network._run_c2s(
                    total_bytes=1024, force_first_data_drop=True, timeout_s=8
                )
            self.assertEqual(sent["data_dropped"], 1)
            self.assertGreaterEqual(sent["retransmitted_frames"], 1)
        finally:
            network.tearDown()
        print(f"  Mat {sent['data_dropped']} packet, "
              f"gui lai {sent['retransmitted_frames']} frame => PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
