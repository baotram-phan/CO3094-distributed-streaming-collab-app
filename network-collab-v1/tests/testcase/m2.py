"""A1.3 — kiểm thử bootstrap TLS bằng socket loopback thật."""

import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from common.tls import server_context
from examples.bootstrap_client import bootstrap
from scripts.gen_cert import generate_certificate
from server.bootstrap import handle_bootstrap
from server.sessions import SessionRegistry, SessionState


class TestBootstrapTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.temp.name) / "server")
        cls.other_cert, _ = generate_certificate(Path(cls.temp.name) / "not_trusted")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _start_one_server(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]
        self.registry = SessionRegistry()
        observed = []
        done = threading.Event()

        def run():
            try:
                conn, peer = listener.accept()
                with conn:
                    conn.settimeout(3)
                    with server_context(self.cert, self.key).wrap_socket(
                        conn, server_side=True
                    ) as tls_sock:
                        observed.append(
                            handle_bootstrap(
                                tls_sock, registry=self.registry, peer_ip=peer[0]
                            )
                        )
            except (ssl.SSLError, OSError):
                pass  # Trường hợp client cố tình không tin cậy chứng chỉ
            finally:
                listener.close()
                done.set()

        threading.Thread(target=run, daemon=True).start()
        return port, observed, done

    def test_hello_ack_over_tls_and_two_keys(self):
        """TC2.1: HELLO_ACK matches the saved session and contains two 32-byte keys."""
        port, observed, done = self._start_one_server()
        result = bootstrap(port=port, trusted_cert=self.cert)
        self.assertTrue(done.wait(4))
        self.assertEqual(len(observed), 1)
        self.assertEqual(result["conn_id"], observed[0].conn_id)
        self.assertEqual(result["c2s_key"], observed[0].c2s_key)
        self.assertEqual(result["s2c_key"], observed[0].s2c_key)
        self.assertEqual(len(result["c2s_key"]), 32)
        self.assertEqual(len(result["s2c_key"]), 32)
        self.assertNotEqual(result["c2s_key"], result["s2c_key"])
        self.assertEqual(result["udp_port"], 9001)
        saved = self.registry.get(result["conn_id"])
        self.assertIsNotNone(saved)
        self.assertIs(saved.state, SessionState.BOOTSTRAPPED)
        self.assertEqual(saved.tcp_ip, "127.0.0.1")
        self.assertIsNone(saved.username)
        self.assertIsNone(saved.udp_endpoint)

    def test_wrong_certificate_rejected(self):
        """TC2.2: untrusted server certificate fails TLS before session creation."""
        port, observed, done = self._start_one_server()
        with self.assertRaises(ssl.SSLCertVerificationError):
            bootstrap(port=port, trusted_cert=self.other_cert)
        self.assertTrue(done.wait(4))
        self.assertEqual(observed, [])
        self.assertEqual(len(self.registry), 0)


if __name__ == "__main__":
    unittest.main()
