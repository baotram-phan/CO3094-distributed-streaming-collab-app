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
        port = listener.getsockname()[1]
        observed = []
        done = threading.Event()

        def run():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(3)
                    with server_context(self.cert, self.key).wrap_socket(
                        conn, server_side=True
                    ) as tls_sock:
                        observed.append(handle_bootstrap(tls_sock))
            except (ssl.SSLError, OSError):
                pass  # Trường hợp client cố tình không tin cậy chứng chỉ
            finally:
                listener.close()
                done.set()

        threading.Thread(target=run, daemon=True).start()
        return port, observed, done

    def test_hello_ack_over_tls_and_two_keys(self):
        port, observed, done = self._start_one_server()
        result = bootstrap(port=port, trusted_cert=self.cert)
        self.assertTrue(done.wait(4))
        self.assertEqual(len(observed), 1)
        self.assertEqual(result["conn_id"], observed[0].conn_id)
        self.assertEqual(result["c2s_key"], observed[0].c2s_key)
        self.assertEqual(result["s2c_key"], observed[0].s2c_key)
        self.assertNotEqual(result["c2s_key"], result["s2c_key"])
        self.assertEqual(result["udp_port"], 9001)

    def test_wrong_certificate_rejected(self):
        port, observed, done = self._start_one_server()
        with self.assertRaises(ssl.SSLCertVerificationError):
            bootstrap(port=port, trusted_cert=self.other_cert)
        self.assertTrue(done.wait(4))
        self.assertEqual(observed, [])


if __name__ == "__main__":
    unittest.main()
