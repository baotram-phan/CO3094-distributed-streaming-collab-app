"""Verify cross-machine TLS certificates include the actual server LAN IP."""

import tempfile
import unittest
from pathlib import Path
from ipaddress import ip_address

from cryptography import x509
from scripts.gen_cert import generate_certificate


class TestLanTLSCert(unittest.TestCase):
    def test_san_ip_plus_localhost(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = generate_certificate(Path(d), san_ip="192.0.2.10")
            self.assertTrue(key.exists())
            loaded = x509.load_pem_x509_certificate(cert.read_bytes())
            san = loaded.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertIn(
                ip_address("192.0.2.10"), san.get_values_for_type(x509.IPAddress)
            )
            self.assertIn(
                ip_address("127.0.0.1"), san.get_values_for_type(x509.IPAddress)
            )
            self.assertIn("localhost", san.get_values_for_type(x509.DNSName))

    def test_invalid_san_ip_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                generate_certificate(Path(d), san_ip="not-an-ip")


if __name__ == "__main__":
    unittest.main()
