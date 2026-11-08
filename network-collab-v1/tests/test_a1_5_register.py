"""A1.5 reference integration tests: real TLS loopback + AES-GCM UDP REGISTER.

These do NOT validate B's real UDP codec; replace adapter and repeat with B.
"""
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from examples.bootstrap_client import bootstrap
from examples.a1_5_client import register_udp
from examples.a1_5_reference_udp import (
    HEADER, BadDatagram, REGISTER, REGISTER_OK,
    ReplayWindow, make_register_packet, verify_register_packet,
)
from examples.a1_5_server import A15Server
from scripts.gen_cert import generate_certificate
from server.sessions import SessionState


class TestA15Packet(unittest.TestCase):
    def test_packet_format_roundtrip(self):
        key = b'K' * 32
        datagram = make_register_packet(REGISTER, 123, 0, key)
        self.assertEqual(len(datagram), 36)
        self.assertEqual(datagram[:4], bytes.fromhex('4e430101'))
        self.assertEqual(verify_register_packet(datagram, key, expected_type=REGISTER), (123, 0))

    def test_aad_and_wrong_key_detected(self):
        packet = make_register_packet(REGISTER, 123, 5, b'A' * 32)
        with self.assertRaises(BadDatagram):
            verify_register_packet(packet, b'B' * 32, expected_type=REGISTER)
        modified = bytearray(packet)
        modified[11] ^= 0x01  # Tamper conn_id in AAD; header still parses
        with self.assertRaises(BadDatagram):
            verify_register_packet(bytes(modified), b'A' * 32, expected_type=REGISTER)

    def test_replay_window_allows_reorder_but_not_duplicate(self):
        w = ReplayWindow()
        self.assertTrue(w.can_accept(10))
        w.commit(10)
        self.assertFalse(w.can_accept(10))
        self.assertTrue(w.can_accept(8))
        w.commit(8)
        self.assertFalse(w.can_accept(8))
        self.assertFalse(w.can_accept(10 - 4096))


class TestA15ActualNetwork(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.server = A15Server(tcp_port=0, udp_port=0, cert=self.cert,
                                key=self.key, verbose=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.stop()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), 'Server must terminate')

    def bootstrap(self):
        return bootstrap(host='127.0.0.1', port=self.server.tcp_port, trusted_cert=self.cert)

    def test_tls_to_udp_bound_real_keys(self):
        session = self.bootstrap()
        self.assertEqual(self.server.registry.get(session['conn_id']).state, SessionState.BOOTSTRAPPED)
        local = register_udp(host='127.0.0.1', udp_port=self.server.udp_port,
                             conn_id=session['conn_id'], c2s_key=session['c2s_key'],
                             s2c_key=session['s2c_key'])
        saved = self.server.registry.get(session['conn_id'])
        self.assertEqual(saved.state, SessionState.UDP_BOUND)
        self.assertEqual(saved.udp_endpoint[1], local[1])
        self.assertEqual(self.server.registry.list_online_users(), [])

    def test_register_retry_new_pn_is_idempotent(self):
        s = self.bootstrap()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(0.4)
            packet0 = make_register_packet(REGISTER, s['conn_id'], 0, s['c2s_key'])
            sock.sendto(packet0, ('127.0.0.1', self.server.udp_port))
            response, _ = sock.recvfrom(2048)
            self.assertEqual(verify_register_packet(response, s['s2c_key'], expected_type=REGISTER_OK)[0], s['conn_id'])
            first = self.server.registry.get(s['conn_id'])
            # Send exact same datagram: anti-replay discards, no response.
            sock.sendto(packet0, ('127.0.0.1', self.server.udp_port))
            with self.assertRaises(socket.timeout):
                sock.recvfrom(2048)
            # Lost REGISTER_OK should be retried with a NEW packet number.
            sock.sendto(make_register_packet(REGISTER, s['conn_id'], 1, s['c2s_key']),
                        ('127.0.0.1', self.server.udp_port))
            response2, _ = sock.recvfrom(2048)
            self.assertEqual(verify_register_packet(response2, s['s2c_key'], expected_type=REGISTER_OK)[0], s['conn_id'])
            second = self.server.registry.get(s['conn_id'])
            self.assertEqual(first.udp_bound_at, second.udp_bound_at)
            self.assertEqual(len(self.server.registry), 1)

    def test_bad_key_cannot_bind_udp(self):
        s = self.bootstrap()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(make_register_packet(REGISTER, s['conn_id'], 0, b'W' * 32),
                        ('127.0.0.1', self.server.udp_port))
        time.sleep(0.1)
        self.assertEqual(self.server.registry.get(s['conn_id']).state, SessionState.BOOTSTRAPPED)

    def test_different_endpoint_cannot_replace_bound_endpoint(self):
        s = self.bootstrap()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as good, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bad:
            good.bind(('127.0.0.1', 0))
            bad.bind(('127.0.0.1', 0))
            good.settimeout(0.5)
            bad.settimeout(0.3)
            server_endpoint = ('127.0.0.1', self.server.udp_port)
            good.sendto(make_register_packet(REGISTER, s['conn_id'], 0, s['c2s_key']), server_endpoint)
            good.recvfrom(2048)
            expected = self.server.registry.get(s['conn_id']).udp_endpoint
            bad.sendto(make_register_packet(REGISTER, s['conn_id'], 1, s['c2s_key']), server_endpoint)
            with self.assertRaises(socket.timeout):
                bad.recvfrom(2048)
            self.assertEqual(self.server.registry.get(s['conn_id']).udp_endpoint, expected)
            # Failed attempt must not consume packet number in replay tracker.
            good.sendto(make_register_packet(REGISTER, s['conn_id'], 1, s['c2s_key']), server_endpoint)
            reply, _ = good.recvfrom(2048)
            self.assertEqual(verify_register_packet(reply, s['s2c_key'], expected_type=REGISTER_OK)[0], s['conn_id'])


if __name__ == '__main__':
    unittest.main()
