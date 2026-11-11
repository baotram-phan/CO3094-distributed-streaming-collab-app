"""Regression tests for the real B-codec UDP client, not the reference adapter."""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from client.core.udp_connection import UDPRegistrationClient
from common.constants import REGISTER, REGISTER_OK
from common.udp_packet import decode_packet, encode_packet
from examples.bootstrap_client import bootstrap
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionState


class TestOfficialUDPRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.registrations = []
        self.server = CollaborationServer(
            tcp_port=0, udp_port=0, cert=self.cert, key=self.key, logger=None,
            on_udp_registered=lambda cid, endpoint: self.registrations.append((cid, endpoint)),
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.stop()
        self.worker.join(timeout=3)
        self.assertFalse(self.worker.is_alive(), 'Server thread must exit')

    def _bootstrap(self):
        started = time.monotonic()
        session = bootstrap(host='127.0.0.1', port=self.server.tcp_port, trusted_cert=self.cert)
        return started, session

    def _client(self, session, deadline):
        return UDPRegistrationClient(
            host='127.0.0.1', udp_port=session['udp_port'],
            conn_id=session['conn_id'], c2s_key=session['c2s_key'],
            s2c_key=session['s2c_key'], bind_host='127.0.0.1',
            bootstrap_deadline=deadline,
        )

    def test_tls_to_real_udp_register_and_first_event(self):
        started, s = self._bootstrap()
        with self._client(s, started + 10) as client:
            local = client.register()
            saved = self.server.registry.get(s['conn_id'])
            self.assertEqual(saved.state, SessionState.UDP_BOUND)
            self.assertEqual(saved.udp_endpoint[1], local[1])
            self.assertTrue(client.registered)
            self.assertEqual(self.registrations, [(s['conn_id'], saved.udp_endpoint)])
            self.assertIn(s['conn_id'], self.server.udp_service.connection_ids())

    def test_client_preserves_packet_counter_after_register(self):
        started, s = self._bootstrap()
        with self._client(s, started + 10) as client:
            client.register()
            self.assertEqual(client.state._next_send_packet_num, 1)
            with self.assertRaisesRegex(RuntimeError, 'Already registered'):
                client.register()
            pn = client.state.allocate_packet_number()
            client.sock.sendto(encode_packet(client.c2s_key, REGISTER, client.conn_id, pn),
                               client.server_endpoint)
            client.sock.settimeout(1)
            reply, _ = client.sock.recvfrom(2048)
            self.assertEqual(decode_packet(s['s2c_key'], reply)[:2], (REGISTER_OK, s['conn_id']))
            self.assertEqual(client.state._next_send_packet_num, 2)
            self.assertEqual(len(self.registrations), 1)

    def test_bootstrap_deadline_already_expired_sends_nothing(self):
        started, s = self._bootstrap()
        with self._client(s, time.monotonic() - 1) as client:
            with self.assertRaises(TimeoutError):
                client.register()
            self.assertEqual(client.state._next_send_packet_num, 0)
            self.assertFalse(client.registered)
            self.assertEqual(self.server.registry.get(s['conn_id']).state, SessionState.BOOTSTRAPPED)

    def test_wrong_server_key_never_validates_register_ok(self):
        started, s = self._bootstrap()
        with UDPRegistrationClient(
            host='127.0.0.1', udp_port=s['udp_port'], conn_id=s['conn_id'],
            c2s_key=s['c2s_key'], s2c_key=b'Q' * 32,
            bootstrap_deadline=time.monotonic() + 0.16,
        ) as client:
            with self.assertRaises(TimeoutError):
                client.register(wait_s=0.06)
            self.assertFalse(client.registered)

    def test_deadline_caps_retry_duration(self):
        started, s = self._bootstrap()
        expiry = time.monotonic() + 0.12
        with UDPRegistrationClient(
            host='127.0.0.1', udp_port=s['udp_port'], conn_id=s['conn_id'],
            c2s_key=s['c2s_key'], s2c_key=b'Q' * 32,
            bootstrap_deadline=expiry,
        ) as client:
            with self.assertRaises(TimeoutError):
                client.register(attempts=10, wait_s=0.5)
            self.assertLess(time.monotonic() - expiry, 0.20)
            self.assertLessEqual(client.state._next_send_packet_num, 1)


class TestUDPClientRetry(unittest.TestCase):
    def test_missing_first_ack_resends_with_new_packet_number(self):
        conn_id = 701
        c2s_key = b'C' * 32
        s2c_key = b'S' * 32
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(('127.0.0.1', 0))
            sink.settimeout(1)
            received = []
            def reply_on_second_packet():
                for i in range(2):
                    packet, source = sink.recvfrom(2048)
                    received.append(decode_packet(c2s_key, packet))
                    if i == 1:
                        sink.sendto(encode_packet(s2c_key, REGISTER_OK, conn_id, 0), source)
            responder = threading.Thread(target=reply_on_second_packet, daemon=True)
            responder.start()
            with UDPRegistrationClient(
                host='127.0.0.1', udp_port=sink.getsockname()[1],
                conn_id=conn_id, c2s_key=c2s_key, s2c_key=s2c_key,
                bootstrap_deadline=time.monotonic() + 2,
            ) as client:
                client.register(attempts=10, wait_s=0.06)
                self.assertTrue(client.registered)
                self.assertEqual(client.state._next_send_packet_num, 2)
            responder.join(timeout=2)
            self.assertFalse(responder.is_alive())
            self.assertEqual([r[2] for r in received], [0, 1])
            self.assertTrue(all(r[0] == REGISTER and r[1] == conn_id for r in received))


if __name__ == '__main__':
    unittest.main()
