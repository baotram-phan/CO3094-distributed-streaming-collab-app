"""Regression cases reported during A/B 2026-11-10 lifecycle review.

Uses B's real AEAD + UDP codec, but injects thread interleavings deterministically.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common.constants import REGISTER
from common.udp_packet import encode_packet
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService


class TestSoleCleanupOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.events = []
        registry = SessionRegistry(
            password_verifier=lambda u, p: u == "alice" and p == "pw"
        )
        self.server = CollaborationServer(
            tcp_port=0,
            udp_port=0,
            registry=registry,
            cert=self.cert,
            key=self.key,
            on_session_closed=self.events.append,
            logger=None,
        )
        self.registry = self.server.registry
        self.udp = self.server.udp_service
        self.session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=b"C" * 32, s2c_key=b"S" * 32
        )
        self.endpoint = ("127.0.0.1", 44550)
        self.packet = encode_packet(
            self.session.c2s_key, REGISTER, self.session.conn_id, 0
        )

    def tearDown(self):
        self.server.stop()

    def test_udp_handler_does_not_drain_close_queue(self):
        self.assertTrue(self.registry.close(self.session.conn_id, reason="test_close"))
        # A's queue remains intact even if UDP receives an unknown ConnID.
        self.assertFalse(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertEqual(self.events, [])
        self.assertEqual(len(self.registry.drain_closed_events()), 1)

    def test_coordinator_dispatches_transport_and_presence_exactly_once(self):
        self.udp._manager.add(self.session.conn_id)
        self.assertTrue(self.registry.close(self.session.conn_id, reason="logout"))
        self.server.dispatch_closed_events()
        self.assertNotIn(self.session.conn_id, self.udp.connection_ids())
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].reason, "logout")
        self.server.dispatch_closed_events()
        self.assertEqual(len(self.events), 1)

    def test_coordinator_delivers_username_for_presence_offline(self):
        self.assertTrue(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(
                self.session.conn_id, "alice", "pw"
            )
        )
        self.assertEqual(self.registry.list_online_users(), ["alice"])
        self.assertTrue(self.registry.close(self.session.conn_id, reason="logout"))
        self.server.dispatch_closed_events()
        self.assertEqual(self.registry.list_online_users(), [])
        self.assertEqual(
            [(event.conn_id, event.username) for event in self.events],
            [(self.session.conn_id, "alice")],
        )
        self.assertNotIn(self.session.conn_id, self.udp.connection_ids())

    def test_close_between_bind_and_add_never_resurrects_state(self):
        original = self.registry.bind_udp_verified_with_status

        def interleaved_bind(conn_id, endpoint):
            result = original(conn_id, endpoint)
            self.registry.close(conn_id, reason="raced_close")
            self.server.dispatch_closed_events()  # cleanup completes before add
            return result

        with patch.object(
            self.registry, "bind_udp_verified_with_status", side_effect=interleaved_bind
        ):
            self.assertFalse(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertEqual(self.udp.connection_ids(), set())
        self.assertEqual(len(self.events), 1)
        self.assertFalse(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertEqual(self.udp.connection_ids(), set())

    def test_close_during_add_is_undone_before_ack(self):
        original_add = self.udp._manager.add

        def add_and_close(conn_id):
            state = original_add(conn_id)
            self.registry.close(conn_id, reason="closed_during_add")
            return state

        with patch.object(self.udp._manager, "add", side_effect=add_and_close):
            self.assertFalse(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertNotIn(self.session.conn_id, self.udp.connection_ids())
        self.server.dispatch_closed_events()
        self.assertEqual(len(self.events), 1)

    def test_callback_uses_conn_id_and_endpoint_without_transport_lock(self):
        callback_calls = []

        def callback(conn_id, endpoint):
            callback_calls.append((conn_id, endpoint))
            self.assertTrue(self.registry.close(conn_id, reason="callback_closed"))
            # If UDP still holds lifecycle lock, this would deadlock.
            self.server.dispatch_closed_events()

        self.udp.on_udp_registered = callback
        self.assertFalse(self.udp.handle_datagram(self.packet, self.endpoint))
        self.assertEqual(callback_calls, [(self.session.conn_id, self.endpoint)])
        self.assertEqual(self.udp.connection_ids(), set())
        self.assertEqual(len(self.events), 1)

    def test_valid_register_callback_once_with_two_parameters(self):
        callback_calls = []
        self.udp.on_udp_registered = lambda conn_id, endpoint: callback_calls.append(
            (conn_id, endpoint)
        )
        self.assertTrue(self.udp.handle_datagram(self.packet, self.endpoint))
        pkt1 = encode_packet(self.session.c2s_key, REGISTER, self.session.conn_id, 1)
        self.assertTrue(self.udp.handle_datagram(pkt1, self.endpoint))
        self.assertFalse(self.udp.handle_datagram(pkt1, self.endpoint))
        self.assertEqual(callback_calls, [(self.session.conn_id, self.endpoint)])
        self.assertIn(self.session.conn_id, self.udp.connection_ids())
        self.assertIsNotNone(self.registry.get(self.session.conn_id))


if __name__ == "__main__":
    unittest.main()
