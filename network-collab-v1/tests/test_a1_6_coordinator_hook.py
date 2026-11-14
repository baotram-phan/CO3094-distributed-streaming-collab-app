"""A1.6 A coordinator glue; B's real reliable transport is not in this test."""

import struct
import tempfile
import unittest
from pathlib import Path

from client.core.a16_auth_protocol import build_auth_request
from common.control_stream_framing import decode_control_json
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionRegistry, SessionState


class CoordinatorHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.registry = SessionRegistry(
            password_verifier=lambda user, password: user == "an"
            and password == "correct"
        )
        self.messages = []
        self.server = CollaborationServer(
            registry=self.registry,
            cert=self.cert,
            key=self.key,
            tcp_port=0,
            udp_port=0,
            logger=None,
            enable_reliable_bridge=False,
        )
        self.session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1",
            c2s_key=b"A" * 32,
            s2c_key=b"B" * 32,
        )
        self.registry.bind_udp_verified(self.session.conn_id, ("127.0.0.1", 40008))

    def tearDown(self):
        self.server.stop()

    def test_cannot_invoke_auth_before_B_attaches_reliable_sender(self):
        with self.assertRaisesRegex(RuntimeError, "not attached"):
            self.server.on_reliable_stream_data(
                self.session.conn_id, 0, 0, build_auth_request("an", "correct")
            )
        self.assertEqual(
            self.registry.get(self.session.conn_id).state, SessionState.UDP_BOUND
        )

    def test_attached_sender_authenticated_and_coordinator_closes(self):
        self.server.attach_reliable_control(
            lambda cid, data: self.messages.append((cid, data))
        )
        with self.assertRaisesRegex(RuntimeError, "already attached"):
            self.server.attach_reliable_control(lambda cid, data: None)
        wire = build_auth_request("an", "correct")
        accepted = self.server.on_reliable_stream_data(self.session.conn_id, 0, 0, wire)
        self.assertTrue(accepted)
        self.assertEqual(
            self.registry.get(self.session.conn_id).state, SessionState.ONLINE
        )
        types = [decode_control_json(blob[4:])["type"] for _, blob in self.messages]
        self.assertEqual(types, ["AUTH_OK", "USER_LIST"])
        self.registry.close(self.session.conn_id, reason="logout")
        self.server.dispatch_closed_events()
        self.assertNotIn(self.session.conn_id, self.server.auth_service._states)
        self.assertIn(self.session.conn_id, self.server.auth_service._closed_conn_ids)
        self.assertEqual(self.server.udp_service.connection_ids(), set())


if __name__ == "__main__":
    unittest.main()
