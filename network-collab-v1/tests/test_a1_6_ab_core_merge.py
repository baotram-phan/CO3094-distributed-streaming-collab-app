"""A/B API compatibility tests ONLY: no UDP DATA/ACK socket reliability claimed.

B's StreamManager produces contiguous bytes; A's coordinator accepts them at
its proposed application hook.  B3.2 still owns authenticated socket delivery.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from client.core.a16_auth_protocol import build_auth_request
from client.core.a17_chat_protocol import build_chat_direct
from common.control_stream_framing import decode_control_json
from common.streams import StreamManager
from common.udp_packet import encode_data_body, encode_packet
from common.constants import DATA
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionRegistry, SessionState


class TestABCoreCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.temp.name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.registry = SessionRegistry(password_verifier=lambda user, pwd: pwd == "pass")
        self.server = CollaborationServer(
            registry=self.registry, cert=self.cert, key=self.key,
            tcp_port=0, udp_port=0, logger=None,
            enable_reliable_bridge=False,
        )
        self.control_out = []
        self.chat_out = []
        self.server.attach_reliable_control(lambda cid, frame: self.control_out.append((cid, frame)))
        self.server.attach_reliable_chat(lambda cid, frame: self.chat_out.append((cid, frame)))
        self.an = self._bound("an", 54101)
        self.binh = self._bound("binh", 54102)

    def tearDown(self):
        self.server.stop()

    def _bound(self, username, port):
        session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=b"A" * 32, s2c_key=b"B" * 32,
        )
        self.registry.bind_udp_verified(session.conn_id, ("127.0.0.1", port))
        return session.conn_id

    def test_b_reassembly_can_feed_a_auth_hook(self):
        wire = build_auth_request("an", "pass")
        manager = StreamManager(self.an)
        split = len(wire) // 2
        # Simulate B's already-authenticated DATA arriving out of order.
        self.assertIsNone(manager.receive_frame(0, split, wire[split:]))
        delivery = manager.receive_frame(0, 0, wire[:split])
        self.assertIsNotNone(delivery)
        self.assertEqual((delivery.stream_id, delivery.offset, delivery.data), (0, 0, wire))
        self.assertTrue(self.server.on_reliable_stream_data(
            self.an, delivery.stream_id, delivery.offset, delivery.data, delivery.fin
        ))
        self.assertEqual(self.registry.get(self.an).state, SessionState.ONLINE)
        self.assertEqual([decode_control_json(frame[4:])["type"] for _, frame in self.control_out],
                         ["AUTH_OK", "USER_LIST"])

    def test_b_reassembly_can_feed_a_chat_hook(self):
        self.assertTrue(self.registry.authenticate_after_verified_udp(self.an, "an", "pass"))
        self.assertTrue(self.registry.authenticate_after_verified_udp(self.binh, "binh", "pass"))
        wire = build_chat_direct("binh", "hello", message_id=1)
        manager = StreamManager(self.an)
        delivery = manager.receive_frame(1, 0, wire)
        self.assertIsNotNone(delivery)
        self.assertTrue(self.server.on_reliable_stream_data(
            self.an, delivery.stream_id, delivery.offset, delivery.data, delivery.fin
        ))
        messages = [(cid, decode_control_json(blob[4:])["type"]) for cid, blob in self.chat_out]
        self.assertIn((self.binh, "CHAT_EVENT"), messages)
        self.assertIn((self.an, "CHAT_ACCEPTED"), messages)

    def test_udp_socket_not_misrepresented_as_reliable_data_yet(self):
        wire = build_auth_request("an", "pass")
        body = encode_data_body(0, 0, 0, wire)
        packet = encode_packet(b"A" * 32, DATA, self.an, 0, body)
        self.assertFalse(self.server.udp_service.handle_datagram(packet, ("127.0.0.1", 54101)))
        self.assertEqual(self.registry.get(self.an).state, SessionState.UDP_BOUND)


if __name__ == "__main__":
    unittest.main()
