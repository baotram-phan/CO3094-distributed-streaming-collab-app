"""Test A-side coordinator stream dispatch with injected B enqueue shims."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from client.core.a17_chat_protocol import build_chat_direct
from client.core.a16_auth_protocol import build_auth_request
from common.control_stream_framing import decode_control_json
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionRegistry, SessionState


class TestA17CoordinatorHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = generate_certificate(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.registry = SessionRegistry(password_verifier=lambda u, p: p == 'pass')
        self.control_out = []
        self.chat_out = []
        self.server = CollaborationServer(
            registry=self.registry, cert=self.cert, key=self.key,
            tcp_port=0, udp_port=0, logger=None,
            enable_reliable_bridge=False,
        )
        self.an = self._online('an', 49001)
        self.binh = self._online('binh', 49002)

    def tearDown(self):
        self.server.stop()

    def _online(self, username, port):
        s = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                           c2s_key=b'A'*32, s2c_key=b'B'*32)
        self.registry.bind_udp_verified(s.conn_id, ('127.0.0.1', port))
        self.assertTrue(self.registry.authenticate_after_verified_udp(s.conn_id, username, 'pass'))
        return s.conn_id

    def test_chat_not_connected_without_B(self):
        with self.assertRaisesRegex(RuntimeError, 'not attached'):
            self.server.on_reliable_stream_data(self.an, 1, 0, build_chat_direct('binh', 'hi', message_id=1))

    def test_cannot_attach_chat_before_control(self):
        with self.assertRaisesRegex(RuntimeError, 'control stream 0'):
            self.server.attach_reliable_chat(lambda cid, payload: None)

    def test_auth_then_chat_only_through_verified_stream_callbacks(self):
        # Start with a registered, NOT authenticated connection. Simulate B's
        # verified contiguous stream data, not an actual UDP sender.
        self.registry.close(self.an, reason='replace_fixture')
        self.server.dispatch_closed_events()
        s = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                           c2s_key=b'A'*32, s2c_key=b'B'*32)
        self.registry.bind_udp_verified(s.conn_id, ('127.0.0.1', 49010))
        self.server.attach_reliable_control(lambda cid, data: self.control_out.append((cid, data)))
        self.server.attach_reliable_chat(lambda cid, data: self.chat_out.append((cid, data)))
        self.assertFalse(self.server.on_reliable_stream_data(
            s.conn_id, 1, 0, build_chat_direct('binh', 'no auth', message_id=1)))
        self.assertEqual(decode_control_json(self.control_out[-1][1][4:])['body']['code'],
                         'NOT_AUTHENTICATED')
        frame = build_auth_request('an', 'pass')
        self.assertTrue(self.server.on_reliable_stream_data(s.conn_id, 0, 0, frame))
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.ONLINE)
        self.assertTrue(self.server.on_reliable_stream_data(
            s.conn_id, 1, 0, build_chat_direct('binh', 'now online', message_id=1)))
        types = [decode_control_json(payload[4:])['type'] for _, payload in self.chat_out]
        self.assertEqual(types, ['CHAT_EVENT', 'CHAT_ACCEPTED'])

    def test_chat_hook_routes_only_stream_one_and_cleanup(self):
        self.server.attach_reliable_control(lambda cid, data: self.control_out.append((cid, data)))
        self.server.attach_reliable_chat(lambda cid, data: self.chat_out.append((cid, data)))
        with self.assertRaisesRegex(RuntimeError, 'already attached'):
            self.server.attach_reliable_chat(lambda cid, payload: None)
        frame = build_chat_direct('binh', 'hi', message_id=1)
        self.assertTrue(self.server.on_reliable_stream_data(self.an, 1, 0, frame))
        self.assertEqual(self.registry.get(self.an).state, SessionState.ONLINE)
        self.assertEqual([decode_control_json(blob[4:])['type'] for _, blob in self.chat_out],
                         ['CHAT_EVENT', 'CHAT_ACCEPTED'])
        with self.assertRaisesRegex(ValueError, 'not integrated'):
            self.server.on_reliable_stream_data(self.an, 2, 0, b'hello')
        self.registry.close(self.binh, reason='logout')
        self.server.dispatch_closed_events()
        self.assertIn(self.binh, self.server.chat_service._closed)
        self.assertNotIn(self.binh, self.server.chat_service._states)


if __name__ == '__main__':
    unittest.main()
