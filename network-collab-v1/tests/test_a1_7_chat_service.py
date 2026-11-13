"""A1.7/A chat application tests: no UDP/TLS/reliability is mocked as working."""
from __future__ import annotations

import struct
import threading
import unittest

from client.core.a17_chat_protocol import build_chat_broadcast, build_chat_direct
from common.control_stream_framing import decode_control_json, encode_control_message
from common.models import ApplicationValidationError
from server.a16_auth_service import A16AuthService
from server.a17_chat_service import A17ChatService
from server.router import ChatRouter, ChatRoutingError
from server.sessions import SessionRegistry, SessionState


class TestA17ChatService(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(
            password_verifier=lambda u, p: u in ('an', 'binh', 'chi') and p == 'correct',
        )
        self.chat_out = []
        self.control_out = []
        self.auth = A16AuthService(self.registry, lambda cid, data: self.control_out.append((cid, data)))
        self.chat = A17ChatService(
            self.registry,
            lambda cid, data: self.chat_out.append((cid, data)),
            self.auth.send_application_error,
            clock_ms=lambda: 1730000123456,
        )
        self.an = self._session('an', 59001)
        self.binh = self._session('binh', 59002)
        self.chi = self._session('chi', 59003)
        self.offsets = {}

    def _session(self, username, port, authenticate=True):
        s = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                          c2s_key=b'X'*32, s2c_key=b'Y'*32)
        self.registry.bind_udp_verified(s.conn_id, ('127.0.0.1', port))
        if authenticate:
            self.assertTrue(self.registry.authenticate_after_verified_udp(s.conn_id, username, 'correct'))
        return s.conn_id

    def _deliver(self, conn_id, frame, *, offset=None, fin=False):
        if offset is None:
            offset = self.offsets.get(conn_id, 0)
        result = self.chat.on_stream_data(conn_id, 1, offset, frame, fin)
        if result and offset == self.offsets.get(conn_id, 0):
            self.offsets[conn_id] = offset + len(frame)
        return result

    @staticmethod
    def _decode(sent):
        out = []
        for conn_id, packet in sent:
            n = struct.unpack('!I', packet[:4])[0]
            assert n == len(packet) - 4
            out.append((conn_id, decode_control_json(packet[4:])))
        return out

    def _chat_msgs(self, conn_id=None):
        return [(cid, msg) for cid, msg in self._decode(self.chat_out)
                if conn_id is None or cid == conn_id]

    def _control_msgs(self, conn_id=None):
        return [(cid, msg) for cid, msg in self._decode(self.control_out)
                if conn_id is None or cid == conn_id]

    def test_direct_one_recipient_only_and_chat_accepted(self):
        self.assertTrue(self._deliver(self.an, build_chat_direct('binh', 'Chào Bình', message_id=1)))
        self.assertEqual([x[0] for x in self.chat_out], [self.binh, self.an])
        event = self._chat_msgs(self.binh)[0][1]
        accepted = self._chat_msgs(self.an)[0][1]
        self.assertEqual(event['type'], 'CHAT_EVENT')
        self.assertEqual(event['body'], {
            'server_msg_id': 1, 'from': 'an', 'to': 'binh',
            'scope': 'direct', 'text': 'Chào Bình', 'ts': 1730000123456,
        })
        self.assertEqual(accepted['type'], 'CHAT_ACCEPTED')
        self.assertEqual(accepted['reply_to'], 1)
        self.assertEqual(accepted['body']['server_msg_id'], 1)
        self.assertEqual(self._chat_msgs(self.chi), [])

    def test_broadcast_each_online_once_including_sender(self):
        self._deliver(self.binh, build_chat_broadcast('Mọi người', message_id=1))
        counts = {cid: len([m for target, m in self._chat_msgs(cid) if m['type'] == 'CHAT_EVENT'])
                  for cid in (self.an, self.binh, self.chi)}
        self.assertEqual(counts, {self.an: 1, self.binh: 1, self.chi: 1})
        self.assertEqual([m['type'] for _, m in self._chat_msgs(self.binh)],
                         ['CHAT_EVENT', 'CHAT_ACCEPTED'])
        self.assertEqual(self._chat_msgs(self.an)[0][1]['body']['to'], None)

    def test_offline_recipient_error_not_accepted(self):
        self.registry.close(self.chi, reason='logout')
        self._deliver(self.an, build_chat_direct('chi', 'Hello', message_id=1))
        self.assertEqual(self.chat_out, [])
        msg = self._control_msgs(self.an)[0][1]
        self.assertEqual((msg['type'], msg['body']['code'], msg['reply_to']),
                         ('ERROR', 'USER_OFFLINE', 1))

    def test_invalid_unknown_recipient_error(self):
        self._deliver(self.an, build_chat_direct('unknown', 'Hello', message_id=1))
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'USER_OFFLINE')

    def test_reject_spoofed_from_field_even_when_session_authenticated(self):
        wire = encode_control_message({
            'v': 1, 'type': 'CHAT_DIRECT', 'id': 1, 'reply_to': None,
            'body': {'to': 'binh', 'from': 'chi', 'text': 'Fake'},
        })
        self._deliver(self.an, wire)
        self.assertEqual(self.chat_out, [])
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'BAD_FRAME')

    def test_1000_utf8_bytes_accepted(self):
        text = 'á' * 500  # exactly 1000 UTF-8 bytes
        self._deliver(self.an, build_chat_direct('binh', text, message_id=1))
        self.assertEqual(self._chat_msgs(self.binh)[0][1]['body']['text'], text)

    def test_1001_bytes_rejected_on_both_client_and_server(self):
        text = 'á' * 500 + 'b'
        with self.assertRaises(ApplicationValidationError):
            build_chat_direct('binh', text, message_id=1)
        self._deliver(self.an, encode_control_message({
            'v': 1, 'type': 'CHAT_DIRECT', 'id': 1, 'reply_to': None,
            'body': {'to': 'binh', 'text': text},
        }))
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'CHAT_TOO_LARGE')
        self.assertEqual(self.chat_out, [])

    def test_invalid_client_values_and_message_id(self):
        for to in ('bad name', 'á', 'A'*33, '', None):
            with self.subTest(to=to), self.assertRaises(ValueError):
                build_chat_direct(to, 'hi', message_id=1)
        for text in ('', None, '\ud800'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                build_chat_broadcast(text, message_id=1)
        for mid in (0, -1, True, 1.1):
            with self.subTest(mid=mid), self.assertRaises(ValueError):
                build_chat_broadcast('hi', message_id=mid)

    def test_fragmented_header_and_body(self):
        frame = build_chat_direct('binh', 'fragmented', message_id=1)
        self._deliver(self.an, frame[:2])
        self._deliver(self.an, frame[2:8])
        self.assertEqual(self.chat_out, [])
        self._deliver(self.an, frame[8:])
        self.assertEqual(len(self.chat_out), 2)

    def test_multiple_requests_in_one_stream_chunk(self):
        joined = build_chat_direct('binh', 'one', message_id=1) + build_chat_direct('binh', 'two', message_id=2)
        self._deliver(self.an, joined)
        self.assertEqual([m['body']['text'] for _, m in self._chat_msgs(self.binh)], ['one', 'two'])
        self.assertEqual([m['body']['server_msg_id'] for _, m in self._chat_msgs(self.binh)], [1, 2])
        self.assertEqual([m['id'] for _, m in self._chat_msgs(self.binh)], [1, 2])
        self.assertEqual([m['id'] for _, m in self._chat_msgs(self.an)], [1, 2])

    def test_duplicate_stream_bytes_do_not_duplicate_delivery(self):
        frame = build_chat_direct('binh', 'only once', message_id=1)
        self._deliver(self.an, frame)
        self.assertTrue(self._deliver(self.an, frame, offset=0))
        self.assertEqual(len(self.chat_out), 2)

    def test_repeat_message_id_at_next_offset_returns_error(self):
        frame = build_chat_direct('binh', 'hi', message_id=1)
        self._deliver(self.an, frame)
        self._deliver(self.an, frame)
        self.assertEqual(len(self._chat_msgs(self.binh)), 1)
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'BAD_FRAME')

    def test_gap_rejected_no_side_effect(self):
        with self.assertRaisesRegex(ValueError, 'contiguous'):
            self._deliver(self.an, build_chat_direct('binh', 'hi', message_id=1), offset=3)
        self.assertEqual(self.chat_out, [])

    def test_unauthenticated_udp_bound_cannot_chat(self):
        other = self._session('unused', 59004, authenticate=False)
        self.assertFalse(self._deliver(other, build_chat_broadcast('hi', message_id=1)))
        self.assertEqual(self.registry.get(other).state, SessionState.UDP_BOUND)
        self.assertEqual(self._control_msgs(other)[0][1]['body']['code'], 'NOT_AUTHENTICATED')
        self.assertEqual(self.chat_out, [])

    def test_unsupported_message_type_rejected(self):
        wire = encode_control_message({
            'v': 1, 'type': 'FILE_OFFER', 'id': 1, 'reply_to': None, 'body': {},
        })
        self._deliver(self.an, wire)
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'BAD_FRAME')

    def test_nonnull_reply_to_rejected(self):
        wire = encode_control_message({
            'v': 1, 'type': 'CHAT_BROADCAST', 'id': 1, 'reply_to': 3, 'body': {'text':'hello'},
        })
        self._deliver(self.an, wire)
        self.assertEqual(self.chat_out, [])
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'BAD_FRAME')

    def test_bad_frame_length_closes_session_and_blocks_resurrection(self):
        self.assertFalse(self._deliver(self.an, struct.pack('!I', 1000000)))
        self.assertIsNone(self.registry.get(self.an))
        self.assertIn(self.an, self.chat._closed)
        self.assertEqual(self.registry.drain_closed_events()[0].reason, 'bad_chat_frame')
        self.assertFalse(self._deliver(self.an, build_chat_broadcast('hi', message_id=1)))

    def test_partial_frame_fin_closes_session(self):
        frame = build_chat_direct('binh', 'Hi', message_id=1)
        self.assertFalse(self._deliver(self.an, frame[:6], fin=True))
        self.assertIsNone(self.registry.get(self.an))

    def test_cleanup_after_logout_removes_chat_state_once(self):
        self._deliver(self.an, build_chat_broadcast('hi', message_id=1))
        self.registry.close(self.an, reason='logout')
        event = self.registry.drain_closed_events()[0]
        self.chat.on_session_closed(event)
        self.chat.on_session_closed(event)
        self.assertFalse(self._deliver(self.an, build_chat_broadcast('hi2', message_id=2)))
        self.assertNotIn(self.an, self.chat._states)

    def test_b_sender_enqueue_failure_reports_error_not_accepted(self):
        def failing_sender(cid, data):
            if cid == self.binh:
                raise RuntimeError('bounded queue full')
            self.chat_out.append((cid, data))
        self.chat._send_chat = failing_sender
        self._deliver(self.an, build_chat_direct('binh', 'hi', message_id=1))
        self.assertEqual(self._control_msgs(self.an)[0][1]['body']['code'], 'INTERNAL')
        self.assertEqual(self._chat_msgs(self.an), [])

    def test_control_error_uses_existing_outbound_control_sequence(self):
        self._deliver(self.an, build_chat_direct('nobody', 'hi', message_id=1))
        self._deliver(self.an, build_chat_direct('nobody', 'hi', message_id=2))
        self.assertEqual([m['id'] for _, m in self._control_msgs(self.an)], [1, 2])
        self.assertEqual([m['reply_to'] for _, m in self._control_msgs(self.an)], [1, 2])

    def test_concurrent_senders_preserve_recipient_enqueue_sequence(self):
        """Two sources concurrently queue to a shared destination."""
        go = threading.Barrier(3)
        exceptions = []

        def sender(conn_id, text):
            try:
                go.wait(timeout=2)
                self._deliver(conn_id, build_chat_direct('binh', text, message_id=1))
            except Exception as exc:
                exceptions.append(exc)

        threads = [threading.Thread(target=sender, args=(self.an, 'A')),
                   threading.Thread(target=sender, args=(self.chi, 'C'))]
        for thread in threads:
            thread.start()
        go.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(exceptions, [])
        self.assertEqual(len(self._chat_msgs(self.binh)), 2)
        self.assertEqual([m['id'] for _, m in self._chat_msgs(self.binh)], [1, 2])
        self.assertEqual({m['body']['from'] for _, m in self._chat_msgs(self.binh)}, {'an', 'chi'})

    def test_router_standalone_does_not_send(self):
        router = ChatRouter(self.registry)
        plan = router.prepare(self.an, 'CHAT_DIRECT', {'to': 'binh', 'text': 'hi'})
        self.assertEqual(plan.sender, 'an')
        self.assertEqual(plan.recipients, ((self.binh, 'binh'),))
        with self.assertRaises(ChatRoutingError) as cm:
            router.prepare(self.an, 'CHAT_DIRECT', {'to': 'not-online', 'text': 'hi'})
        self.assertEqual(cm.exception.code, 'USER_OFFLINE')
        self.assertEqual(self.chat_out, [])


if __name__ == '__main__':
    unittest.main()
