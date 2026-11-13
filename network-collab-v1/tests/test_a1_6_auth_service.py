"""A1.6 AUTH core tests. Simulated B *reliable encrypted stream-0 delivery*.

These tests DO NOT establish that B's actual DATA/ACK/retransmission works.
"""
from __future__ import annotations

import struct
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile
from server.auth import verify_password

from client.core.a16_auth_protocol import build_auth_request
from common.control_framing import ProtocolError
from common.control_stream_framing import (
    MAX_CONTROL_JSON, encode_control_message, decode_control_json,
)
from server.a16_auth_service import A16AuthService
from server.sessions import SessionRegistry, SessionState


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def tick(self, delta):
        self.now += delta


class TestA16AuthService(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.registry = SessionRegistry(
            clock=self.clock,
            password_verifier=lambda u, p: u in ('an', 'binh') and p == 'correct',
        )
        self.sent = []
        self.auth = A16AuthService(self.registry,
                                   lambda conn_id, data: self.sent.append((conn_id, data)))
        self.session = self.new_session()
        self.conn = self.session.conn_id

    def new_session(self):
        s = self.registry.create_bootstrap(tcp_ip='127.0.0.1',
                                           c2s_key=b'a' * 32, s2c_key=b'b' * 32)
        self.registry.bind_udp_verified(s.conn_id, ('127.0.0.1', 51000 + len(self.registry)))
        return s

    def messages(self, conn_id=None):
        decoded = []
        for recipient, wire in self.sent:
            if conn_id is not None and recipient != conn_id:
                continue
            length = struct.unpack('!I', wire[:4])[0]
            self.assertEqual(length, len(wire) - 4)
            decoded.append((recipient, decode_control_json(wire[4:])))
        return decoded

    def auth_request(self, username='an', password='correct', msg_id=1):
        return build_auth_request(username, password, message_id=msg_id)

    def deliver(self, data, *, conn=None, offset=0, fin=False):
        return self.auth.on_stream_data(conn or self.conn, 0, offset, data, fin)

    def test_auth_success_online_user_list_and_reply_to(self):
        self.assertTrue(self.deliver(self.auth_request()))
        self.assertEqual(self.registry.get(self.conn).state, SessionState.ONLINE)
        messages = [m for _, m in self.messages(self.conn)]
        self.assertEqual([m['type'] for m in messages], ['AUTH_OK', 'USER_LIST'])
        self.assertEqual(messages[0]['reply_to'], 1)
        self.assertEqual(messages[0]['body'], {'username': 'an'})
        self.assertEqual(messages[1]['body'], {'users': ['an']})
        self.assertEqual([m['id'] for m in messages], [1, 2])

    def test_wrong_password_keeps_udp_bound(self):
        self.deliver(self.auth_request(password='wrong'))
        self.assertEqual(self.registry.get(self.conn).state, SessionState.UDP_BOUND)
        self.assertEqual(self.messages()[0][1]['body']['code'], 'AUTH_FAILED')
        self.assertEqual(self.registry.list_online_users(), [])

    def test_third_failed_attempt_closes_and_emits_event(self):
        offset = 0
        for msg_id in (1, 2, 3):
            frame = self.auth_request(password='wrong', msg_id=msg_id)
            self.deliver(frame, offset=offset)
            offset += len(frame)
        self.assertIsNone(self.registry.get(self.conn))
        self.assertEqual(len([m for _, m in self.messages() if m['type'] == 'AUTH_FAIL']), 3)
        events = self.registry.drain_closed_events()
        self.assertEqual([(e.conn_id, e.reason) for e in events],
                         [(self.conn, 'auth_failure_limit')])

    def test_duplicate_user_login_rejected_without_removing_first(self):
        self.deliver(self.auth_request())
        other = self.new_session().conn_id
        frame = self.auth_request()
        self.assertTrue(self.deliver(frame, conn=other))
        self.assertEqual(self.registry.get(other).state, SessionState.UDP_BOUND)
        self.assertEqual(self.messages(other)[0][1]['body']['code'], 'ALREADY_LOGGED_IN')
        self.assertEqual(self.registry.find_online('an').conn_id, self.conn)

    def test_fragmented_and_coalesced_control_frames(self):
        wire = self.auth_request()
        self.deliver(wire[:2], offset=0)
        self.deliver(wire[2:7], offset=2)
        self.assertFalse(self.sent)
        self.deliver(wire[7:], offset=7)
        self.assertEqual(self.messages()[0][1]['type'], 'AUTH_OK')

    def test_fragmented_duplicate_bytes_do_not_repeat_auth(self):
        wire = self.auth_request()
        self.deliver(wire)
        self.deliver(wire, offset=0)
        self.assertEqual([m['type'] for _, m in self.messages()], ['AUTH_OK', 'USER_LIST'])

    def test_gap_rejected_before_state_changes(self):
        with self.assertRaises(ValueError):
            self.deliver(self.auth_request(), offset=3)
        self.assertEqual(self.registry.get(self.conn).state, SessionState.UDP_BOUND)

    def test_unauthenticated_operation_rejected(self):
        frame = encode_control_message({
            'v': 1, 'type': 'USER_LIST', 'id': 1, 'reply_to': None, 'body': {},
        })
        self.deliver(frame)
        self.assertEqual(self.messages()[0][1]['body']['code'], 'NOT_AUTHENTICATED')
        self.assertEqual(self.registry.get(self.conn).state, SessionState.UDP_BOUND)

    def test_second_auth_after_online_is_rejected(self):
        one = self.auth_request()
        self.deliver(one)
        two = self.auth_request(msg_id=2)
        self.deliver(two, offset=len(one))
        self.assertEqual(self.messages()[-1][1]['type'], 'ERROR')
        self.assertEqual(self.registry.list_online_users(), ['an'])

    def test_malformed_length_closes_no_large_allocation(self):
        self.assertFalse(self.deliver(struct.pack('!I', MAX_CONTROL_JSON + 1)))
        self.assertIsNone(self.registry.get(self.conn))
        self.assertEqual(self.registry.drain_closed_events()[0].reason, 'bad_control_frame')

    def test_bad_json_closes(self):
        self.assertFalse(self.deliver(struct.pack('!I', 4) + b'nope'))
        self.assertIsNone(self.registry.get(self.conn))

    def test_partial_frame_fin_closes(self):
        self.assertFalse(self.deliver(self.auth_request()[:6], fin=True))
        self.assertIsNone(self.registry.get(self.conn))

    def test_old_message_id_not_reexecuted(self):
        bad = self.auth_request(password='wrong', msg_id=1)
        self.deliver(bad)
        repeated_id = self.auth_request(password='wrong', msg_id=1)
        self.deliver(repeated_id, offset=len(bad))
        self.assertEqual([m['type'] for _, m in self.messages()], ['AUTH_FAIL', 'ERROR'])
        self.assertEqual(self.registry.get(self.conn).state, SessionState.UDP_BOUND)

    def test_auth_timeout_is_not_reset_by_handler(self):
        self.clock.tick(30)
        self.assertFalse(self.deliver(self.auth_request()))
        self.assertIsNone(self.registry.get(self.conn))
        self.assertEqual(self.registry.drain_closed_events()[0].reason, 'auth_timeout')

    def test_presence_online_and_offline_via_coordinator_callback(self):
        self.deliver(self.auth_request())
        other = self.new_session().conn_id
        self.deliver(self.auth_request('binh', 'correct'), conn=other)
        a_msgs = [m for _, m in self.messages(self.conn)]
        self.assertEqual(a_msgs[-1]['type'], 'PRESENCE')
        self.assertEqual(a_msgs[-1]['body'], {'username': 'binh', 'status': 'online'})
        self.registry.close(other, reason='logout')
        event = self.registry.drain_closed_events()[0]
        self.auth.on_session_closed(event)
        a_msgs = [m for _, m in self.messages(self.conn)]
        self.assertEqual(a_msgs[-1]['body'], {'username': 'binh', 'status': 'offline'})

    def test_message_length_is_in_utf8_bytes(self):
        message = { 'v': 1, 'type': 'AUTH', 'id': 1, 'reply_to': None,
                    'body': {'username': 'ăn', 'password': 'ok'}}
        wire = encode_control_message(message)
        self.assertEqual(struct.unpack('!I', wire[:4])[0], len(wire) - 4)
        self.assertEqual(decode_control_json(wire[4:]), message)

    def test_reject_oversized_json(self):
        message = { 'v': 1, 'type': 'AUTH', 'id': 1, 'reply_to': None,
                    'body': {'password': 'a' * 9000}}
        with self.assertRaises(ProtocolError):
            encode_control_message(message)

    def test_client_auth_serialization_has_no_network_calls(self):
        frame = build_auth_request('an', 'correct')
        self.assertEqual(decode_control_json(frame[4:])['type'], 'AUTH')

    def test_coordinator_tombstone_blocks_in_flight_recreation(self):
        self.registry.close(self.conn)
        event = self.registry.drain_closed_events()[0]
        self.auth.on_session_closed(event)
        self.assertFalse(self.deliver(self.auth_request()))
        self.assertNotIn(self.conn, self.auth._states)
        self.assertIn(self.conn, self.auth._closed_conn_ids)

    def test_invalid_auth_body_is_bad_frame_not_password_failure(self):
        malformed_body = encode_control_message({
            'v': 1, 'type': 'AUTH', 'id': 1, 'reply_to': None,
            'body': {'username': 'an', 'password': 123},
        })
        self.deliver(malformed_body)
        self.assertEqual(self.messages()[0][1]['type'], 'ERROR')
        self.assertEqual(self.messages()[0][1]['body']['code'], 'BAD_FRAME')
        self.assertEqual(self.registry.get(self.conn).state, SessionState.UDP_BOUND)

    def test_password_not_exposed_in_error_reply(self):
        self.deliver(self.auth_request(password='sensitive_wrong'))
        self.assertNotIn(b'sensitive_wrong', self.sent[0][1])
        self.assertNotIn(b'sensitive_wrong', repr(self.messages()).encode())




class TestPasswordFileFailsClosed(unittest.TestCase):
    def test_missing_account_file_rejects_without_exception(self):
        with patch('server.auth.USERS_FILE', Path('/not-a-real-dir-in-tests/users.json')):
            self.assertFalse(verify_password('an', 'pass'))

    def test_invalid_account_file_rejects_without_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'users.json'
            path.write_text('{ invalid json', encoding='utf8')
            with patch('server.auth.USERS_FILE', path):
                self.assertFalse(verify_password('an', 'pass'))

if __name__ == '__main__':
    unittest.main()
