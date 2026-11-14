"""A1.4 — state machine, timeout, duplicate login, concurrent sessions, TLS hookup.

Không mở UDP socket thật: bind_udp_verified() được gọi giả lập SAU khi B
xác minh datagram AES-GCM; test này KHÔNG chứng minh AES-GCM chạy đúng.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import unittest

from common.control_framing import encode_frame, recv_frame
from server.bootstrap import handle_bootstrap
from server.sessions import (
    DuplicateLogin,
    EndpointChanged,
    InvalidTransition,
    SessionExpired,
    SessionRegistry,
    SessionState,
    UnknownSession,
)


class FakeClock:
    def __init__(self):
        self.current = 1000.0

    def __call__(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds


class TestSessionRegistry(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.registry = SessionRegistry(
            bootstrap_timeout_s=10,
            idle_timeout_s=10,
            clock=self.clock,
            password_verifier=lambda user, password: password == "ok"
            and user in {"an", "binh"},
        )

    def new_session(self):
        return self.registry.create_bootstrap(
            tcp_ip="127.0.0.1",
            c2s_key=b"a" * 32,
            s2c_key=b"b" * 32,
        )

    def test_bootstrapped_session_has_keys_and_is_not_online(self):
        s = self.new_session()
        self.assertEqual(s.state, SessionState.BOOTSTRAPPED)
        self.assertEqual(len(self.registry), 1)
        self.assertEqual(self.registry.list_online_users(), [])
        self.assertNotIn("aaaaaaaa", repr(s))
        self.assertNotIn("bbbbbbbb", repr(s))
        self.assertIsNone(self.registry.find_online("an"))

    def test_full_lifecycle_and_cleanup(self):
        s = self.new_session()
        updated = self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53000))
        self.assertEqual(updated.state, SessionState.UDP_BOUND)
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok")
        )
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.ONLINE)
        self.assertEqual(self.registry.list_online_users(), ["an"])
        self.assertEqual(self.registry.find_online("an").conn_id, s.conn_id)
        self.assertTrue(self.registry.close(s.conn_id))
        self.assertFalse(self.registry.close(s.conn_id))
        self.assertIsNone(self.registry.get(s.conn_id))
        self.assertEqual(self.registry.list_online_users(), [])

    def test_auth_rejected_before_udp_verified(self):
        s = self.new_session()
        with self.assertRaises(InvalidTransition):
            self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok")

    def test_wrong_password_keeps_udp_bound(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53001))
        self.assertFalse(
            self.registry.authenticate_after_verified_udp(s.conn_id, "an", "bad")
        )
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.UDP_BOUND)
        self.assertEqual(self.registry.list_online_users(), [])

    def test_duplicate_username_rejected_then_relogin_after_close(self):
        s1, s2 = self.new_session(), self.new_session()
        self.registry.bind_udp_verified(s1.conn_id, ("127.0.0.1", 53001))
        self.registry.bind_udp_verified(s2.conn_id, ("127.0.0.1", 53002))
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(s1.conn_id, "an", "ok")
        )
        with self.assertRaises(DuplicateLogin):
            self.registry.authenticate_after_verified_udp(s2.conn_id, "an", "ok")
        self.assertEqual(self.registry.get(s2.conn_id).state, SessionState.UDP_BOUND)
        self.registry.close(s1.conn_id)
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(s2.conn_id, "an", "ok")
        )

    def test_bootstrap_timeout_clears_pending(self):
        s = self.new_session()
        self.clock.advance(10)
        self.assertEqual(self.registry.cleanup_expired(), [s.conn_id])
        self.assertIsNone(self.registry.get(s.conn_id))
        with self.assertRaises(UnknownSession):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53000))

    def test_expired_bootstrap_rejected_even_without_cleanup_call(self):
        s = self.new_session()
        self.clock.advance(11)
        with self.assertRaises(SessionExpired):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53000))

    def test_idle_timeout_and_activity_refresh(self):
        s = self.new_session()
        endpoint = ("127.0.0.1", 53000)
        self.registry.bind_udp_verified(s.conn_id, endpoint)
        self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok")
        self.clock.advance(9)
        self.registry.touch_verified_udp(s.conn_id, endpoint)  # datagram đã xác thực
        self.clock.advance(9)
        self.assertEqual(self.registry.list_online_users(), ["an"])
        self.clock.advance(1)
        self.assertEqual(self.registry.cleanup_expired(), [s.conn_id])
        self.assertEqual(self.registry.list_online_users(), [])

    def test_reject_udp_endpoint_change_without_rebind_flow(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53000))
        with self.assertRaises(EndpointChanged):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53001))
        self.assertEqual(
            self.registry.get(s.conn_id).udp_endpoint, ("127.0.0.1", 53000)
        )

    def test_20_concurrent_bootstraps_have_unique_ids(self):
        def create(_):
            return self.new_session().conn_id

        with ThreadPoolExecutor(max_workers=8) as executor:
            ids = list(executor.map(create, range(20)))
        self.assertEqual(len(ids), 20)
        self.assertEqual(len(set(ids)), 20)
        self.assertEqual(len(self.registry), 20)

    def test_invalid_keys_and_endpoint(self):
        with self.assertRaises(ValueError):
            self.registry.create_bootstrap(
                tcp_ip="127.0.0.1",
                c2s_key=b"short",
                s2c_key=b"b" * 32,
            )
        s = self.new_session()
        with self.assertRaises(ValueError):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 0))


class TestSessionRegistryIntegrationContract(unittest.TestCase):
    """A1.4+ contract tests. Fake clock avoids waiting 10/30 seconds."""

    def setUp(self):
        self.clock = FakeClock()
        self.registry = SessionRegistry(
            clock=self.clock,
            password_verifier=lambda user, password: user == "an" and password == "ok",
        )
        self.endpoint = ("127.0.0.1", 53000)

    def new_session(self):
        return self.registry.create_bootstrap(
            tcp_ip="127.0.0.1",
            c2s_key=b"a" * 32,
            s2c_key=b"b" * 32,
        )

    def test_defaults_are_ten_and_thirty_seconds(self):
        self.assertEqual(self.registry.bootstrap_timeout_s, 10)
        self.assertEqual(self.registry.idle_timeout_s, 10)
        self.assertEqual(self.registry.auth_timeout_s, 30)

    def test_first_register_and_repeat_register_keep_original_auth_deadline(self):
        s = self.new_session()
        first = self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        self.assertEqual(first.state, SessionState.UDP_BOUND)
        self.assertEqual(first.udp_bound_at, self.clock.current)
        self.clock.advance(7)
        repeated = self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        self.assertEqual(repeated.udp_bound_at, first.udp_bound_at)
        self.assertEqual(repeated.last_activity_at, self.clock.current)
        self.assertEqual(len(self.registry), 1)
        self.assertEqual(self.registry.list_online_users(), [])

    def test_touch_forbidden_before_register(self):
        s = self.new_session()
        with self.assertRaises(InvalidTransition):
            self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.BOOTSTRAPPED)

    def test_touch_updates_activity_only_for_bound_endpoint(self):
        s = self.new_session()
        bound = self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        self.clock.advance(9)
        updated = self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.assertEqual(updated.udp_bound_at, bound.udp_bound_at)
        self.assertEqual(updated.state, SessionState.UDP_BOUND)
        self.assertEqual(updated.last_activity_at, self.clock.current)
        self.assertEqual(updated.udp_endpoint, self.endpoint)

    def test_touch_rejects_endpoint_change_and_invalid_port(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        with self.assertRaises(EndpointChanged):
            self.registry.touch_verified_udp(s.conn_id, ("127.0.0.1", 53001))
        with self.assertRaises(ValueError):
            self.registry.touch_verified_udp(s.conn_id, ("127.0.0.1", 0))
        self.assertEqual(self.registry.get(s.conn_id).last_activity_at, s.created_at)

    def test_online_idle_timeout_is_ten_seconds(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok")
        )
        self.clock.advance(9)
        self.assertEqual(self.registry.list_online_users(), ["an"])
        self.clock.advance(1)
        self.assertEqual(self.registry.cleanup_expired(), [s.conn_id])
        self.assertEqual(self.registry.list_online_users(), [])
        events = self.registry.drain_closed_events()
        self.assertEqual(
            [(e.conn_id, e.reason, e.username) for e in events],
            [(s.conn_id, "idle_timeout", "an")],
        )

    def test_heartbeat_cannot_extend_auth_deadline(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        for _ in range(4):
            self.clock.advance(7)
            self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.clock.advance(2)  # 30s since first REGISTER, only 2s idle
        with self.assertRaises(SessionExpired):
            self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.assertEqual(self.registry.drain_closed_events()[0].reason, "auth_timeout")

    def test_duplicate_register_cannot_extend_auth_deadline(self):
        s = self.new_session()
        first = self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        for _ in range(4):
            self.clock.advance(7)
            next_snapshot = self.registry.bind_udp_verified(s.conn_id, self.endpoint)
            self.assertEqual(next_snapshot.udp_bound_at, first.udp_bound_at)
        self.clock.advance(2)
        self.assertEqual(self.registry.cleanup_expired(), [s.conn_id])
        self.assertEqual(self.registry.drain_closed_events()[0].reason, "auth_timeout")

    def test_successful_auth_removes_auth_deadline_but_not_idle_deadline(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, self.endpoint)
        self.clock.advance(8)
        self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.assertTrue(
            self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok")
        )
        for _ in range(4):
            self.clock.advance(8)
            self.registry.touch_verified_udp(s.conn_id, self.endpoint)
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.ONLINE)
        self.assertGreater(self.clock.current - s.created_at, 30)

    def test_get_implicit_expiration_emits_single_cleanup_event(self):
        s = self.new_session()
        self.clock.advance(10)
        self.assertIsNone(self.registry.get(s.conn_id))  # old A1.4 silently removed
        events = self.registry.drain_closed_events()
        self.assertEqual(
            [(e.conn_id, e.reason) for e in events], [(s.conn_id, "bootstrap_timeout")]
        )
        self.assertIsNone(self.registry.get(s.conn_id))
        self.assertEqual(self.registry.drain_closed_events(), [])

    def test_close_emits_event_once_and_is_idempotent(self):
        s = self.new_session()
        self.assertTrue(self.registry.close(s.conn_id, reason="logout"))
        self.assertFalse(self.registry.close(s.conn_id, reason="logout"))
        events = self.registry.drain_closed_events()
        self.assertEqual(
            [(e.conn_id, e.reason) for e in events], [(s.conn_id, "logout")]
        )
        self.assertEqual(self.registry.drain_closed_events(), [])


class TestUDPBindResultContract(unittest.TestCase):
    """A/B integration tests: atomic newly_bound, no deadline reset, cleanup."""

    def setUp(self):
        self.clock = FakeClock()
        self.registry = SessionRegistry(
            clock=self.clock, password_verifier=lambda u, p: u == "an" and p == "ok"
        )
        self.endpoint = ("127.0.0.1", 53000)
        self.session = self.registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=b"A" * 32, s2c_key=b"B" * 32
        )

    def test_newly_bound_true_once_then_false_on_repeat(self):
        first = self.registry.bind_udp_verified_with_status(
            self.session.conn_id, self.endpoint
        )
        self.assertTrue(first.newly_bound)
        self.assertEqual(first.session.state, SessionState.UDP_BOUND)
        self.clock.advance(3)
        repeat = self.registry.bind_udp_verified_with_status(
            self.session.conn_id, self.endpoint
        )
        self.assertFalse(repeat.newly_bound)
        self.assertEqual(repeat.session.udp_bound_at, first.session.udp_bound_at)
        self.assertEqual(len(self.registry), 1)
        self.assertEqual(self.registry.list_online_users(), [])

    def test_repeat_register_during_online_does_not_revert_state(self):
        self.registry.bind_udp_verified_with_status(self.session.conn_id, self.endpoint)
        self.registry.authenticate_after_verified_udp(self.session.conn_id, "an", "ok")
        repeat = self.registry.bind_udp_verified_with_status(
            self.session.conn_id, self.endpoint
        )
        self.assertFalse(repeat.newly_bound)
        self.assertEqual(repeat.session.state, SessionState.ONLINE)
        self.assertEqual(self.registry.list_online_users(), ["an"])

    def test_rejected_endpoint_does_not_change_session(self):
        first = self.registry.bind_udp_verified_with_status(
            self.session.conn_id, self.endpoint
        )
        with self.assertRaises(EndpointChanged):
            self.registry.bind_udp_verified_with_status(
                self.session.conn_id, ("127.0.0.1", 53001)
            )
        self.assertEqual(self.registry.get(self.session.conn_id), first.session)

    def test_concurrent_register_calls_exactly_one_newly_bound(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.registry.bind_udp_verified_with_status(
                        self.session.conn_id, self.endpoint
                    ),
                    range(20),
                )
            )
        self.assertEqual(sum(result.newly_bound for result in results), 1)
        self.assertEqual(len(self.registry), 1)

    def test_legacy_bind_returns_session_and_new_method_is_compatible(self):
        old = self.registry.bind_udp_verified(self.session.conn_id, self.endpoint)
        self.assertEqual(old.state, SessionState.UDP_BOUND)
        self.assertFalse(
            self.registry.bind_udp_verified_with_status(
                self.session.conn_id, self.endpoint
            ).newly_bound
        )

    def test_touch_does_not_reset_auth_deadline(self):
        first = self.registry.bind_udp_verified_with_status(
            self.session.conn_id, self.endpoint
        )
        for _ in range(3):
            self.clock.advance(8)
            refreshed = self.registry.touch_verified_udp(
                self.session.conn_id, self.endpoint
            )
            self.assertEqual(refreshed.udp_bound_at, first.session.udp_bound_at)
        self.clock.advance(6)
        self.assertEqual(self.registry.cleanup_expired(), [self.session.conn_id])
        self.assertEqual(self.registry.drain_closed_events()[0].reason, "auth_timeout")

    def test_cleanup_event_once_on_expired_get(self):
        self.clock.advance(10)
        self.assertIsNone(self.registry.get(self.session.conn_id))
        self.assertEqual(
            [(e.conn_id, e.reason) for e in self.registry.drain_closed_events()],
            [(self.session.conn_id, "bootstrap_timeout")],
        )
        self.assertEqual(self.registry.drain_closed_events(), [])


class BufferSocket:
    """Socket giả kiểm thử giao tiếp framing, không phải socket mạng hay TLS thật."""

    def __init__(self, request_bytes, on_send=None):
        self.buf = bytearray(request_bytes)
        self.sent = b""
        self.on_send = on_send

    def recv(self, n):
        received = bytes(self.buf[:n])
        del self.buf[:n]
        return received

    def sendall(self, data):
        if self.on_send:
            self.on_send()
        self.sent += data


class TestBootstrapIntegration(unittest.TestCase):
    def test_registered_before_ack_sent(self):
        registry = SessionRegistry(password_verifier=lambda _u, _p: False)
        request = encode_frame(
            {
                "v": 1,
                "type": "HELLO",
                "id": 4,
                "reply_to": None,
                "body": {"client_version": "1.0"},
            }
        )
        observed = []
        fake = BufferSocket(request, on_send=lambda: observed.append(len(registry)))
        session = handle_bootstrap(fake, registry=registry, peer_ip="192.0.2.10")
        self.assertEqual(observed, [1])  # Bản ghi có TRƯỚC lúc gửi HELLO_ACK
        self.assertEqual(registry.get(session.conn_id).tcp_ip, "192.0.2.10")
        reply = recv_frame(BufferSocket(fake.sent))
        self.assertEqual(reply["type"], "HELLO_ACK")
        self.assertEqual(reply["reply_to"], 4)
        self.assertEqual(int(reply["body"]["conn_id"], 16), session.conn_id)
        self.assertEqual(base64.b64decode(reply["body"]["c2s_key"]), session.c2s_key)

    def test_send_ack_failure_removes_session(self):
        registry = SessionRegistry()
        request = encode_frame(
            {
                "v": 1,
                "type": "HELLO",
                "id": 4,
                "reply_to": None,
                "body": {"client_version": "1.0"},
            }
        )

        def fail():
            raise OSError("connection broken")

        with self.assertRaises(OSError):
            handle_bootstrap(BufferSocket(request, on_send=fail), registry=registry)
        self.assertEqual(len(registry), 0)


if __name__ == "__main__":
    unittest.main()
