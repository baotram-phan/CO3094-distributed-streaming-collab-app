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
    DuplicateLogin, EndpointChanged, InvalidTransition, SessionExpired,
    SessionRegistry, SessionState, UnknownSession,
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
            bootstrap_timeout_s=10, idle_timeout_s=15, clock=self.clock,
            password_verifier=lambda user, password: password == "ok" and user in {"an", "binh"},
        )

    def new_session(self):
        return self.registry.create_bootstrap(
            tcp_ip="127.0.0.1", c2s_key=b"a" * 32, s2c_key=b"b" * 32,
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
        self.assertTrue(self.registry.authenticate_after_verified_udp(s.conn_id, "an", "ok"))
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
        self.assertFalse(self.registry.authenticate_after_verified_udp(s.conn_id, "an", "bad"))
        self.assertEqual(self.registry.get(s.conn_id).state, SessionState.UDP_BOUND)
        self.assertEqual(self.registry.list_online_users(), [])

    def test_duplicate_username_rejected_then_relogin_after_close(self):
        s1, s2 = self.new_session(), self.new_session()
        self.registry.bind_udp_verified(s1.conn_id, ("127.0.0.1", 53001))
        self.registry.bind_udp_verified(s2.conn_id, ("127.0.0.1", 53002))
        self.assertTrue(self.registry.authenticate_after_verified_udp(s1.conn_id, "an", "ok"))
        with self.assertRaises(DuplicateLogin):
            self.registry.authenticate_after_verified_udp(s2.conn_id, "an", "ok")
        self.assertEqual(self.registry.get(s2.conn_id).state, SessionState.UDP_BOUND)
        self.registry.close(s1.conn_id)
        self.assertTrue(self.registry.authenticate_after_verified_udp(s2.conn_id, "an", "ok"))

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
        self.clock.advance(14)
        self.registry.bind_udp_verified(s.conn_id, endpoint)  # datagram đã xác thực
        self.clock.advance(14)
        self.assertEqual(self.registry.list_online_users(), ["an"])
        self.clock.advance(1)
        self.assertEqual(self.registry.cleanup_expired(), [s.conn_id])
        self.assertEqual(self.registry.list_online_users(), [])

    def test_reject_udp_endpoint_change_without_rebind_flow(self):
        s = self.new_session()
        self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53000))
        with self.assertRaises(EndpointChanged):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 53001))
        self.assertEqual(self.registry.get(s.conn_id).udp_endpoint, ("127.0.0.1", 53000))

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
                tcp_ip="127.0.0.1", c2s_key=b"short", s2c_key=b"b" * 32,
            )
        s = self.new_session()
        with self.assertRaises(ValueError):
            self.registry.bind_udp_verified(s.conn_id, ("127.0.0.1", 0))


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
        request = encode_frame({
            "v": 1, "type": "HELLO", "id": 4, "reply_to": None,
            "body": {"client_version": "1.0"},
        })
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
        request = encode_frame({
            "v": 1, "type": "HELLO", "id": 4, "reply_to": None,
            "body": {"client_version": "1.0"},
        })

        def fail():
            raise OSError("connection broken")

        with self.assertRaises(OSError):
            handle_bootstrap(BufferSocket(request, on_send=fail), registry=registry)
        self.assertEqual(len(registry), 0)


if __name__ == "__main__":
    unittest.main()
