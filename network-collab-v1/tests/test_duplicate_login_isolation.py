"""A rejected GUI login must never stop the shared UDP server.

Real TLS/UDP/HTTP integration; only the Windows recvfrom error is injected.
"""

import errno
import hashlib
import json
import threading
import time
import unittest
import sys
from unittest.mock import Mock, patch

from client.core.session import CollaborationClient
from server.sessions import SessionRegistry
from server.udp_service import UDPTransportService
from tests.test_gui_bridge import BridgeTestMixin
import tests.test_gui_bridge as bridge_tests


def windows_reset():
    error = ConnectionResetError(10054, "ICMP Port Unreachable")
    error.winerror = 10054
    return error


class TestUDPReceiveIsolation(unittest.TestCase):
    def setUp(self):
        self.service = UDPTransportService(
            SessionRegistry(), port=0, logger=None, auto_drive=True
        )
        self.addCleanup(self.service.stop)

    def test_windows_reset_keeps_scheduler_and_next_receive_alive(self):
        fake = Mock()
        fake.recvfrom.side_effect = [
            windows_reset(),
            (b"next-packet", ("127.0.0.1", 12345)),
        ]
        with (
            patch.object(self.service, "sock", fake),
            patch.object(self.service, "pump_reliable_once") as pump,
            patch.object(self.service, "handle_datagram") as handle,
        ):
            self.service.serve_once()
            self.service.serve_once()
            self.assertEqual(pump.call_count, 2)
            handle.assert_called_once_with(b"next-packet", ("127.0.0.1", 12345))
        self.assertFalse(self.service._stopping.is_set())

    def test_other_socket_errors_are_not_swallowed(self):
        fake = Mock()
        fake.recvfrom.side_effect = OSError(errno.EBADF, "Bad descriptor")
        with patch.object(self.service, "sock", fake):
            with self.assertRaises(OSError):
                self.service.serve_once()

    @unittest.skipIf(
        sys.platform == "win32",
        "Not portable to Windows: errno.ECONNRESET is 10054, the UDP error intentionally handled by the server.",
    )
    def test_unrelated_connection_reset_is_not_swallowed(self):
        fake = Mock()
        fake.recvfrom.side_effect = ConnectionResetError(
            errno.ECONNRESET, "Other reset"
        )
        with patch.object(self.service, "sock", fake):
            with self.assertRaises(ConnectionResetError):
                self.service.serve_once()

    def test_shutdown_does_not_pump_or_raise(self):
        self.service.stop()
        with patch.object(self.service, "pump_reliable_once") as pump:
            self.service.serve_once()
            pump.assert_not_called()


class ResetOnceSocket:
    def __init__(self, sock):
        self.sock = sock
        self.arm = threading.Event()
        self.delivered = threading.Event()

    def recvfrom(self, size):
        if self.arm.is_set():
            self.arm.clear()
            self.delivered.set()
            raise windows_reset()
        return self.sock.recvfrom(size)

    def __getattr__(self, name):
        return getattr(self.sock, name)


class TestDuplicateLoginIsolation(BridgeTestMixin, unittest.TestCase):
    def setUp(self):
        bridge_tests.TestGUIBridgeLive.setUp(self)
        import server.auth

        path = server.auth.USERS_FILE
        users = json.loads(path.read_text(encoding="utf8"))
        salt = b"isolated-test-chi"
        users["chi"] = {
            "salt": salt.hex(),
            "hash": hashlib.pbkdf2_hmac("sha256", b"chi123456", salt, 200_000).hex(),
            "iterations": 200_000,
        }
        path.write_text(json.dumps(users), encoding="utf8")

    def test_duplicate_and_bad_password_keep_an_binh_chi_online_after_reset(self):
        bridges = []
        tokens = []
        for _ in range(4):
            bridge = self._start_bridge(
                factory=CollaborationClient,
                server_host="127.0.0.1",
                tcp_port=self.server.tcp_port,
                trusted_cert=self.cert,
            )
            bridges.append(bridge)
            tokens.append(self._get(bridge)[1]["bridge_token"])
        names = ["an", "binh", "chi"]
        for bridge, token, name in zip(bridges, tokens, names):
            code, body = self._post(
                bridge,
                "/api/login",
                {"username": name, "password": name + "123456"},
                token=token,
            )
            self.assertEqual(code, 200, body)
        for bridge in bridges[:3]:
            self._wait_users(bridge, names)
        original_ids = [bridge._client.conn_id for bridge in bridges[:3]]
        proxy = ResetOnceSocket(self.server.udp_service.sock)
        # The receive thread may be in recvfrom already; the next iteration
        # uses this transparent wrapper. Real network traffic is unchanged.
        self.server.udp_service.sock = proxy
        for password in ("an123456", "an123456", "wrong-password"):
            code, body = self._post(
                bridges[3],
                "/api/login",
                {"username": "an", "password": password},
                token=tokens[3],
            )
            self.assertEqual(code, 401, body)
            self.assertEqual(self._get(bridges[3])[1]["state"], "disconnected")
            proxy.delivered.clear()
            proxy.arm.set()
            self.assertTrue(proxy.delivered.wait(2), "UDP receive loop stopped")
        # Beyond default idle timeout: a dead UDP thread cannot pass by merely
        # retaining stale GUI online state or an unchanged Registry snapshot.
        time.sleep(11)
        self.assertTrue(self.server_thread.is_alive())
        self.assertEqual(self.server.registry.list_online_users(), names)
        for bridge, cid in zip(bridges[:3], original_ids):
            self.assertEqual(self._get(bridge)[1]["state"], "online")
            self.assertEqual(bridge._client.conn_id, cid)
            self.assertIsNone(bridge._client.failure)
            self.assertIsNotNone(bridge._client.udp._last_pong_timestamp_ms)
        code, body = self._post(
            bridges[1],
            "/api/chat/broadcast",
            {"text": "still-alive-after-duplicate"},
            token=tokens[1],
        )
        self.assertEqual(code, 202, body)
        for bridge in bridges[:3]:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                events = self._get(bridge, "/api/events?since=0")[1]["events"]
                matches = [
                    event
                    for event in events
                    if event["type"] == "CHAT_EVENT"
                    and event["body"].get("text") == "still-alive-after-duplicate"
                ]
                if matches:
                    self.assertEqual(len(matches), 1)
                    break
                time.sleep(0.05)
            else:
                self.fail("An/Binh/Chi did not receive chat after rejected login")


if __name__ == "__main__":
    unittest.main()
