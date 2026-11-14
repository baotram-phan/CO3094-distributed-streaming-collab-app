"""A GUI-4 + B5.2 integration: live TLS/UDP heartbeat keeps authenticated GUI alive."""

from __future__ import annotations

import time
import unittest

from client.core.session import CollaborationClient
from tests.test_gui4_file import FileHTTPMixin
import tests.test_gui_bridge as bridge_tests


class TestGUIHeartbeatIntegration(FileHTTPMixin, unittest.TestCase):
    setUp = bridge_tests.TestGUIBridgeLive.setUp

    def test_two_gui_clients_stay_online_past_ten_second_idle_and_chat(self):
        """Real sockets, no fixture-only sessions or mocked PING/PONG."""
        alice = self._start_bridge(
            factory=CollaborationClient,
            server_host="127.0.0.1",
            tcp_port=self.server.tcp_port,
            trusted_cert=self.cert,
        )
        bob = self._start_bridge(
            factory=CollaborationClient,
            server_host="127.0.0.1",
            tcp_port=self.server.tcp_port,
            trusted_cert=self.cert,
        )
        alice_token = self._get(alice)[1]["bridge_token"]
        bob_token = self._get(bob)[1]["bridge_token"]
        self.assertEqual(
            self._post(
                alice,
                "/api/login",
                {"username": "an", "password": "an123456"},
                token=alice_token,
            )[0],
            200,
        )
        self.assertEqual(
            self._post(
                bob,
                "/api/login",
                {"username": "binh", "password": "binh123456"},
                token=bob_token,
            )[0],
            200,
        )
        self._wait_users(alice, ["an", "binh"])
        self._wait_users(bob, ["an", "binh"])
        # Without heartbeat both GUI accounts would disappear at 10 seconds.
        time.sleep(11.0)
        for bridge in (alice, bob):
            status = self._get(bridge)[1]
            self.assertEqual(status["state"], "online", status)
            self.assertEqual(status["users"], ["an", "binh"])
            client = bridge._client
            assert client and client.udp
            self.assertIsNotNone(client.udp._last_pong_timestamp_ms)
            self.assertIsNone(client.failure)
        status, response = self._post(
            alice,
            "/api/chat/direct",
            {"to": "binh", "text": "heartbeat vẫn chạy"},
            token=alice_token,
        )
        self.assertEqual(status, 202, response)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            _, events = self._get(bob, "/api/events?since=0")
            if any(
                event["type"] == "CHAT_EVENT"
                and event["body"].get("text") == "heartbeat vẫn chạy"
                for event in events["events"]
            ):
                return
            time.sleep(0.05)
        self.fail("No authenticated chat arrived after 11 seconds of idle heartbeat")


if __name__ == "__main__":
    unittest.main()
