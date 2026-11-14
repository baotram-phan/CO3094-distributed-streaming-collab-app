"""GUI-5: fail-closed browser bridge and manual login recovery.

These tests never simulate successful delivery after UDP failure, and never
silently requeue an application command. They complement the real B5.2 PING/PONG
and TCP/TLS+Reliable UDP live tests.
"""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from tests.test_gui_bridge import BridgeTestMixin, FakeClient


class TestGUI5Resilience(BridgeTestMixin, unittest.TestCase):
    def setUp(self):
        FakeClient.instances = []
        self.bridge = self._start_bridge()
        self.token = self._get(self.bridge)[1]["bridge_token"]

    def _login(self, username="an"):
        code, payload = self._post(
            self.bridge,
            "/api/login",
            {"username": username, "password": "correct"},
            token=self.token,
        )
        self.assertEqual(code, 200, payload)
        self._wait_users(
            self.bridge, [username, "binh"] if username != "binh" else ["binh"]
        )
        return FakeClient.instances[-1]

    def _wait_for_error(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = self._get(self.bridge)[1]
            if status["state"] == "error":
                return status
            time.sleep(0.025)
        self.fail(f"Failure never reached GUI, final status: {status}")

    def test_transport_failure_is_explicit_and_no_auto_retry(self):
        client = self._login()
        client.failure = TimeoutError("simulated heartbeat timeout")
        status = self._wait_for_error()
        self.assertTrue(client.closed)
        self.assertIsNone(status["username"])
        self.assertEqual(status["users"], [])
        self.assertIn("đăng nhập lại", status["error"])
        self.assertEqual(len(FakeClient.instances), 1)
        time.sleep(0.22)
        self.assertEqual(
            len(FakeClient.instances), 1, "GUI must never reconnect implicitly"
        )
        events = self._get(self.bridge, "/api/events?since=0")[1]["events"]
        self.assertEqual([e["type"] for e in events], ["BRIDGE_ERROR"])
        self.assertEqual(events[0]["body"]["code"], "TRANSPORT_ERROR")
        self.assertEqual(events[0]["body"]["retry"], "LOGIN_AGAIN")
        self.assertEqual(
            self._post(
                self.bridge,
                "/api/chat/broadcast",
                {"text": "not sent"},
                token=self.token,
            )[0],
            409,
        )

    def test_login_after_failure_is_fresh_session_without_old_events(self):
        client = self._login("an")
        client.failure = OSError("network dead")
        self._wait_for_error()
        old = self._get(self.bridge)[1]["cursor"]
        next_client = self._login("chi")
        self.assertIsNot(client, next_client)
        status = self._get(self.bridge)[1]
        self.assertEqual(status["state"], "online")
        self.assertEqual(status["username"], "chi")
        self.assertEqual(status["error"], None)
        self.assertEqual(status["users"], ["binh", "chi"])
        events = self._get(self.bridge, f"/api/events?since={old}")[1]["events"]
        self.assertFalse(any(e["type"] == "BRIDGE_ERROR" for e in events))

    def test_cleanup_files_and_incomplete_transfer_when_udp_fails(self):
        client = self._login()
        with self.bridge._lock:
            stage = Path(self.bridge._file_area.name)
            path = stage / "incomplete.part"
            path.write_bytes(b"partial data")
            self.bridge._file_transfers["a" * 32] = {
                "transfer_id": "a" * 32,
                "role": "receiver",
                "filename": "incomplete.bin",
                "size": 100,
                "status": "transferring",
                "bytes_received": 12,
                "_path": path,
            }
        client.failure = ConnectionError("broken udp stream")
        self._wait_for_error()
        self.assertFalse(path.exists())
        status = self._get(self.bridge)[1]
        self.assertEqual(status["transfers"], [])
        download = self._get(
            self.bridge,
            f"/api/file/download/{'a' * 32}",
            headers={"X-Bridge-Token": self.token},
        )
        self.assertEqual(download[0], 404)

    def test_dashboard_assets_include_manual_recovery_ui(self):
        html = self._get(self.bridge, "/")[1].decode("utf-8")
        js = self._get(self.bridge, "/app.js")[1].decode("utf-8")
        css = self._get(self.bridge, "/style.css")[1].decode("utf-8")
        self.assertIn('id="resilienceBanner"', html)
        self.assertIn('id="retryBridgeButton"', html)
        self.assertIn('role="alert"', html)
        self.assertIn("bridgeReachable = false", js)
        self.assertIn("Không liên hệ được HTTP Bridge", js)
        self.assertIn("retryBridgeButton", js)
        self.assertIn(".resilience-banner", css)


if __name__ == "__main__":
    unittest.main()
