"""GUI-3 HTTP chat bridge and two-browser-style TLS/UDP network integration."""

from __future__ import annotations

import queue
import time
import unittest
import sys

from tests.test_gui_bridge import BridgeTestMixin, FakeClient, TestGUIBridgeLive


class ChatFake(FakeClient):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.calls = []
        self.next_id = 1

    def send_direct(self, recipient, text):
        self.calls.append(("direct", recipient, text))
        result = self.next_id
        self.next_id += 1
        return result

    def send_broadcast(self, text):
        self.calls.append(("broadcast", text))
        result = self.next_id
        self.next_id += 1
        return result


class BrokenChatFake(ChatFake):
    def send_direct(self, recipient, text):
        raise OSError("network refused the send queue")


class TestGUI3BridgeUnit(BridgeTestMixin, unittest.TestCase):
    def setUp(self):
        ChatFake.instances = []
        FakeClient.instances = []
        self.bridge = self._start_bridge(factory=ChatFake)
        self.token = self._get(self.bridge)[1]["bridge_token"]

    def _login(self):
        code, result = self._post(
            self.bridge,
            "/api/login",
            {"username": "an", "password": "correct"},
            token=self.token,
        )
        self.assertEqual(code, 200, result)
        self._wait_users(self.bridge, ["an", "binh"])

    def test_chat_requires_authenticated_session(self):
        code, _ = self._post(
            self.bridge, "/api/chat/broadcast", {"text": "hi"}, token=self.token
        )
        self.assertEqual(code, 409)
        code, _ = self._post(
            self.bridge,
            "/api/chat/direct",
            {"to": "binh", "text": "hi"},
            token=self.token,
        )
        self.assertEqual(code, 409)

    def test_direct_and_broadcast_reuse_one_client(self):
        self._login()
        one, direct = self._post(
            self.bridge,
            "/api/chat/direct",
            {"to": "binh", "text": "Xin chào 👋"},
            token=self.token,
        )
        self.assertEqual(one, 202)
        self.assertEqual(
            direct, {"ok": True, "queued": True, "scope": "direct", "request_id": 1}
        )
        two, broadcast = self._post(
            self.bridge,
            "/api/chat/broadcast",
            {"text": "Chào cả phòng"},
            token=self.token,
        )
        self.assertEqual(two, 202)
        self.assertEqual(broadcast["request_id"], 2)
        client = ChatFake.instances[0]
        self.assertEqual(
            client.calls,
            [("direct", "binh", "Xin chào 👋"), ("broadcast", "Chào cả phòng")],
        )

    def test_utf8_size_and_username_validation(self):
        self._login()
        for message in ("", "🍀" * 251):  # 1004 bytes, not merely 251 characters
            code, _ = self._post(
                self.bridge, "/api/chat/broadcast", {"text": message}, token=self.token
            )
            self.assertEqual(code, 400)
        code, result = self._post(
            self.bridge, "/api/chat/broadcast", {"text": "🍀" * 250}, token=self.token
        )
        self.assertEqual(code, 202, result)
        for bad_target in ("", "contains spaces", "a" * 33):
            code, _ = self._post(
                self.bridge,
                "/api/chat/direct",
                {"to": bad_target, "text": "hi"},
                token=self.token,
            )
            self.assertEqual(code, 400)

    @unittest.skipIf(
        sys.platform == "win32",
        "Temporarily skipped on Windows: localhost HTTP early-rejection can reset TCP before response; needs separate fix.",
    )
    def test_reject_extra_chat_fields_and_missing_token(self):
        self._login()
        code, _ = self._post(
            self.bridge,
            "/api/chat/direct",
            {"to": "binh", "text": "hi", "from": "admin"},
            token=self.token,
        )
        self.assertEqual(code, 400)
        code, _ = self._post(
            self.bridge, "/api/chat/direct", {"to": "binh", "text": "hi"}
        )
        self.assertEqual(code, 403)
        self.assertEqual(ChatFake.instances[0].calls, [])

    def test_chat_received_and_reply_to_metadata_preserved(self):
        self._login()
        current = self._get(self.bridge)[1]["cursor"]
        ChatFake.instances[0].events.put(
            {
                "type": "CHAT_ACCEPTED",
                "id": 19,
                "reply_to": 7,
                "body": {"server_msg_id": 77},
            }
        )
        ChatFake.instances[0].events.put(
            {
                "type": "CHAT_EVENT",
                "id": 20,
                "reply_to": None,
                "body": {
                    "from": "binh",
                    "to": "an",
                    "scope": "direct",
                    "text": "<script>alert(1)</script>",
                    "server_msg_id": 77,
                },
            }
        )
        deadline = time.monotonic() + 3
        items = []
        while time.monotonic() < deadline:
            _, data = self._get(self.bridge, f"/api/events?since={current}")
            items = data["events"]
            if len([e for e in items if e["type"].startswith("CHAT")]) == 2:
                break
            time.sleep(0.05)
        accepted = next(x for x in items if x["type"] == "CHAT_ACCEPTED")
        self.assertEqual(accepted["reply_to"], 7)
        self.assertEqual(accepted["message_id"], 19)
        self.assertEqual(
            next(x for x in items if x["type"] == "CHAT_EVENT")["body"]["text"],
            "<script>alert(1)</script>",
        )

    def test_logout_erases_previous_user_chat_history(self):
        self._login()
        ChatFake.instances[0].events.put(
            {
                "type": "CHAT_EVENT",
                "body": {
                    "from": "binh",
                    "scope": "broadcast",
                    "text": "PRIVATE CHAT CONTENT",
                },
            }
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            _, data = self._get(self.bridge, "/api/events?since=0")
            if any("PRIVATE CHAT CONTENT" in str(e) for e in data["events"]):
                break
            time.sleep(0.04)
        self.assertTrue(any("PRIVATE CHAT CONTENT" in str(e) for e in data["events"]))
        self.assertEqual(
            self._post(self.bridge, "/api/logout", {}, token=self.token)[0], 200
        )
        _, after = self._get(self.bridge, "/api/events?since=0")
        self.assertNotIn("PRIVATE CHAT CONTENT", str(after))
        self._login()
        _, after_login = self._get(self.bridge, "/api/events?since=0")
        self.assertNotIn("PRIVATE CHAT CONTENT", str(after_login))

    def test_send_queue_failure_is_not_202(self):
        broken = self._start_bridge(factory=BrokenChatFake)
        token = self._get(broken)[1]["bridge_token"]
        code, _ = self._post(
            broken, "/api/login", {"username": "an", "password": "correct"}, token=token
        )
        self.assertEqual(code, 200)
        code, response = self._post(
            broken, "/api/chat/direct", {"to": "binh", "text": "hello"}, token=token
        )
        self.assertEqual(code, 502, response)
        self.assertFalse(response.get("queued", False))


class TestGUI3LiveNetwork(BridgeTestMixin, unittest.TestCase):
    """Unlike a transport fixture: both clients use TLS + UDP sockets."""

    setUp = TestGUIBridgeLive.setUp

    def _wait_chat(self, bridge, expected_type, *, text=None, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, response = self._get(bridge, "/api/events?since=0")
            self.assertEqual(code, 200)
            matches = [
                e
                for e in response["events"]
                if e["type"] == expected_type
                and (text is None or e["body"].get("text") == text)
            ]
            if matches:
                return matches[0]
            time.sleep(0.05)
        self.fail(f"{expected_type} never arrived with text={text!r}")

    def test_two_real_http_bridges_send_direct_and_broadcast_over_udp(self):
        from client.core.session import CollaborationClient

        one = self._start_bridge(
            factory=CollaborationClient,
            server_host="127.0.0.1",
            tcp_port=self.server.tcp_port,
            trusted_cert=self.cert,
        )
        two = self._start_bridge(
            factory=CollaborationClient,
            server_host="127.0.0.1",
            tcp_port=self.server.tcp_port,
            trusted_cert=self.cert,
        )
        tok1 = self._get(one)[1]["bridge_token"]
        tok2 = self._get(two)[1]["bridge_token"]
        self.assertEqual(
            self._post(
                one,
                "/api/login",
                {"username": "an", "password": "an123456"},
                token=tok1,
            )[0],
            200,
        )
        self.assertEqual(
            self._post(
                two,
                "/api/login",
                {"username": "binh", "password": "binh123456"},
                token=tok2,
            )[0],
            200,
        )
        self._wait_users(one, ["an", "binh"])
        self._wait_users(two, ["an", "binh"])
        code, result = self._post(
            one,
            "/api/chat/direct",
            {"to": "binh", "text": "Hello from browser 🌼"},
            token=tok1,
        )
        self.assertEqual(code, 202, result)
        self.assertEqual(
            self._wait_chat(two, "CHAT_EVENT", text="Hello from browser 🌼")["body"][
                "from"
            ],
            "an",
        )
        receipt = self._wait_chat(one, "CHAT_ACCEPTED")
        self.assertEqual(receipt["reply_to"], result["request_id"])
        code, response = self._post(
            two, "/api/chat/broadcast", {"text": "Global hello ✨"}, token=tok2
        )
        self.assertEqual(code, 202, response)
        self.assertEqual(
            self._wait_chat(one, "CHAT_EVENT", text="Global hello ✨")["body"]["scope"],
            "broadcast",
        )
        self.assertEqual(
            self._wait_chat(two, "CHAT_EVENT", text="Global hello ✨")["body"]["scope"],
            "broadcast",
        )
        self.assertEqual(
            self._wait_chat(two, "CHAT_ACCEPTED")["reply_to"], response["request_id"]
        )


if __name__ == "__main__":
    unittest.main()
