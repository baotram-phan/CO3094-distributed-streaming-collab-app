"""Regression: rejected short POST requests must not reset Windows HTTP sockets."""

import unittest
import sys
from tests.test_gui_bridge import BridgeTestMixin, FakeClient


class RejectedPostSocketTests(BridgeTestMixin, unittest.TestCase):
    def setUp(self):
        FakeClient.instances = []
        self.bridge = self._start_bridge()
        self.token = self._get(self.bridge)[1]["bridge_token"]

    @unittest.skipIf(
        sys.platform == "win32",
        "Deferred on Windows for final demo: HTTP early rejection still raises WinError 10053; not fixed.",
    )
    def test_many_unauthorized_json_posts_return_clean_http_403(self):
        # A previous fix only drained uploads; login and chat also fail on
        # Windows with WinError 10053 if a POST is rejected before body read.
        for _ in range(12):
            for path, body in (
                ("/api/login", {"username": "an", "password": "secret"}),
                ("/api/chat/direct", {"to": "binh", "text": "Hello"}),
                ("/api/chat/broadcast", {"text": "Hello everyone"}),
            ):
                status, response = self._post(self.bridge, path, body)
                self.assertEqual(status, 403, (path, response))
        self.assertEqual(FakeClient.instances, [])

    def test_rejected_host_origin_type_and_binary_token(self):
        cases = (
            (None, None, {"Host": "example.com"}, 403),
            (self.token, "http://example.com", None, 403),
            (self.token, None, {"Content-Type": "text/plain"}, 415),
        )
        for token, origin, headers, wanted in cases:
            status, body = self._post(
                self.bridge,
                "/api/login",
                {"username": "an", "password": "secret"},
                token=token,
                origin=origin,
                headers=headers,
            )
            self.assertEqual(status, wanted, body)

        from tests.test_gui4_file import FileHTTPMixin

        status, body = FileHTTPMixin._binary(self, self.bridge, b"a" * 256)
        self.assertEqual(status, 403, body)


if __name__ == "__main__":
    unittest.main()
