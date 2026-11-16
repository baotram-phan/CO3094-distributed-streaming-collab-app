"""REAL loopback TLS + REGISTER + DATA/ACK AUTH + two-client CHAT.

Creates a short-lived, isolated password file and TLS certificate; unlike
transport fixtures, every session and encrypted DATA packet comes through
actual TCP/UDP sockets. Nothing private is written to the project tree.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import queue
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from client.core.session import CollaborationClient
from scripts.gen_cert import generate_certificate
from server.main import CollaborationServer
from server.sessions import SessionState


def _until(client, kind, *, predicate=None, timeout=6.0):
    end = time.monotonic() + timeout
    seen = []
    while time.monotonic() < end:
        try:
            item = client.receive_event(
                timeout_s=min(0.2, max(0.001, end - time.monotonic()))
            )
        except queue.Empty:
            if client.failure:
                raise AssertionError(f"client worker failed: {client.failure}")
            continue
        seen.append(item)
        if item["type"] == kind and (predicate is None or predicate(item)):
            return item
    raise AssertionError(
        f"Timed out expecting {kind}; seen={[x['type'] for x in seen]}"
    )


class RealTlsUdpTwoClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        cert, key = generate_certificate(root / "cert")
        user_json = root / "users.json"
        result = {}
        for username, password in (("an", "an123456"), ("binh", "binh123456")):
            salt = secrets.token_bytes(16)
            result[username] = {
                "salt": salt.hex(),
                "hash": hashlib.pbkdf2_hmac(
                    "sha256", password.encode(), salt, 200_000
                ).hex(),
                "iterations": 200_000,
            }
        user_json.write_text(json.dumps(result), encoding="utf-8")
        self.users_path = patch("server.auth.USERS_FILE", user_json)
        self.users_path.start()
        self.closed_events = queue.Queue()
        self.server = CollaborationServer(
            host="127.0.0.1",
            tcp_port=0,
            udp_port=0,
            cert=cert,
            key=key,
            logger=None,
            on_session_closed=self.closed_events.put,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cert = cert
        self.clients = []

    def tearDown(self):
        for cli in self.clients:
            cli.close()
        self.server.stop()
        self.thread.join(timeout=2)
        self.users_path.stop()
        self.tmp.cleanup()

    def _new_client(self):
        cli = CollaborationClient(
            host="127.0.0.1", tcp_port=self.server.tcp_port, trusted_cert=self.cert
        )
        self.clients.append(cli)
        cli.connect()
        # These are the real remote UDP ports, not HTTP bridge ports 8000/8001.
        session = self.server.registry.get(cli.conn_id)
        self.assertIsNotNone(session)
        self.assertIs(session.state, SessionState.UDP_BOUND)
        self.assertIsNone(session.username)
        self.assertEqual(session.tcp_ip, "127.0.0.1")
        self.assertEqual(
            session.udp_endpoint, ("127.0.0.1", cli.udp.sock.getsockname()[1])
        )
        return cli

    def test_real_two_client_tls_register_auth_direct_and_broadcast(self):
        """TC3.1: correct credentials yield AUTH_OK/ONLINE and working chat."""
        an = self._new_client()
        self.assertTrue(an.authenticate("an", "an123456", timeout_s=6.0))
        self.assertIs(self.server.registry.get(an.conn_id).state, SessionState.ONLINE)
        self.assertEqual(_until(an, "AUTH_OK")["body"], {"username": "an"})
        self.assertEqual(_until(an, "USER_LIST")["body"], {"users": ["an"]})
        binh = self._new_client()
        self.assertTrue(binh.authenticate("binh", "binh123456", timeout_s=6.0))
        self.assertIs(self.server.registry.get(binh.conn_id).state, SessionState.ONLINE)
        an.send_direct("binh", "Xin chào Bình 👋")
        received = _until(
            binh,
            "CHAT_EVENT",
            predicate=lambda e: e["body"]["text"] == "Xin chào Bình 👋",
        )
        self.assertEqual(received["body"]["from"], "an")
        self.assertEqual(received["body"]["scope"], "direct")
        _until(an, "CHAT_ACCEPTED")
        binh.send_broadcast("Chào cả phòng!")
        _until(
            an, "CHAT_EVENT", predicate=lambda e: e["body"]["text"] == "Chào cả phòng!"
        )
        _until(
            binh,
            "CHAT_EVENT",
            predicate=lambda e: e["body"]["text"] == "Chào cả phòng!",
        )
        self.assertIsNone(an.failure)
        self.assertIsNone(binh.failure)

    def test_wrong_password_is_business_auth_fail_not_delivery_failure(self):
        """TC3.2: wrong password yields AUTH_FAILED without becoming ONLINE."""
        an = self._new_client()
        self.assertFalse(an.authenticate("an", "bad-password", timeout_s=6.0))
        failure = _until(an, "AUTH_FAIL")
        self.assertEqual(failure["body"]["code"], "AUTH_FAILED")
        self.assertIs(
            self.server.registry.get(an.conn_id).state, SessionState.UDP_BOUND
        )
        self.assertEqual(self.server.registry.list_online_users(), [])
        self.assertIsNone(self.server.registry.get(an.conn_id).username)
        self.assertIsNone(an.failure)

    def test_duplicate_login_preserves_original_session(self):
        """TC3.3: reject the new ConnID, keep the original usable."""
        an = self._new_client()
        self.assertTrue(an.authenticate("an", "an123456", timeout_s=6.0))
        binh = self._new_client()
        self.assertTrue(binh.authenticate("binh", "binh123456", timeout_s=6.0))
        original_endpoint = self.server.registry.find_online("an").udp_endpoint

        duplicate = self._new_client()
        self.assertNotEqual(duplicate.conn_id, an.conn_id)
        self.assertFalse(duplicate.authenticate("an", "an123456", timeout_s=6.0))
        failure = _until(duplicate, "AUTH_FAIL")
        self.assertEqual(failure["body"]["code"], "ALREADY_LOGGED_IN")
        self.assertIs(
            self.server.registry.get(duplicate.conn_id).state, SessionState.UDP_BOUND
        )
        original = self.server.registry.find_online("an")
        self.assertEqual(original.conn_id, an.conn_id)
        self.assertEqual(original.udp_endpoint, original_endpoint)
        self.assertEqual(self.server.registry.list_online_users(), ["an", "binh"])

        an.send_direct("binh", "original-session-still-alive")
        _until(
            binh,
            "CHAT_EVENT",
            predicate=lambda e: e["body"].get("from") == "an"
            and e["body"].get("text") == "original-session-still-alive",
        )
        self.assertIsNone(an.failure)
        self.assertIsNone(binh.failure)

    def test_user_list_and_online_presence_after_second_login(self):
        """TC3.4: the new user gets USER_LIST; existing users get PRESENCE."""
        an = self._new_client()
        self.assertTrue(an.authenticate("an", "an123456", timeout_s=6.0))
        self.assertEqual(_until(an, "USER_LIST")["body"]["users"], ["an"])

        binh = self._new_client()
        self.assertTrue(binh.authenticate("binh", "binh123456", timeout_s=6.0))
        self.assertEqual(
            _until(binh, "USER_LIST")["body"]["users"], ["an", "binh"]
        )
        presence = _until(an, "PRESENCE")
        self.assertEqual(presence["body"], {"username": "binh", "status": "online"})
        self.assertEqual(self.server.registry.list_online_users(), ["an", "binh"])
        for client, username in ((an, "an"), (binh, "binh")):
            session = self.server.registry.find_online(username)
            self.assertEqual(session.conn_id, client.conn_id)
            self.assertIs(session.state, SessionState.ONLINE)
            self.assertEqual(
                session.udp_endpoint, ("127.0.0.1", client.udp.sock.getsockname()[1])
            )
        self.assertNotEqual(
            self.server.registry.find_online("an").udp_endpoint,
            self.server.registry.find_online("binh").udp_endpoint,
        )

    def test_client_close_times_out_cleans_resources_and_notifies_peer(self):
        """TC3.5: stop real client UDP; let the server's default timeout clean up."""
        an = self._new_client()
        self.assertTrue(an.authenticate("an", "an123456", timeout_s=6.0))
        binh = self._new_client()
        self.assertTrue(binh.authenticate("binh", "binh123456", timeout_s=6.0))
        _until(
            an,
            "PRESENCE",
            predicate=lambda e: e["body"] == {"username": "binh", "status": "online"},
        )
        # Ensure An has application chat state to dispose, too.
        an.send_direct("binh", "before-disconnect")
        _until(
            binh,
            "CHAT_EVENT",
            predicate=lambda e: e["body"].get("text") == "before-disconnect",
        )
        _until(an, "CHAT_ACCEPTED")

        an.close()  # No registry.close(), fake clock or mocked network.
        offline = _until(
            binh,
            "PRESENCE",
            predicate=lambda e: e["body"] == {"username": "an", "status": "offline"},
            timeout=self.server.registry.idle_timeout_s + 5,
        )
        self.assertEqual(offline["body"]["username"], "an")
        closed = self.closed_events.get(timeout=2)
        self.assertEqual((closed.conn_id, closed.reason), (an.conn_id, "idle_timeout"))
        self.assertIsNone(self.server.registry.get(an.conn_id))
        self.assertIsNone(self.server.registry.find_online("an"))
        self.assertNotIn(an.conn_id, self.server.udp_service.connection_ids())
        self.assertIsNone(self.server.udp_service.get_reliable_receiver(an.conn_id))
        self.assertNotIn(an.conn_id, self.server.auth_service._states)
        self.assertNotIn(an.conn_id, self.server.chat_service._states)
        self.assertEqual(self.server.registry.list_online_users(), ["binh"])

        # Surviving client remains usable and the account can obtain a new session.
        replacement = self._new_client()
        self.assertTrue(replacement.authenticate("an", "an123456", timeout_s=6.0))
        self.assertNotEqual(replacement.conn_id, an.conn_id)
        binh.send_direct("an", "after-reconnect")
        _until(
            replacement,
            "CHAT_EVENT",
            predicate=lambda e: e["body"].get("from") == "binh"
            and e["body"].get("text") == "after-reconnect",
        )
        self.assertIsNone(binh.failure)
