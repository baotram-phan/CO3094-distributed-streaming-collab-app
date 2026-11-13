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
from server.sessions import SessionRegistry, SessionState


def _until(client, kind, *, predicate=None, timeout=6.0):
    end = time.monotonic() + timeout
    seen = []
    while time.monotonic() < end:
        try:
            item = client.receive_event(timeout_s=min(0.2, max(0.001, end - time.monotonic())))
        except queue.Empty:
            if client.failure:
                raise AssertionError(f"client worker failed: {client.failure}")
            continue
        seen.append(item)
        if item["type"] == kind and (predicate is None or predicate(item)):
            return item
    raise AssertionError(f"Timed out expecting {kind}; seen={[x['type'] for x in seen]}")


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
                "hash": hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000).hex(),
                "iterations": 200_000,
            }
        user_json.write_text(json.dumps(result), encoding="utf-8")
        self.users_path = patch('server.auth.USERS_FILE', user_json)
        self.users_path.start()
        self.server = CollaborationServer(host="127.0.0.1", tcp_port=0, udp_port=0,
                                          cert=cert, key=key, logger=None)
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
        cli = CollaborationClient(host='127.0.0.1', tcp_port=self.server.tcp_port,
                                  trusted_cert=self.cert)
        self.clients.append(cli)
        cli.connect()
        return cli

    def test_real_two_client_tls_register_auth_direct_and_broadcast(self):
        an = self._new_client()
        self.assertTrue(an.authenticate("an", "an123456", timeout_s=6.0))
        self.assertIs(self.server.registry.get(an.conn_id).state, SessionState.ONLINE)
        binh = self._new_client()
        self.assertTrue(binh.authenticate("binh", "binh123456", timeout_s=6.0))
        self.assertIs(self.server.registry.get(binh.conn_id).state, SessionState.ONLINE)
        an.send_direct("binh", "Xin chào Bình 👋")
        received = _until(binh, "CHAT_EVENT", predicate=lambda e: e['body']['text'] == "Xin chào Bình 👋")
        self.assertEqual(received['body']['from'], 'an')
        self.assertEqual(received['body']['scope'], 'direct')
        _until(an, 'CHAT_ACCEPTED')
        binh.send_broadcast("Chào cả phòng!")
        _until(an, 'CHAT_EVENT', predicate=lambda e: e['body']['text'] == "Chào cả phòng!")
        _until(binh, 'CHAT_EVENT', predicate=lambda e: e['body']['text'] == "Chào cả phòng!")
        self.assertIsNone(an.failure)
        self.assertIsNone(binh.failure)

    def test_wrong_password_is_business_auth_fail_not_delivery_failure(self):
        an = self._new_client()
        self.assertFalse(an.authenticate("an", "bad-password", timeout_s=6.0))
        self.assertIs(self.server.registry.get(an.conn_id).state, SessionState.UDP_BOUND)
        self.assertIsNone(an.failure)
