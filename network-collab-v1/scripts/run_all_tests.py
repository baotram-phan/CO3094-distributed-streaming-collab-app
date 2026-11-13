"""Run the project test suite using temporary demo accounts only.

Avoids creating config/users.json or accidentally overwriting real accounts.
This helper is for unit/integration tests, not for running the real server.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch


def main() -> int:
    with tempfile.TemporaryDirectory(prefix='collab-test-users-') as tmp:
        path = Path(tmp) / 'users.json'
        accounts = {}
        for username, password in (("an", "an123456"),
                                   ("binh", "binh123456"),
                                   ("chi", "chi123456")):
            salt = secrets.token_bytes(16)
            accounts[username] = {
                "salt": salt.hex(),
                "hash": hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000).hex(),
                "iterations": 200_000,
            }
        path.write_text(json.dumps(accounts), encoding='utf-8')
        import server.auth
        with patch.object(server.auth, 'USERS_FILE', path):
            tests = unittest.defaultTestLoader.discover('tests')
            result = unittest.TextTestRunner(verbosity=1).run(tests)
            return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
