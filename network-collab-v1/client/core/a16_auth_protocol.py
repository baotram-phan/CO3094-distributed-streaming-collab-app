"""Client-side AUTH request serializer (A1.6/A); B sends on reliable UDP stream 0.

This file intentionally does NOT call UDP socket.sendto or TLS. It is an
application helper and cannot authenticate anyone without B's transport.
"""
from __future__ import annotations

from common.control_stream_framing import encode_control_message


def build_auth_request(username: str, password: str, *, message_id: int = 1) -> bytes:
    if not isinstance(username, str) or not 1 <= len(username) <= 128:
        raise ValueError("Invalid username")
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise ValueError("Invalid password")
    if type(message_id) is not int or message_id < 1:
        raise ValueError("message_id must be a positive integer")
    return encode_control_message({
        "v": 1,
        "type": "AUTH",
        "id": message_id,
        "reply_to": None,
        "body": {"username": username, "password": password},
    })
