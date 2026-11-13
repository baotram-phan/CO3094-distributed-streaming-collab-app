"""Build stream-1 chat application frames; B is responsible for reliable UDP.

No socket or TLS calls live here. Each client should use a monotonically
increasing message_id on its chat stream.
"""
from __future__ import annotations

from common.control_stream_framing import encode_control_message
from common.models import validate_chat_text, validate_chat_username


def _build(kind: str, body: dict, message_id: int) -> bytes:
    if type(message_id) is not int or message_id < 1:
        raise ValueError("message_id must be a positive integer")
    validate_chat_text(body.get("text"))
    return encode_control_message({
        "v": 1, "type": kind, "id": message_id,
        "reply_to": None, "body": body,
    })


def build_chat_direct(to: str, text: str, *, message_id: int) -> bytes:
    validate_chat_username(to)
    return _build("CHAT_DIRECT", {"to": to, "text": text}, message_id)


def build_chat_broadcast(text: str, *, message_id: int) -> bytes:
    return _build("CHAT_BROADCAST", {"text": text}, message_id)
