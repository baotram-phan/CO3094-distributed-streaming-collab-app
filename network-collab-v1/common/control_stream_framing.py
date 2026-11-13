"""Application JSON framing for reliable UDP control stream 0 (NOT TLS bootstrap).

Wire format: u32 big-endian JSON byte length + UTF-8 JSON (1..8192 bytes).
B's reliable transport carries these bytes; no UDP send/receive occurs here.
"""
from __future__ import annotations

import json
import struct

from common.control_framing import ProtocolError, validate_envelope

MAX_CONTROL_JSON = 8192


def encode_control_message(message: dict) -> bytes:
    validate_envelope(message)
    try:
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
    except (UnicodeError, TypeError, ValueError) as exc:
        raise ProtocolError("BAD_FRAME", "Invalid control JSON") from exc
    if not 1 <= len(payload) <= MAX_CONTROL_JSON:
        raise ProtocolError("FRAME_TOO_LARGE", "Control JSON is longer than 8192 bytes")
    return struct.pack("!I", len(payload)) + payload


def decode_control_json(payload: bytes) -> dict:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_CONTROL_JSON:
        raise ProtocolError("BAD_FRAME", "Invalid control JSON length")
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("BAD_FRAME", "Invalid UTF-8 JSON") from exc
    validate_envelope(message)
    return message
