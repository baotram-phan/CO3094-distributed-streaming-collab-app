"""Shared application validators, separate from UDP binary packet codecs.

Client serializers and server routing reuse these message and username limits.
"""

from __future__ import annotations

import re

MAX_CHAT_TEXT_BYTES = 1000
MAX_USERNAME_LENGTH = 32
_VALID_USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z", flags=re.ASCII)


class ApplicationValidationError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def validate_chat_username(username: str) -> str:
    if not isinstance(username, str) or not _VALID_USERNAME.fullmatch(username):
        raise ApplicationValidationError("BAD_FRAME", "Invalid target username")
    return username


def validate_chat_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        raise ApplicationValidationError("BAD_FRAME", "Chat text must not be empty")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ApplicationValidationError(
            "BAD_FRAME", "Invalid Unicode chat text"
        ) from exc
    if size > MAX_CHAT_TEXT_BYTES:
        raise ApplicationValidationError(
            "CHAT_TOO_LARGE", "Chat exceeds 1000 UTF-8 bytes"
        )
    return text
