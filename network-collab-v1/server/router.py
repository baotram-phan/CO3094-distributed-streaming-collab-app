"""A1.7/A: application-level direct/broadcast chat routing (no UDP I/O).

Only ONLINE SessionRegistry entries are eligible. The sender is looked up from
ConnID, never trusted from the client's JSON. B owns reliable stream 1.
"""
from __future__ import annotations

from dataclasses import dataclass
import threading

from common.models import ApplicationValidationError, validate_chat_text, validate_chat_username
from server.sessions import SessionRegistry, SessionState


class ChatRoutingError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ChatPlan:
    sender: str
    scope: str
    to: str | None
    text: str
    recipients: tuple[tuple[int, str], ...]  # (ConnID, authenticated username)


class ChatRouter:
    """Compute an ONLINE-only delivery plan without queuing any bytes."""

    def __init__(self, registry: SessionRegistry) -> None:
        self.registry = registry
        self._next_message_id = 1
        self._id_lock = threading.Lock()

    def next_message_id(self) -> int:
        with self._id_lock:
            current = self._next_message_id
            self._next_message_id += 1
            return current

    def prepare(self, conn_id: int, kind: str, body: dict) -> ChatPlan:
        source = self.registry.get(conn_id)
        if source is None or source.state is not SessionState.ONLINE or not source.username:
            raise ChatRoutingError("NOT_AUTHENTICATED", "Login required for chat")
        if not isinstance(body, dict):
            raise ChatRoutingError("BAD_FRAME", "Chat body must be an object")
        if kind not in ("CHAT_DIRECT", "CHAT_BROADCAST"):
            raise ChatRoutingError("BAD_FRAME", "Unsupported chat message")
        required = {"to", "text"} if kind == "CHAT_DIRECT" else {"text"}
        if set(body) != required:  # includes rejecting user-supplied 'from'
            raise ChatRoutingError("BAD_FRAME", "Invalid chat fields")
        try:
            text = validate_chat_text(body["text"])
        except ApplicationValidationError as exc:
            raise ChatRoutingError(exc.code, str(exc)) from exc
        if kind == "CHAT_DIRECT":
            to = body["to"]
            try:
                validate_chat_username(to)
            except ApplicationValidationError as exc:
                raise ChatRoutingError(exc.code, str(exc)) from exc
            destination = self.registry.find_online(to)
            if destination is None or destination.state is not SessionState.ONLINE:
                raise ChatRoutingError("USER_OFFLINE", "Recipient is offline")
            return ChatPlan(source.username, "direct", to, text,
                            ((destination.conn_id, to),))
        recipients: list[tuple[int, str]] = []
        # Server-side broadcast means one copy to EACH ONLINE client, including
        # sender, rather than an IP-level UDP broadcast.
        for name in self.registry.list_online_users():
            entry = self.registry.find_online(name)
            if entry is not None and entry.state is SessionState.ONLINE:
                recipients.append((entry.conn_id, name))
        return ChatPlan(source.username, "broadcast", None, text, tuple(recipients))
