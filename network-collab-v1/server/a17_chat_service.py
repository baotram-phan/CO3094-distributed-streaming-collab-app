"""A1.7/A: chat stream 1 application handler, independent of B's reliability.

Caller contract: verified encrypted UDP, contiguous in-order stream-1 bytes,
serial delivery per ConnID, and a bounded non-blocking reliable stream-1 sender.
No sockets, UDP crypto, ACKs or retransmit logic are implemented here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct
import threading
import time
from typing import Callable

from common.control_framing import ProtocolError
from common.control_stream_framing import (
    MAX_CONTROL_JSON, decode_control_json, encode_control_message,
)
from server.router import ChatRouter, ChatRoutingError
from server.sessions import SessionClosedEvent, SessionRegistry, SessionState

CHAT_STREAM_ID = 1
MAX_STREAM_DELIVERY_BYTES = 65536


@dataclass
class _ChatState:
    inbound_lock: threading.RLock = field(default_factory=threading.RLock)
    outbound_lock: threading.RLock = field(default_factory=threading.RLock)
    buffer: bytearray = field(default_factory=bytearray)
    next_offset: int = 0
    last_client_message_id: int = 0
    next_server_message_id: int = 1
    finished: bool = False
    disposed: bool = False


class A17ChatService:
    def __init__(self, registry: SessionRegistry,
                 send_reliable_chat: Callable[[int, bytes], None],
                 send_control_error: Callable[[int, str, str, int | None], None],
                 *, clock_ms: Callable[[], int] | None = None) -> None:
        if not callable(send_reliable_chat) or not callable(send_control_error):
            raise TypeError("Both reliable chat and control-error callbacks are required")
        self.registry = registry
        self.router = ChatRouter(registry)
        self._send_chat = send_reliable_chat
        self._send_error = send_control_error
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self._states: dict[int, _ChatState] = {}
        self._closed: set[int] = set()
        self._lock = threading.Lock()

    def _get_state(self, conn_id: int) -> _ChatState | None:
        with self._lock:
            if conn_id in self._closed:
                return None
            state = self._states.get(conn_id)
            if state is None:
                state = _ChatState()
                self._states[conn_id] = state
            return state

    def on_session_closed(self, event: SessionClosedEvent) -> None:
        """Called only by A coordinator, which alone drains Registry events."""
        with self._lock:
            self._closed.add(event.conn_id)
            state = self._states.pop(event.conn_id, None)
        if state is not None:
            state.disposed = True

    def _error(self, conn_id: int, code: str, message: str,
               reply_to: int | None = None) -> None:
        # Always use reliable CONTROL stream 0 for ERROR responses.
        self._send_error(conn_id, code, message, reply_to)

    def _enqueue_chat(self, conn_id: int, kind: str, body: dict,
                      reply_to: int | None = None) -> bool:
        session = self.registry.get(conn_id)
        if session is None or session.state is not SessionState.ONLINE:
            return False
        state = self._get_state(conn_id)
        if state is None:
            return False
        # Serializes outbound IDs AND enqueue order for this recipient.
        # This is an application lock, never B's transport lock. B's callback
        # must be bounded/non-blocking and must not synchronously reenter A.
        with state.outbound_lock:
            if state.disposed:
                return False
            # A concurrent logout may have closed the session since the first
            # check. Transport cleanup still remains B's final cancel barrier.
            current = self.registry.get(conn_id)
            if current is None or current.state is not SessionState.ONLINE:
                return False
            message = {"v": 1, "type": kind, "id": state.next_server_message_id,
                       "reply_to": reply_to, "body": body}
            payload = encode_control_message(message)
            self._send_chat(conn_id, payload)
            state.next_server_message_id += 1
            return True

    def _process_message(self, conn_id: int, message: dict) -> None:
        request_id = message["id"]
        if message["reply_to"] is not None:
            self._error(conn_id, "BAD_FRAME", "Client request reply_to must be null", request_id)
            return
        try:
            plan = self.router.prepare(conn_id, message["type"], message["body"])
        except ChatRoutingError as exc:
            self._error(conn_id, exc.code, str(exc), request_id)
            return
        server_msg_id = self.router.next_message_id()
        event = {
            "server_msg_id": server_msg_id,
            "from": plan.sender,
            "to": plan.to,
            "scope": plan.scope,
            "text": plan.text,
            "ts": self._clock_ms(),  # Unix epoch milliseconds
        }
        # Enqueue one copy for every target. CHAT_ACCEPTED means queued by
        # server, NEVER opened/read by the final recipient.
        for destination_id, username in plan.recipients:
            current = self.registry.find_online(username)
            if current is None or current.conn_id != destination_id:
                self._error(conn_id, "USER_OFFLINE", "Recipient went offline", request_id)
                return
            try:
                if not self._enqueue_chat(destination_id, "CHAT_EVENT", event):
                    self._error(conn_id, "USER_OFFLINE", "Recipient went offline", request_id)
                    return
            except Exception:
                # A failed enqueue might already have queued some broadcast
                # recipients; delivery is NOT transactional across clients.
                self._error(conn_id, "INTERNAL", "Chat enqueue failed", request_id)
                return
        try:
            self._enqueue_chat(conn_id, "CHAT_ACCEPTED", {
                "server_msg_id": server_msg_id
            }, request_id)
        except Exception:
            # The event may be queued even if the confirmation cannot be sent.
            # Do not retransmit it here: B owns transport reliability.
            return

    def on_stream_data(self, conn_id: int, stream_id: int, offset: int,
                       data: bytes, fin: bool = False) -> bool:
        if stream_id != CHAT_STREAM_ID:
            raise ValueError("Chat service accepts stream 1 only")
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes):
            raise ValueError("Invalid stream offset/data")
        session = self.registry.get(conn_id)
        if session is None or session.state not in (SessionState.UDP_BOUND, SessionState.ONLINE):
            return False
        if session.state is not SessionState.ONLINE:
            self._error(conn_id, "NOT_AUTHENTICATED", "Login required for chat")
            return False
        state = self._get_state(conn_id)
        if state is None:
            return False
        parsed: list[dict] = []
        malformed = False
        with state.inbound_lock:
            if state.disposed or state.finished:
                return False
            if offset < state.next_offset and offset + len(data) <= state.next_offset:
                return True  # Already delivered by B; don't repeat side effects
            if offset != state.next_offset:
                raise ValueError("B must deliver contiguous stream 1 offsets")
            if len(data) > MAX_STREAM_DELIVERY_BYTES:
                malformed = True
            else:
                state.next_offset += len(data)
                state.buffer.extend(data)
                while len(state.buffer) >= 4:
                    (length,) = struct.unpack("!I", state.buffer[:4])
                    if not 1 <= length <= MAX_CONTROL_JSON:
                        malformed = True
                        break
                    if len(state.buffer) < 4 + length:
                        break
                    chunk = bytes(state.buffer[4:4 + length])
                    del state.buffer[:4 + length]
                    try:
                        item = decode_control_json(chunk)
                    except ProtocolError:
                        malformed = True
                        break
                    if item["id"] <= state.last_client_message_id:
                        parsed.append({"_duplicate_id": item["id"]})
                        continue
                    state.last_client_message_id = item["id"]
                    parsed.append(item)
            if fin:
                if state.buffer:
                    malformed = True
                state.finished = True
        if malformed:
            self.registry.close(conn_id, reason="bad_chat_frame")
            self.on_session_closed(SessionClosedEvent(conn_id, "bad_chat_frame"))
            return False
        # No registry/transport locks are held during callbacks. B must call
        # each session serially; different connections may execute concurrently.
        for item in parsed:
            if state.disposed:
                return False
            if "_duplicate_id" in item:
                self._error(conn_id, "BAD_FRAME", "Non-increasing chat message id",
                            item["_duplicate_id"])
            else:
                self._process_message(conn_id, item)
        return True
