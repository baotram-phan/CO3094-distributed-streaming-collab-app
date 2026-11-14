"""Authentication and presence handling on reliable control stream 0."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
import threading
from typing import Callable

from common.control_framing import ProtocolError
from common.control_stream_framing import (
    MAX_CONTROL_JSON,
    decode_control_json,
    encode_control_message,
)
from server.sessions import (
    DuplicateLogin,
    InvalidTransition,
    SessionClosedEvent,
    SessionError,
    SessionRegistry,
    SessionState,
)

CONTROL_STREAM_ID = 0
MAX_AUTH_ATTEMPTS = 3


@dataclass
class _StreamState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    buffer: bytearray = field(default_factory=bytearray)
    next_offset: int = 0
    last_client_id: int = 0
    next_server_id: int = 1
    failed_auth: int = 0
    finished: bool = False
    disposed: bool = False


class A16AuthService:
    """Synchronous application handler. B must call on an A-side worker,
    serially per ConnID, never directly under its UDP receive/transport locks.

    sender(conn_id, framed_bytes) only queues bytes for reliable transmission;
    it must not synchronously call back into this service.
    """

    def __init__(
        self,
        registry: SessionRegistry,
        send_reliable_control: Callable[[int, bytes], None],
    ) -> None:
        if not callable(send_reliable_control):
            raise TypeError("send_reliable_control must be a callable")
        self.registry = registry
        self._sender = send_reliable_control
        self._states: dict[int, _StreamState] = {}
        # Coordinator tombstones block an in-flight stream callback from
        # recreating application state after close-event cleanup.
        self._closed_conn_ids: set[int] = set()
        self._states_lock = threading.Lock()

    def _get_state(self, conn_id: int) -> _StreamState | None:
        with self._states_lock:
            if conn_id in self._closed_conn_ids:
                return None
            state = self._states.get(conn_id)
            if state is None:
                state = _StreamState()
                self._states[conn_id] = state
            return state

    def _drop_state(self, conn_id: int) -> None:
        with self._states_lock:
            self._closed_conn_ids.add(conn_id)
            state = self._states.pop(conn_id, None)
        if state is not None:
            # No need to hold state.lock. In-flight callbacks check disposed
            # after their current processing step, before sending replies.
            state.disposed = True

    def _message(
        self, recipient_id: int, kind: str, body: dict, reply_to: int | None = None
    ) -> None:
        if self.registry.get(recipient_id) is None:
            return
        state = self._get_state(recipient_id)
        if state is None:
            return
        with state.lock:
            if state.disposed:
                return
            message_id = state.next_server_id
            state.next_server_id += 1
        envelope = {
            "v": 1,
            "type": kind,
            "id": message_id,
            "reply_to": reply_to,
            "body": body,
        }
        self._sender(recipient_id, encode_control_message(envelope))

    def send_application_error(
        self, conn_id: int, code: str, message: str, reply_to: int | None = None
    ) -> None:
        """A1.7 chat uses the existing stream-0 envelope ID sequence for ERROR.

        This is an A-side application callback, NOT a raw transport send.
        """
        self._message(conn_id, "ERROR", {"code": code, "message": message}, reply_to)

    def on_stream_data(
        self, conn_id: int, stream_id: int, offset: int, data: bytes, fin: bool = False
    ) -> bool:
        """Consume contiguous in-order bytes from B. Return False if session
        absent/unbound; reject gaps (B must reorder/assemble before delivery).
        No plaintext AUTH ever arrives from REGISTER/raw UDP/TLS here.
        """
        if stream_id != CONTROL_STREAM_ID:
            raise ValueError("A1.6 AUTH only handles reliable stream 0")
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes):
            raise ValueError("Invalid reliable stream data/offset")
        session = self.registry.get(conn_id)
        if session is None or session.state not in (
            SessionState.UDP_BOUND,
            SessionState.ONLINE,
        ):
            return False
        state = self._get_state(conn_id)
        if state is None:
            return False
        outgoing: list[tuple[int, str, dict, int | None]] = []
        close_after = False
        malformed = False
        with state.lock:
            if state.disposed or state.finished:
                return False
            if offset < state.next_offset and offset + len(data) <= state.next_offset:
                return True  # already-delivered duplicate; no re-execution
            if offset != state.next_offset:
                raise ValueError("B must deliver stream 0 bytes in exact offset order")
            if len(data) > 65536:
                malformed = True
            else:
                state.next_offset += len(data)
                state.buffer.extend(data)
                while len(state.buffer) >= 4:
                    (size,) = struct.unpack("!I", state.buffer[:4])
                    if not 1 <= size <= MAX_CONTROL_JSON:
                        malformed = True
                        break
                    if len(state.buffer) < size + 4:
                        break
                    payload = bytes(state.buffer[4 : 4 + size])
                    del state.buffer[: 4 + size]
                    try:
                        message = decode_control_json(payload)
                    except ProtocolError:
                        malformed = True
                        break
                    request_id = message["id"]
                    if request_id <= state.last_client_id:
                        outgoing.append(
                            (
                                conn_id,
                                "ERROR",
                                {
                                    "code": "BAD_FRAME",
                                    "message": "Non-increasing message id",
                                },
                                request_id,
                            )
                        )
                        continue
                    state.last_client_id = request_id
                    intents, close = self._dispatch(conn_id, state, message)
                    outgoing.extend(intents)
                    if close:
                        close_after = True
                        break
            if fin:
                if state.buffer:
                    malformed = True
                state.finished = True

        if malformed:
            # Invalid/incomplete application frame: close to prevent ambiguous
            # stream parsing or unbounded buffer growth. Coordinator drains event.
            self.registry.close(conn_id, reason="bad_control_frame")
            self._drop_state(conn_id)
            return False

        # External transport callback is OUTSIDE state/registry locks.
        try:
            for recipient_id, kind, body, reply_to in outgoing:
                if state.disposed:
                    break
                self._message(recipient_id, kind, body, reply_to)
        finally:
            if close_after:
                # The last AUTH_FAIL is best effort: cleanup can cancel a
                # pending reliable response, as required by session teardown.
                self.registry.close(conn_id, reason="auth_failure_limit")
                self._drop_state(conn_id)
        return True

    def _dispatch(
        self, conn_id: int, state: _StreamState, message: dict
    ) -> tuple[list[tuple[int, str, dict, int | None]], bool]:
        request_id = message["id"]
        kind = message["type"]
        session = self.registry.get(conn_id)
        if session is None:
            return [], False
        if (
            session.state is SessionState.ONLINE
            and kind.startswith("FILE_")
            and getattr(self, "file_control", None)
        ):
            return self.file_control(conn_id, message), False
        if kind != "AUTH":
            code = (
                "NOT_AUTHENTICATED"
                if session.state is not SessionState.ONLINE
                else "BAD_FRAME"
            )
            return [
                (
                    conn_id,
                    "ERROR",
                    {"code": code, "message": "Unsupported at A1.6"},
                    request_id,
                )
            ], False
        if session.state is not SessionState.UDP_BOUND:
            return [
                (
                    conn_id,
                    "ERROR",
                    {"code": "BAD_FRAME", "message": "AUTH not allowed"},
                    request_id,
                )
            ], False

        body = message["body"]
        username = body.get("username")
        password = body.get("password")
        if (
            not isinstance(username, str)
            or not 1 <= len(username) <= 128
            or not isinstance(password, str)
            or not 1 <= len(password) <= 1024
        ):
            return [
                (
                    conn_id,
                    "ERROR",
                    {"code": "BAD_FRAME", "message": "Invalid AUTH body"},
                    request_id,
                )
            ], False

        try:
            accepted = self.registry.authenticate_after_verified_udp(
                conn_id, username, password
            )
        except DuplicateLogin:
            return [
                (conn_id, "AUTH_FAIL", {"code": "ALREADY_LOGGED_IN"}, request_id)
            ], False
        except (InvalidTransition, SessionError):
            return [], False  # session expired/closed during slow password verification

        if not accepted:
            state.failed_auth += 1
            return [
                (conn_id, "AUTH_FAIL", {"code": "AUTH_FAILED"}, request_id)
            ], state.failed_auth >= MAX_AUTH_ATTEMPTS

        result: list[tuple[int, str, dict, int | None]] = [
            (conn_id, "AUTH_OK", {"username": username}, request_id),
            (conn_id, "USER_LIST", {"users": self.registry.list_online_users()}, None),
        ]
        # No presence signal for REGISTER; only ONLINE is public.
        for other in self.registry.list_online_users():
            if other != username:
                online = self.registry.find_online(other)
                if online is not None:
                    result.append(
                        (
                            online.conn_id,
                            "PRESENCE",
                            {"username": username, "status": "online"},
                            None,
                        )
                    )
        return result, False

    def on_session_closed(self, event: SessionClosedEvent) -> None:
        """Called by A's SOLE coordinator drain consumer, once per close event.
        Drops AUTH framing state and broadcasts offline presence if logged in.
        """
        self._drop_state(event.conn_id)
        if event.username is None:
            return
        for username in self.registry.list_online_users():
            online = self.registry.find_online(username)
            if online is not None:
                self._message(
                    online.conn_id,
                    "PRESENCE",
                    {"username": event.username, "status": "offline"},
                )
