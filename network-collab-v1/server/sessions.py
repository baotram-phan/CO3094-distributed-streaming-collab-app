"""Thread-safe session registry shared by TLS bootstrap and verified UDP."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
import secrets
import threading
import time
from typing import Callable

from server.auth import verify_password


class SessionState(str, Enum):
    BOOTSTRAPPED = "BOOTSTRAPPED"
    UDP_BOUND = "UDP_BOUND"
    ONLINE = "ONLINE"
    CLOSED = "CLOSED"


class SessionError(ValueError):
    """A session operation is not allowed."""


class UnknownSession(SessionError):
    pass


class SessionExpired(SessionError):
    pass


class InvalidTransition(SessionError):
    pass


class DuplicateLogin(SessionError):
    pass


class EndpointChanged(SessionError):
    pass


@dataclass(frozen=True, slots=True)
class Session:
    conn_id: int
    c2s_key: bytes = field(repr=False)
    s2c_key: bytes = field(repr=False)
    tcp_ip: str = ""
    state: SessionState = SessionState.BOOTSTRAPPED
    udp_endpoint: tuple[str, int] | None = None
    username: str | None = None
    created_at: float = 0.0
    last_activity_at: float = 0.0
    # First successful UDP REGISTER. NEVER refresh for repeat REGISTER or PING.
    udp_bound_at: float | None = None


@dataclass(frozen=True, slots=True)
class UDPBindResult:
    """Result of an atomic, verified REGISTER bind.

    newly_bound is True only for the FIRST successful BOOTSTRAPPED -> UDP_BOUND
    transition. Duplicate valid REGISTERs from the same endpoint yield False.
    Transport B uses this flag to emit on_udp_registered exactly once.
    """

    session: Session
    newly_bound: bool


@dataclass(frozen=True, slots=True)
class SessionClosedEvent:
    """Notification for B to dispose transport state, without secret keys."""

    conn_id: int
    reason: str
    username: str | None = None


class SessionRegistry:
    """Thread-safe state machine; no networking or crypto inside.

    After any operation that may close sessions, the application can call
    drain_closed_events() and ask B to remove the associated transport state.
    Never hold a transport lock while calling registry methods (or vice versa).
    """

    def __init__(
        self,
        *,
        bootstrap_timeout_s: float = 10.0,
        idle_timeout_s: float = 10.0,
        auth_timeout_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        password_verifier: Callable[[str, str], bool] = verify_password,
    ) -> None:
        if min(bootstrap_timeout_s, idle_timeout_s, auth_timeout_s) <= 0:
            raise ValueError("Timeout phải lớn hơn 0")
        self.bootstrap_timeout_s = float(bootstrap_timeout_s)
        self.idle_timeout_s = float(idle_timeout_s)
        self.auth_timeout_s = float(auth_timeout_s)
        self._clock = clock
        self._check_password = password_verifier
        self._sessions: dict[int, Session] = {}
        self._online_by_user: dict[str, int] = {}
        self._closed_events: deque[SessionClosedEvent] = deque()
        self._lock = threading.RLock()

    @staticmethod
    def _validate_endpoint(endpoint: tuple[str, int]) -> None:
        if (
            not isinstance(endpoint, tuple)
            or len(endpoint) != 2
            or not isinstance(endpoint[0], str)
            or not endpoint[0]
            or type(endpoint[1]) is not int
            or not 1 <= endpoint[1] <= 65535
        ):
            raise ValueError("Endpoint phải là (ip, port) hợp lệ")

    def create_bootstrap(
        self, *, tcp_ip: str, c2s_key: bytes, s2c_key: bytes
    ) -> Session:
        """Store session BEFORE HELLO_ACK, while it is still BOOTSTRAPPED."""
        if not isinstance(tcp_ip, str) or not tcp_ip:
            raise ValueError("Thiếu TCP peer IP")
        if not isinstance(c2s_key, bytes) or not isinstance(s2c_key, bytes):
            raise ValueError("Khóa phải là bytes")
        if len(c2s_key) != 32 or len(s2c_key) != 32 or c2s_key == s2c_key:
            raise ValueError("Cần hai khóa 32 bytes khác nhau")
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            for _ in range(64):
                conn_id = secrets.randbits(64)
                if conn_id and conn_id not in self._sessions:
                    break
            else:
                raise RuntimeError("Không thể cấp ConnID không trùng")
            now = self._clock()
            session = Session(
                conn_id=conn_id,
                c2s_key=c2s_key,
                s2c_key=s2c_key,
                tcp_ip=tcp_ip,
                created_at=now,
                last_activity_at=now,
            )
            self._sessions[conn_id] = session
            return session

    def get(self, conn_id: int) -> Session | None:
        """Return a snapshot or None. Expiry also emits a close event."""
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            return self._sessions.get(conn_id)

    def bind_udp_verified(self, conn_id: int, endpoint: tuple[str, int]) -> Session:
        """Backward-compatible REGISTER API returning only Session.

        New UDP code should prefer bind_udp_verified_with_status() to obtain an
        atomic newly_bound flag. Both methods enforce the same validations.
        """
        return self.bind_udp_verified_with_status(conn_id, endpoint).session

    def bind_udp_verified_with_status(
        self, conn_id: int, endpoint: tuple[str, int]
    ) -> UDPBindResult:
        """B calls AFTER AEAD verification and non-replay check (not commit).

        First REGISTER binds endpoint and returns newly_bound=True.
        Repeated REGISTERs from the SAME endpoint (with new authenticated
        packet numbers) return newly_bound=False; session is not recreated,
        state/udp_bound_at are not reset, ONLINE stays ONLINE.

        The check and update happen atomically under SessionRegistry's lock,
        avoiding a get()->bind() race between concurrent REGISTERs. B commits
        packet_number to its replay window ONLY after this call succeeds.
        """
        self._validate_endpoint(endpoint)
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.udp_endpoint is not None and session.udp_endpoint != endpoint:
                raise EndpointChanged("UDP endpoint changed; bootstrap again")
            if session.state not in (
                SessionState.BOOTSTRAPPED,
                SessionState.UDP_BOUND,
                SessionState.ONLINE,
            ):
                raise InvalidTransition("REGISTER không hợp lệ ở trạng thái này")
            now = self._clock()
            newly_bound = session.state is SessionState.BOOTSTRAPPED
            updated = replace(
                session,
                udp_endpoint=endpoint,
                state=SessionState.UDP_BOUND if newly_bound else session.state,
                last_activity_at=now,
                udp_bound_at=now if newly_bound else session.udp_bound_at,
            )
            self._sessions[conn_id] = updated
            return UDPBindResult(session=updated, newly_bound=newly_bound)

    def touch_verified_udp(self, conn_id: int, endpoint: tuple[str, int]) -> Session:
        """Refresh activity for a verified, non-replayed datagram from bound endpoint.

        Does not bind a new endpoint, change authentication state, or reset AUTH
        deadline. This method does NOT validate AES-GCM itself.
        """
        self._validate_endpoint(endpoint)
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.state not in (SessionState.UDP_BOUND, SessionState.ONLINE):
                raise InvalidTransition("Chưa REGISTER; không thể touch UDP")
            if session.udp_endpoint != endpoint:
                raise EndpointChanged("UDP endpoint khác endpoint đã đăng ký")
            updated = replace(session, last_activity_at=self._clock())
            self._sessions[conn_id] = updated
            return updated

    def authenticate_after_verified_udp(
        self, conn_id: int, username: str, password: str
    ) -> bool:
        """A only: password check after B delivers verified AUTH from control stream."""
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(password, str)
        ):
            return False
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.state is not SessionState.UDP_BOUND:
                raise InvalidTransition("AUTH chỉ được phép từ UDP_BOUND")
        # Expensive PBKDF2 does not run under the registry lock.
        if not self._check_password(username, password):
            return False
        with self._lock:
            # Re-check: session could have expired/closed while PBKDF2 ran.
            session = self._require_active_locked(conn_id)
            if session.state is not SessionState.UDP_BOUND:
                raise InvalidTransition("Phiên thay đổi trong khi kiểm tra mật khẩu")
            existing = self._online_by_user.get(username)
            if existing is not None and existing != conn_id:
                raise DuplicateLogin("Username đang online trong một phiên khác")
            updated = replace(
                session,
                state=SessionState.ONLINE,
                username=username,
                last_activity_at=self._clock(),
            )
            self._sessions[conn_id] = updated
            self._online_by_user[username] = conn_id
            return True

    def list_online_users(self) -> list[str]:
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            return sorted(self._online_by_user)

    def find_online(self, username: str) -> Session | None:
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            conn_id = self._online_by_user.get(username)
            return self._sessions.get(conn_id) if conn_id is not None else None

    def close(self, conn_id: int, *, reason: str = "closed") -> bool:
        """Close and notify transport cleanup; idempotent for unknown conn_id."""
        with self._lock:
            if conn_id not in self._sessions:
                return False
            self._remove_locked(conn_id, reason=reason)
            return True

    def cleanup_expired(self) -> list[int]:
        """Close timed-out sessions; return IDs for compatibility with A1.4."""
        with self._lock:
            return self._cleanup_expired_locked(self._clock())

    def drain_closed_events(self) -> list[SessionClosedEvent]:
        """Atomically drain notifications; call B cleanup OUTSIDE registry locks."""
        with self._lock:
            events = list(self._closed_events)
            self._closed_events.clear()
            return events

    def __len__(self) -> int:
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            return len(self._sessions)

    def _require_active_locked(self, conn_id: int) -> Session:
        session = self._sessions.get(conn_id)
        if session is None:
            raise UnknownSession("ConnID không tồn tại")
        reason = self._expiry_reason(session, self._clock())
        if reason is not None:
            self._remove_locked(conn_id, reason=reason)
            raise SessionExpired("Phiên đã hết hạn")
        return session

    def _expiry_reason(self, session: Session, now: float) -> str | None:
        if session.state is SessionState.BOOTSTRAPPED:
            return (
                "bootstrap_timeout"
                if now - session.created_at >= self.bootstrap_timeout_s
                else None
            )
        if session.state is SessionState.UDP_BOUND:
            # AUTH deadline is independent of keepalive and duplicate REGISTER.
            if session.udp_bound_at is None:
                return "invalid_unbound_session"
            if now - session.udp_bound_at >= self.auth_timeout_s:
                return "auth_timeout"
        if now - session.last_activity_at >= self.idle_timeout_s:
            return "idle_timeout"
        return None

    def _remove_locked(self, conn_id: int, *, reason: str) -> None:
        session = self._sessions.pop(conn_id)
        if session.username and self._online_by_user.get(session.username) == conn_id:
            del self._online_by_user[session.username]
        # Event deliberately contains no c2s_key/s2c_key.
        self._closed_events.append(
            SessionClosedEvent(conn_id, reason, session.username)
        )

    def _cleanup_expired_locked(self, now: float) -> list[int]:
        expired: list[int] = []
        for conn_id, session in list(self._sessions.items()):
            reason = self._expiry_reason(session, now)
            if reason is not None:
                self._remove_locked(conn_id, reason=reason)
                expired.append(conn_id)
        return expired
