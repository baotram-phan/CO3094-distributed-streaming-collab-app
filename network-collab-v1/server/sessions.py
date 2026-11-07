"""A1.4 — phiên kết nối trên server (chưa tự mở UDP socket).

Luồng: BOOTSTRAPPED -> UDP_BOUND -> ONLINE -> CLOSED.

Ranh giới bảo mật rất quan trọng:
- bind_udp_verified() CHỈ được gọi sau khi tầng UDP của B xác thực AES-GCM,
  kiểm tra packet number/anti-replay và biết chính xác conn_id hợp lệ.
- authenticate_after_verified_udp() CHỈ được gọi với nội dung AUTH được giải mã,
  xác thực qua UDP; hàm tự kiểm tra password thực tế.
- Chỉ biết ConnID hoặc địa chỉ IP/port KHÔNG đủ để đăng ký/đăng nhập.

Các bản ghi Session bất biến (frozen) để caller không vô tình sửa registry.
RLock cho phép nhiều thread cùng thêm/đọc/đóng phiên.
"""
from __future__ import annotations

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
    """Hành động không hợp lệ đối với phiên."""


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


class SessionRegistry:
    """Kho phiên trong RAM. Không có network I/O; có thể unit-test độc lập.

    Tham số `clock` hỗ trợ test thời gian không cần sleep().
    `password_verifier` mặc định dùng server.auth.verify_password().
    """

    def __init__(
        self,
        *,
        bootstrap_timeout_s: float = 10.0,
        idle_timeout_s: float = 15.0,
        clock: Callable[[], float] = time.monotonic,
        password_verifier: Callable[[str, str], bool] = verify_password,
    ) -> None:
        if bootstrap_timeout_s <= 0 or idle_timeout_s <= 0:
            raise ValueError("Timeout phải lớn hơn 0")
        self.bootstrap_timeout_s = float(bootstrap_timeout_s)
        self.idle_timeout_s = float(idle_timeout_s)
        self._clock = clock
        self._check_password = password_verifier
        self._sessions: dict[int, Session] = {}
        self._online_by_user: dict[str, int] = {}
        self._lock = threading.RLock()

    def create_bootstrap(self, *, tcp_ip: str, c2s_key: bytes, s2c_key: bytes) -> Session:
        """Đặt phiên BOOTSTRAPPED vào registry TRƯỚC khi gửi HELLO_ACK.

        Nhờ đó gói UDP đầu tiên không thể tới trước khi server ghi nhận ConnID.
        """
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
        """Lấy snapshot phiên còn hiệu lực; không trả khóa qua log/UI."""
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            return self._sessions.get(conn_id)

    def bind_udp_verified(self, conn_id: int, endpoint: tuple[str, int]) -> Session:
        """RANH GIỚI TIN CẬY: chỉ UDP transport đã verify AEAD/anti-replay được gọi.

        Lần đầu BOOTSTRAPPED -> UDP_BOUND. Những gói đã xác thực tiếp theo cập nhật
        last_activity. Không tự động cho phép chuyển UDP endpoint giữa chừng.
        """
        if (not isinstance(endpoint, tuple) or len(endpoint) != 2
                or not isinstance(endpoint[0], str) or not endpoint[0]
                or type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
            raise ValueError("Endpoint phải là (ip, port) hợp lệ")
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.udp_endpoint is not None and session.udp_endpoint != endpoint:
                raise EndpointChanged("Đổi UDP endpoint cần flow rebind được xác thực riêng")
            state = SessionState.UDP_BOUND if session.state is SessionState.BOOTSTRAPPED else session.state
            updated = replace(session, udp_endpoint=endpoint, state=state,
                              last_activity_at=self._clock())
            self._sessions[conn_id] = updated
            return updated

    def authenticate_after_verified_udp(self, conn_id: int, username: str, password: str) -> bool:
        """Kiểm tra mật khẩu thật; chỉ sau khi UDP đã bind + AUTH đã xác thực AEAD.

        True: BOOTSTRAPPED -> UDP_BOUND -> ONLINE hợp lệ.
        False: sai thông tin đăng nhập; vẫn UDP_BOUND.
        Tránh giữ lock trong lúc PBKDF2 (có thể chậm).
        """
        if not isinstance(username, str) or not username or not isinstance(password, str):
            return False
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.state is not SessionState.UDP_BOUND:
                raise InvalidTransition("AUTH chỉ được phép từ UDP_BOUND")
        if not self._check_password(username, password):
            return False
        with self._lock:
            session = self._require_active_locked(conn_id)
            if session.state is not SessionState.UDP_BOUND:
                raise InvalidTransition("Phiên thay đổi trong khi kiểm tra mật khẩu")
            existing = self._online_by_user.get(username)
            if existing is not None and existing != conn_id:
                raise DuplicateLogin("Username đang online trong một phiên khác")
            updated = replace(session, state=SessionState.ONLINE,
                              username=username, last_activity_at=self._clock())
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

    def close(self, conn_id: int) -> bool:
        """Đóng và xóa phiên; trả False nếu phiên không tồn tại."""
        with self._lock:
            if conn_id not in self._sessions:
                return False
            self._remove_locked(conn_id)
            return True

    def cleanup_expired(self) -> list[int]:
        """Xóa bootstrap chưa đăng ký và phiên UDP im lặng quá lâu."""
        with self._lock:
            return self._cleanup_expired_locked(self._clock())

    def __len__(self) -> int:
        with self._lock:
            self._cleanup_expired_locked(self._clock())
            return len(self._sessions)

    def _require_active_locked(self, conn_id: int) -> Session:
        now = self._clock()
        session = self._sessions.get(conn_id)
        if session is None:
            raise UnknownSession("ConnID không tồn tại")
        if self._expired(session, now):
            self._remove_locked(conn_id)
            raise SessionExpired("Phiên đã hết hạn")
        return session

    def _expired(self, session: Session, now: float) -> bool:
        if session.state is SessionState.BOOTSTRAPPED:
            return (now - session.created_at) >= self.bootstrap_timeout_s
        return (now - session.last_activity_at) >= self.idle_timeout_s

    def _remove_locked(self, conn_id: int) -> None:
        session = self._sessions.pop(conn_id)
        if session.username and self._online_by_user.get(session.username) == conn_id:
            del self._online_by_user[session.username]
        # CLOSED là trạng thái logic sau khi xóa, không giữ key trong registry.

    def _cleanup_expired_locked(self, now: float) -> list[int]:
        expired = [conn_id for conn_id, session in self._sessions.items()
                   if self._expired(session, now)]
        for conn_id in expired:
            self._remove_locked(conn_id)
        return expired
