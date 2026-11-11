# INTEGRATION CONTRACT A–B — v1.1-review (2026-11-07)

> **Trạng thái:** A đã hiện thực phần `SessionRegistry` dưới đây và kiểm thử trên bản sao project; **chờ B kiểm tra trước khi đổi sang approved**. B chưa gửi source transport để kiểm thử trực tiếp. Tài liệu này cập nhật v1.0-review, **không thay thế các quy định on-wire** đã thống nhất.

## 1. Ranh giới module

- **A:** TLS bootstrap, `SessionRegistry`, authentication/presence, routing/file logic, UI, **thuật toán CUBIC + test/đồ thị**, network simulator.
- **B:** UDP socket/codec/AES-GCM, packet number/anti-replay, ACK/retransmission, stream multiplexing/flow control, `bytes_in_flight`, heartbeat, transport state; B **tích hợp controller CUBIC của A**.
- **Cùng một tiến trình server dùng một instance** `SessionRegistry`. Không sao chép registry cho UDP server.

## 2. Session snapshot và API đang có trong code

```python
from server.sessions import (
    SessionRegistry, Session, SessionState, UDPBindResult, SessionClosedEvent,
    SessionError, UnknownSession, SessionExpired, InvalidTransition,
    DuplicateLogin, EndpointChanged,
)

snapshot: Session | None = registry.get(conn_id)
# Session dataclass frozen=True, slots=True; fields:
# conn_id: int (u64)
# c2s_key: bytes (32); s2c_key: bytes (32)
# tcp_ip: str
# state: SessionState (BOOTSTRAPPED, UDP_BOUND, ONLINE, CLOSED [logic only])
# udp_endpoint: tuple[str, int] | None
# username: str | None
# created_at: float; last_activity_at: float; udp_bound_at: float | None
```

Khóa do server giữ dưới dạng **bytes**; phía client giải mã Base64 HELLO_ACK thành bytes trước khi gọi transport. `get` trả `None` nếu không có/hết hạn. `get` có thể xóa những session hết hạn (và **phát `SessionClosedEvent`**) nên không được giữ snapshot làm nguồn chân lý lâu dài.

### Chữ ký API A cung cấp

```python
registry.get(conn_id: int) -> Session | None
registry.bind_udp_verified(conn_id: int, endpoint: tuple[str, int]) -> Session
registry.bind_udp_verified_with_status(conn_id: int, endpoint: tuple[str, int]) -> UDPBindResult
registry.touch_verified_udp(conn_id: int, endpoint: tuple[str, int]) -> Session
registry.authenticate_after_verified_udp(conn_id: int, username: str, password: str) -> bool
registry.close(conn_id: int, *, reason: str = "closed") -> bool
registry.cleanup_expired() -> list[int]
registry.drain_closed_events() -> list[SessionClosedEvent]
registry.list_online_users() -> list[str]
registry.find_online(username: str) -> Session | None
```

**Ưu tiên B dùng API MỚI:**

```python
bind_result = registry.bind_udp_verified_with_status(conn_id, (src_ip, src_port))
session = bind_result.session            # Session snapshot mới nhất
if bind_result.newly_bound:
    on_udp_registered(conn_id)           # phát một lần / session
# Mọi REGISTER hợp lệ đều được gửi REGISTER_OK mới, dù newly_bound False.
```

`UDPBindResult` là dataclass bất biến gồm `session: Session`, `newly_bound: bool`. Hàm cũ `bind_udp_verified` vẫn trả `Session` để tương thích A1.4/A1.5 reference. `newly_bound=True` **chỉ đúng khi transition BOOTSTRAPPED→UDP_BOUND đầu tiên**, được tính và cập nhật nguyên tử dưới `RLock`. REGISTER từ endpoint cũ khi `ONLINE` vẫn hợp lệ, giữ `ONLINE` và `udp_bound_at` cũ, `newly_bound=False`.

`touch_verified_udp` chỉ cập nhật `last_activity_at` sau khi B đã xác thực datagram, chống replay và đảm bảo endpoint đúng; **không** thay `udp_bound_at` hay gia hạn AUTH deadline.

### Ngoại lệ: bắt và xử lý thế nào

| Exception (đều từ `server.sessions`) | Ý nghĩa | Xử lý của B |
|---|---|---|
| `UnknownSession(SessionError)` | ConnID không tồn tại hoặc đã bị dọn | Drop; clear transport state nếu đã có |
| `SessionExpired(SessionError)` | Đang truy cập phiên vừa vượt deadline và chưa bị dọn | Drop; A phát close event; clear transport state |
| `EndpointChanged(SessionError)` | IP/port mới không phải endpoint đã bind | Drop; không tự rebinding |
| `InvalidTransition(SessionError)` | Gọi sai state, ví dụ touch trước REGISTER | Drop hoặc thông báo nội bộ cho A |
| `DuplicateLogin(SessionError)` | Username đã ONLINE trên session khác | A xử lý ở AUTH; B không kiểm tra username |
| `ValueError` | Endpoint không phải tuple `(ip, port)` hợp lệ | Drop, không làm crash UDP loop |

`SessionError` kế thừa `ValueError`, nên B có thể bắt gộp `(SessionError, ValueError)` sau khi log an toàn. **`get()` trả None, không raise** (nếu phiên hết hạn đã dọn bởi `get`, bind sau đó có thể raise `UnknownSession`, không nhất thiết `SessionExpired`). B không log khóa, password hoặc plaintext payload.

## 3. REGISTER + AES-GCM + anti-replay — thứ tự CHỐT

Wire format B xác nhận: `!HBBQQ` (header 20 bytes, magic `0x4E43`, version=1, type `0x01 REGISTER` / `0x02 REGISTER_OK`, ConnID u64, pkt_num u64), header là AES-GCM AAD; nonce `00000000 || pkt_num:u64big`; tag 16; REGISTER và REGISTER_OK rỗng = 36 bytes; datagram tối đa 1200 bytes. Mỗi chiều quản lý packet number độc lập; retransmission dùng packet number mới.

**B xử lý REGISTER theo thứ tự:**

1. Parse header, validate version/type/size. `session = registry.get(conn_id)`. Nếu None, bỏ gói.
2. **Peek anti-replay không commit**: packet number phải chưa nhận và trong cửa sổ. B phải bảo đảm `check → decrypt → bind → commit` được xử lý **tuần tự cho cùng conn_id** (ví dụ UDP event loop một worker/ConnID hoặc cơ chế đồng bộ tương đương), tránh hai thread cùng chấp nhận packet number giống nhau.
3. Giải mã AES-GCM bằng `session.c2s_key`, nonce và header AAD. REGISTER body phải rỗng.
4. Gọi `registry.bind_udp_verified_with_status(conn_id, endpoint)`; nếu registry từ chối, **không commit** packet number.
5. Chỉ sau khi bind thành công, **commit packet number** vào replay state. Từ `newly_bound` quyết định có phát `on_udp_registered` hay không.
6. Tạo `REGISTER_OK` với pkt_num mới phía server, mã hóa bằng `session.s2c_key`, gửi lại endpoint đã bind. REGISTER lặp hợp lệ vẫn trả OK; không tạo session, không phát sự kiện online/presence.

**Lưu ý deadlock:** `SessionRegistry` không gọi transport khi giữ RLock; coordinator phải đặt quy tắc thứ tự lock rõ ràng. Khuyến nghị UDP handler **xử lý tuần tự mỗi conn_id**, không giữ một transport-global-lock khi gọi Registry hoặc application callback. Không dùng `newly_bound` lấy từ snapshot `get()` trước `bind`, vì khi hai gói đến đồng thời sẽ race.

## 4. Timeout, heartbeat, cleanup

- Bootstrap: **10 s** từ `created_at`.
- UDP idle: **10 s** kể từ `last_activity_at` ở `UDP_BOUND`/`ONLINE`.
- AUTH: **30 s** kể từ `udp_bound_at` lần REGISTER đầu tiên, chỉ khi còn `UDP_BOUND`.
- Heartbeat: **2 s**. REGISTER lặp và PING hợp lệ có thể refresh idle, nhưng không kéo dài AUTH deadline.
- Không rebinding endpoint v1: thay đổi IP/port phải bootstrap lại.

`registry.close(...)` hoặc expiry sẽ enqueue `SessionClosedEvent(conn_id, reason, username)`, không chứa khóa. Dùng **một consumer do A chủ trì** gọi định kỳ:

```python
registry.cleanup_expired()
for event in registry.drain_closed_events():
    transport.remove_connection(event.conn_id)  # tên API B xác nhận khi tích hợp
    # A cũng xử lý presence/user offline nếu event.username is not None
```

Đây mới là **hợp đồng dispatch**, chưa phải worker cleanup chính thức. Không để cả A và B cùng drain queue (mất sự kiện). Hàm remove B cần idempotent, và callback `on_transport_failed` từ B phải báo A để A close session; tránh gọi vòng lặp vô hạn. `get()` có thể làm expire và phát event nên consumer cần chạy đều, không chỉ khi `cleanup_expired` trả danh sách có phần tử.

## 5. AUTH và các phần chưa code

Sau REGISTER_OK: B chuyển reliable DATA trên control stream 0 (stream offset + reassembly, application length-prefixed JSON), A parse AUTH, kiểm tra PBKDF2 và `authenticate_after_verified_udp`, trả AUTH_OK/FAIL, xử lý ONLINE/presence. **Không gọi AUTH sau khi chỉ nhận REGISTER, chưa có reliability layer.**

A1.5 reference (nằm ở `examples/`) là demo *khác* code thật của B. B cần thay demo fixed ConnID/keys bằng phiên thật; không đưa adapter tham chiếu vào transport production.

## 6. Điều kiện kiểm thử và chốt duyệt

- A1.4.5: 40 tests đã được bạn xác nhận PASS; patch cập nhật thêm test cho `newly_bound`, concurrency, AUTH deadline, cleanup.
- Trên bản testbed mẫu A1.5 + patch này: **54/54 tests PASS** (bao gồm 7 test UDP reference), **không thay thế test 24 bài của B**.
- B kiểm tra bằng source thật: TLS Bootstrap → REGISTER encrypted → REGISTER_OK → UDP_BOUND, duplicate packet replay drop, REGISTER lặp pkt_num mới trả OK không phát event; bad tag, wrong endpoint, timeout drop, cleanup transport state.
- CUBIC: A code controller + test/plots; B tích hợp với ACK/loss và quản lý `bytes_in_flight`. Cần thống nhất interface trước khi làm transport production.

**Status:** `v1.1-review` — B xác nhận chữ ký API và các thứ tự xử lý thì mới đổi thành `approved`.
