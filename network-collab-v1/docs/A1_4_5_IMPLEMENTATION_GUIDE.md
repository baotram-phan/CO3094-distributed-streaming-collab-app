# A1.4.5 — Nâng cấp SessionRegistry chuẩn bị A1.5

**Dành cho:** Thành viên A (Windows PowerShell / Python).  
**Cơ sở:** A1.4 đã chạy 29/29 tests; Integration Contract A–B ngày 07/11/2026.  
**Giới hạn:** Chưa có UDP REGISTER thật hay AES-GCM trong patch này. B sẽ tích hợp sau.

## I. Ghép code an toàn

Sao lưu ba file cũ để có thể quay lại:

```powershell
Copy-Item .\server\sessions.py .\server\sessions.py.a14.bak
Copy-Item .\tests\test_sessions.py .\tests\test_sessions.py.a14.bak
Copy-Item .\examples\bootstrap_server.py .\examples\bootstrap_server.py.a14.bak
```

Giải nén ZIP patch và chép **nội dung** các thư mục `server`, `tests`, `examples`, `docs` vào thư mục gốc `network-collab-v1` (Windows sẽ hỏi thay thế ba file trùng tên). Giữ nguyên `config/users.json`, `server/auth.py`, `server/bootstrap.py`, `certs/`, code của B và mọi file khác.

Nếu dùng git, thực hiện kiểm tra trước khi commit:

```powershell
git status
git diff -- server/sessions.py tests/test_sessions.py examples/bootstrap_server.py
```

## II. Chạy tests

```powershell
python -m unittest tests.test_sessions -v
python -m unittest discover -s tests -v
```

Bộ patch ghép với đúng project gốc đã chạy **24/24** bài test trong `test_sessions.py`, tổng **40/40** (gồm 10 framing, 4 auth, 2 TLS, 24 session). Nếu máy bạn có thêm test riêng, số lượng khác là bình thường; mục tiêu là **tất cả đều PASS**.

Sau đó kiểm tra một lần bằng hai cửa sổ terminal (mới chỉ TCP/TLS bootstrap):

```powershell
python -m examples.bootstrap_server
```

Ở cửa sổ khác:

```powershell
python -m examples.bootstrap_client
```

Session BOOTSTRAPPED sẽ hết hạn sau 10 giây nếu không có UDP REGISTER. Log sẽ có `CLOSED ... reason=bootstrap_timeout`. Đây là hành vi đúng trong giai đoạn này.

## III. Các API quan trọng

`SessionRegistry.get(conn_id)` trả về `Session` snapshot (bất biến) hoặc `None`. Có thể lấy `c2s_key`, `s2c_key`, `state`, `udp_endpoint`, `created_at`, `last_activity_at`, `udp_bound_at`. **B tuyệt đối không đưa các khóa ra log.**

`registry.bind_udp_verified(conn_id, endpoint)` chỉ được B gọi **sau** khi UDP REGISTER vượt qua AES-GCM, anti-replay và kiểm tra packet. Lần đầu đặt `UDP_BOUND`, ghi endpoint và `udp_bound_at`; REGISTER lặp cùng endpoint không reset `udp_bound_at`, không tạo session/presence mới.

`registry.touch_verified_udp(conn_id, endpoint)` chỉ được B gọi sau datagram hợp lệ, đúng endpoint, không replay; chỉ được phép ở `UDP_BOUND`/`ONLINE`, cập nhật `last_activity_at`. Chưa REGISTER thì raise `InvalidTransition`; endpoint khác raise `EndpointChanged`.

`registry.authenticate_after_verified_udp(conn_id, username, password)` **chỉ A** gọi sau khi nhận AUTH được giải mã và sắp xếp đúng thứ tự từ control stream của B. Thành công -> `ONLINE`.

`registry.cleanup_expired()` xóa session quá hạn và trả về danh sách ConnID (giữ tương thích A1.4). Nhưng xóa còn có thể xảy ra gián tiếp qua `get()`, `__len__()`, kiểm tra AUTH, v.v. Vì vậy bổ sung:

```python
registry.cleanup_expired()
for event in registry.drain_closed_events():
    # Sau A1.5: giao cho B dọn transport state theo event.conn_id
    print(event.conn_id, event.reason)
```

`drain_closed_events()` trả về các `SessionClosedEvent(conn_id, reason, username)` và xóa chúng khỏi hàng đợi (mỗi lần xóa session phát một event). Callback sang B phải chạy **bên ngoài lock**. Demo bootstrap hiện mới in log; **chưa có B cleanup thật**.

`registry.close(conn_id, reason="logout")` vẫn trả bool như trước, đồng thời tạo event cho B. Gọi `close` nhiều lần không tạo thêm event.

## IV. Giải thích timeout

- `BOOTSTRAPPED`: 10 giây tính từ `created_at`, phải nhận REGISTER hợp lệ trước hạn.
- `UDP_BOUND`: đồng thời chịu **idle timeout 10 giây** từ `last_activity_at` và **AUTH deadline 30 giây** từ `udp_bound_at`; nếu chạm một trong hai thì đóng.
- `ONLINE`: idle timeout 10 giây; không còn ràng buộc 30 giây chưa AUTH.
- REGISTER lặp/PING hợp lệ làm mới `last_activity_at` nhưng không đổi `udp_bound_at`; không thể giữ mãi session chưa login.
- 2 giây PING interval thuộc **B**, không phải code SessionRegistry. Phiên chỉ được touch khi gói nhận thực sự hợp lệ và đúng endpoint.

Các thời điểm dùng `time.monotonic()` để tính khoảng thời gian, không dùng `time.time()`. Test dùng `FakeClock` và không cần `sleep(30)`.

## V. Ngoại lệ cho B

- `get()` -> `None` với ConnID không tồn tại/hết hạn.
- `bind_udp_verified()` -> `UnknownSession`, `SessionExpired`, `EndpointChanged`, `ValueError`.
- `touch_verified_udp()` -> `UnknownSession`, `SessionExpired`, `InvalidTransition`, `EndpointChanged`, `ValueError`.
- Nếu B giữ snapshot rồi phiên bị A đóng trong lúc B xác thực AES-GCM, lệnh bind/touch có thể từ chối. **B phải bỏ datagram** thay vì cố tạo session lại.

**A1.5 sau này:** server TCP bootstrap và UDP listener phải chia sẻ **cùng một instance `SessionRegistry` trong cùng tiến trình**. Hai chương trình chạy riêng với hai registry trong RAM không thể tích hợp.

## VI. Tương tác khi B nhận REGISTER

```python
# MINH HỌA RANH GIỚI TÍCH HỢP, CHƯA PHẢI CODE UDP HOÀN CHỈNH
from server.sessions import SessionError

session = registry.get(conn_id)
if session is None:
    return  # không có khóa/phiên hợp lệ

# B thực hiện kiểm tra định dạng / chống replay / AES-GCM
# bằng session.c2s_key, body REGISTER rỗng, endpoint thực.
if not verified_udp_packet:
    return

try:
    session = registry.bind_udp_verified(conn_id, remote_endpoint)
except SessionError:
    return

# B đánh dấu replay state theo quy tắc transport và gửi REGISTER_OK
# bằng session.s2c_key, packet_number mới. Không gọi AUTH ở đây.
```

**Lưu ý quan trọng:** snippet chỉ mô tả trách nhiệm. Việc cập nhật replay state và gọi `bind` cần được B phối hợp đồng bộ theo interface đã chốt, để không chấp nhận packet trùng, kể cả khi có nhiều worker.

## VII. Tiêu chí A1.4.5 hoàn tất

1. Có `udp_bound_at`, `touch_verified_udp`, idle timeout 10s và AUTH deadline 30s.
2. Duplicate REGISTER không gia hạn AUTH và không đổi endpoint.
3. `get()` tự xóa hết hạn **không làm mất thông báo cleanup**.
4. Tất cả unit tests cũ và mới PASS.
5. Đã gửi cho B chữ ký API, các trường trong `Session` và quy tắc cleanup để đối chiếu.

**Chưa được coi là xong A1.5:** chưa có UDP socket thật, REGISTER_OK AES-GCM thật, replay window thật hay UDP AUTH thật.
