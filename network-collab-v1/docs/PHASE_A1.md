# Giai đoạn A1 — Foundation & Authentication (bắt đầu từ đây)

**Đầu ra mong muốn**: chương trình thật có thể TCP/TLS HELLO → cấp ConnID/keys →
UDP REGISTER → UDP AUTH → AUTH_OK/FAIL; cùng ít nhất hai client đăng nhập.
Trong quá trình học làm từng lớp, **không** gửi password qua TCP/UDP plaintext.

## Bước 0 — Khởi động lại code đã có
1. Mở sườn trong VS Code. `python -m unittest discover -s tests -v` → 10 tests framing.
2. Mở 2 terminals chạy `python -m examples.demo_server` rồi `python -m examples.demo_client`.
3. Nhớ: đây là demo cũ chỉ HELLO/ACK, không phải security/login thực.

## Bước 1 — Chuyển phần auth từ project cũ
1. So sánh và chép `scripts/create_test_users.py` từ project cũ sang.
2. Chép `server/auth.py` chứa `verify_password` nếu đã viết.
3. Chép `config/users.json` đã tạo ở máy (không đưa vào Git).
4. Chép `tests/test_auth.py` đã có, chạy `python -m unittest discover -s tests -v`.
5. Nếu chưa làm `auth.py`, hãy học/viết nó từ đầu; không xem placeholder là đã xong.

## Bước 2 — Thiết lập TLS cho bootstrap (A)
1. Lựa chọn cert tin cậy cho demo, tạo bằng tool riêng (không commit private key).
2. Viết `server/bootstrap.py` dùng `ssl.SSLContext` và `common/control_framing.py`.
3. Client **xác thực** server certificate; từ chối certificate không tin cậy.
4. Sau TLS, HELLO/HELLO_ACK cấp ConnID và hai khóa UDP riêng cho hai chiều.
5. Thêm `tests/test_bootstrap.py`.

## Bước 3 — Sessions và tích hợp B (A+B)
1. A viết `server/sessions.py`: BOOTSTRAPPED → UDP_BOUND → ONLINE → CLOSED.
2. B viết packet AES-GCM + REGISTER/REGISTER_OK, API nhận event vào session.
3. A xử lý AUTH **chỉ qua UDP đã mã hóa**.
4. Thử hai user đăng nhập, logout/disconnect, user-list cập nhật.

## Điều kiện kết thúc A1
- TLS bootstrap hoạt động, cert sai bị từ chối.
- Cấp conn_id và khóa qua TLS, không log bí mật.
- UDP REGISTER xác minh được khóa; timeout bootstrap đúng.
- Login thành công/sai mật khẩu phân biệt, session lưu địa chỉ UDP đúng.
- Hai client ONLINE đồng thời; user-list đúng.
- Các module có unit/integration tests.

> A1 có phần cần B tích hợp để hoàn thiện. Trong lúc chờ B, A dùng fake transport để kiểm thử `auth.py` và `sessions.py` độc lập.
