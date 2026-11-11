# A1.5 — Đồng bộ project A/B từ ZIP bạn đã gửi (10/11/2026)

## Kết quả kiểm tra trên ZIP được gửi

- Trước sửa: **88/88** bài test hiện có PASS trong môi trường Python 3.13.5.
- `common/udp_packet.py` **đã có** `encode_packet` và `decode_packet`; lỗi import từ lần trước **không tái hiện** trong ZIP mới.
- `client/core/udp_connection.py` là skeleton 5 dòng, chưa chạy được.
- Thiếu `examples/a1_5_official_client.py`.
- `server/main.py` đã dùng cùng `SessionRegistry` cho TLS và UDP; `server/udp_service.py` đã có lifecycle fix.
- `requirements.txt` trước đó chưa khai báo dependency cần cho AES-GCM và certificate generation.

## Những file sửa/thêm (patch nhỏ)

1. `client/core/udp_connection.py`: triển khai `UDPRegistrationClient`, sử dụng packet/crypto/TransportConnectionState của B, không dùng reference codec.
2. `examples/a1_5_official_client.py`: demo TLS HELLO → UDP REGISTER → REGISTER_OK.
3. `tests/test_a1_5_official_client.py`: integration tests và regression tests mới.
4. `requirements.txt`: khai báo dependency `cryptography>=42`.
5. `docs/A1_5_USER_SYNC_FIX_GUIDE.md`: tài liệu này.

**Không sửa/ghi đè** `common/udp_packet.py`, `common/crypto.py`, `server/udp_service.py`, `server/main.py`, `server/sessions.py` hoặc manager của B.

## Cách áp dụng vào project đang có

Từ PowerShell tại thư mục `network-collab-v1`:

```powershell
git status
# Chỉ thực hiện nếu working tree sạch hoặc đã backup/commit.
# Giải nén ZIP bản vá *patch*, không phải toàn bộ project, tại thư mục gốc.
python -c "import zipfile; zipfile.ZipFile('A1_5_Client_Sync_patch.zip').extractall('.')"
python -m pip install -r requirements.txt
# Chỉ với bản project đã lọc, nếu thiếu config/users.json:
# python -m scripts.create_test_users
python -m unittest tests.test_a1_5_official_client -v
python -m unittest tests.test_a1_5_lifecycle_contract -v
python -m unittest discover -s tests -v
```

File ZIP patch phải được đặt trực tiếp trong thư mục gốc trước khi chạy lệnh. Nếu giải nén bằng Explorer/7-Zip, sao chép các file theo đúng thư mục con tương ứng.

## Chạy localhost với **hai terminal**

Nếu chưa có `certs/server.crt` và `certs/server.key`, tạo với:

```powershell
python -m scripts.gen_cert
```

Terminal 1:

```powershell
python -m server.main
```

Terminal 2:

```powershell
python -m examples.a1_5_official_client
```

Kết quả mong đợi: client xác thực `REGISTER_OK` và in `A1.5 UDP_BOUND OK`; server báo `REGISTER_OK ... state=UDP_BOUND`. ConnID và port ngẫu nhiên sẽ khác nhau mỗi lần.

**Lưu ý với ZIP project đầy đủ đã lọc:** Để bảo vệ dữ liệu, bản ZIP không chứa `config/users.json` và `certs/server.key`/`server.crt`. Nếu bạn giải nén thành **thư mục project mới**, trước khi chạy toàn bộ tests cần tạo tài khoản thử bằng `python -m scripts.create_test_users` (chỉ khi chưa có `config/users.json`) và tạo chứng chỉ bằng `python -m scripts.gen_cert`. Nếu bạn chỉ áp dụng patch nhỏ vào project đang có thì giữ nguyên các file cấu hình trên máy, không cần tạo lại.

Nếu thử LAN, server chạy `--host 0.0.0.0`, tạo chứng chỉ có SAN IP LAN với `python -m scripts.gen_cert --force --san-ip <IP_THỰC>`; client truyền `--host <IP_THỰC> --trust <đường_dẫn_server.crt>`. **Không chia sẻ `server.key`.** `--force` thay chứng chỉ đang có, yêu cầu client cập nhật bản được tin cậy.

## Deadline / retry đã triển khai

- Tối đa **10 lần** gửi UDP REGISTER.
- Mỗi lần chờ tối đa **500 ms**, dùng cùng socket/endpoint và **packet number mới**.
- Bỏ qua gói sai endpoint/ConnID/loại packet, kiểm tra anti-replay và AES-GCM với `s2c_key`.
- CLI đo `time.monotonic()` **trước TLS bootstrap**, cấp `bootstrap_deadline = started + 10 s`; do đó không thử REGISTER sau deadline 10 giây của server trong điều kiện thời gian xử lý bình thường.
- Nếu dùng `UDPRegistrationClient` độc lập mà *không* truyền `bootstrap_deadline`, nó chỉ giới hạn 10 giây từ lúc khởi tạo object, **không biết được thời gian TLS đã trôi qua**. Nên luôn truyền deadline từ trước bootstrap để tuân thủ chặt chẽ protocol.
- `registered` hiện đánh dấu đã nhận `REGISTER_OK` xác thực; chưa có client session state machine hoàn chỉnh, AUTH, heartbeat hay reliable streams.
- A1.6 cần **giữ lại socket + `TransportConnectionState`**, không được tái sử dụng packet numbers với cùng khóa.

## Phân chia trách nhiệm

- File `client/core/udp_connection.py` về lâu dài do **B** sở hữu. Đây là bản kết nối tạm thời để project chạy được; B cần review trước khi merge và tiếp tục mở rộng thành reliable UDP transport.
- `server/main.py`, close-event coordinator, SessionRegistry do **A** phụ trách.
- Callback hiện đang dùng `on_udp_registered(conn_id, endpoint)` theo lifecycle addendum, nhưng cần A và B xác nhận trong contract cuối cùng. Đừng thay ngầm thành chữ ký một hoặc ba tham số.

## Lưu ý bảo mật / source ZIP đầy đủ

ZIP người dùng cung cấp chứa `certs/server.key` (khóa riêng TLS) và `config/users.json`. **ZIP project đã đồng bộ được đóng gói gửi lại sẽ bỏ hai file này** cùng các `__pycache__` để tránh vô tình phát tán dữ liệu. Trên máy của bạn, giữ nguyên hai file cũ nếu dùng tiếp; khi chia sẻ code cho B, không gửi khóa riêng hoặc dữ liệu tài khoản thật. Nếu lấy bản project đã lọc và chưa có chứng chỉ, chạy `python -m scripts.gen_cert` trước khi chạy server.
