# Network Collaboration

Ứng dụng Python client–server: đăng nhập, danh sách online, chat riêng/chat chung và truyền file 1–1 qua server. Giao diện trình duyệt kết nối đến HTTP Bridge trên máy client.

## Kiến trúc đang chạy

- **TCP/TLS, cổng 9000:** bootstrap, cấp ConnID và hai khóa UDP.
- **Reliable UDP, cổng 9001:** REGISTER, AUTH, chat, file; AES-256-GCM, ACK, retransmission, flow control, CUBIC và heartbeat.
- **HTTP Bridge, mặc định cổng 8000:** phục vụ GUI tại `127.0.0.1`; mỗi tiến trình Bridge quản lý một client.
- Stream 0: điều khiển; stream 1: chat; stream từ 2 trở lên: file với ID cấp mới cho từng lượt.

Broadcast ứng dụng được server gửi đến các client online, không phải IP broadcast trên LAN. File tối đa **50 MiB**, xác minh bằng SHA-256; một lượt truyền đang hoạt động cho mỗi phía, cho phép nhiều lượt tuần tự.

## Cài đặt

Dùng Python 3.12, mở terminal tại thư mục chứa README này:

```powershell
python -m pip install -r requirements.txt
```

Giữ tài khoản/chứng chỉ hiện có. **Chỉ chạy lệnh tạo dữ liệu nếu thiếu file tương ứng:**

```powershell
# Chỉ khi chưa có config/users.json; script tạo lại toàn bộ tài khoản mẫu.
python -m scripts.create_test_users

# Chỉ khi chưa có cặp chứng chỉ/khóa TLS.
python -m scripts.gen_cert
```

Tài khoản do script mẫu tạo: `an / an123456`, `binh / binh123456`, `chi / chi123456`. Nếu bạn đã sửa tài khoản thì dùng dữ liệu của bạn.

## Chạy nhiều cửa sổ terminal

Mỗi lệnh dưới đây chạy trong **một terminal riêng**, cùng thư mục project:

```powershell
python -m server.main
```

```powershell
python -m client.bridge.http_server --port 8000
```

```powershell
python -m client.bridge.http_server --port 8001
```

```powershell
python -m client.bridge.http_server --port 8002
```

Mở `http://127.0.0.1:8000`, `http://127.0.0.1:8001`, `http://127.0.0.1:8002` và đăng nhập ba tài khoản khác nhau. Nhiều tab trên cùng một cổng dùng chung một Bridge, không phải nhiều client độc lập.

Có thể dùng client terminal thay GUI:

```powershell
python -m client.main --user an
```

Nhập mật khẩu khi được hỏi. Lệnh chat: `/to binh Xin chào`, `/all Chào mọi người`, `/quit`. Dừng server/Bridge bằng `Ctrl+C`.

## Kiểm thử

```powershell
python -m scripts.run_all_tests
```

Runner dùng tài khoản tạm, không ghi đè `config/users.json`. Xem [hướng dẫn kiểm thử và demo](docs/TESTING.md) để kiểm tra nhiều client, đăng nhập trùng, file và mất kết nối.

Trên Windows có một số test được đánh dấu SKIP có lý do. `OK (skipped=N)` chỉ xác nhận các test đã chạy; không tính N test bị bỏ qua là PASS.

## Cấu trúc mã nguồn

| Thư mục | Vai trò |
|---|---|
| `server/` | Bootstrap, quản lý phiên, AUTH, routing, relay file và UDP server |
| `client/core/` | Client session, transport UDP, framing ứng dụng |
| `client/bridge/` | HTTP localhost và điều phối lệnh/sự kiện GUI |
| `client/ui/` | HTML, CSS, JavaScript |
| `common/` | Codec, crypto, streams, ACK/RTO, scheduling và CUBIC |
| `scripts/` | Tạo chứng chỉ, tài khoản mẫu, chạy tests |
| `tests/` | Unit và integration tests |
| `examples/` | Bootstrap dùng bởi runtime và các ví dụ phục vụ tests |
| `config/`, `certs/` | Tài khoản và cấu hình TLS cục bộ |

Một số tên module/test vẫn chứa A1.x hoặc B4.x để giữ tương thích import. Không xóa `examples/`: `client/core/session.py` còn sử dụng `examples/bootstrap_client.py`.

## Phạm vi và tài liệu

- [Kiến trúc và luồng xử lý](docs/ARCHITECTURE.md)
- [Kiểm thử và demo](docs/TESTING.md)
- [Trích yếu giải đáp đề bài](docs/teacher_clarifications.md)

Phiên mất kết nối cần đăng nhập lại; chưa có tự reconnect hoặc resume file xuyên phiên. Không có lịch sử chat lưu bền vững trên server. `CHAT_ACCEPTED` là xác nhận xếp hàng, không phải đã đọc. Chạy localhost không thay thế chứng cứ kiểm thử LAN hoặc truyền file 50 MiB dưới mất gói.

## Định dạng mã nguồn

Python được định dạng bằng Black 25.1.0; JavaScript bằng Prettier 3.5.3. Đây là công cụ phát triển, không phải dependency chạy ứng dụng. Không đổi tên module, API, message body hay thứ tự xử lý để làm đẹp code.

```powershell
python -m pip install -r requirements-dev.txt
python -m black --check .
```
