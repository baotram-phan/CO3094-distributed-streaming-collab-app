# Network Collaboration — Python Client–Server Application

> **Trạng thái (07/11/2026):** Thành viên A đã hoàn thiện phần nền tảng **A1.1–A1.4** (setup, authentication, TCP/TLS bootstrap, session management). **Chưa có chat hoặc truyền file end-to-end**; UDP Registration và UDP Authentication đang chờ tích hợp với thành viên B.

Dự án xây dựng ứng dụng cộng tác Client–Server phục vụ đăng nhập, quản lý người dùng trực tuyến, nhắn tin cá nhân/nhóm và truyền file 1-1. Phần mạng cốt lõi dùng Python `socket` và giao thức do nhóm tự thiết kế. Đây là dự án đang phát triển, không phải ứng dụng hoàn chỉnh.

## 1. Kiến trúc dự kiến

```text
Browser (HTML/CSS/JS)
        |
  Local HTTP / SSE                 [Chưa triển khai]
        |
   Python Client
        | TCP + TLS: bootstrap (HELLO / HELLO_ACK, ConnID, UDP keys)
        | UDP: REGISTER / AUTH / messages / file chunks [Chưa tích hợp]
        v
   Python Server ── SessionRegistry ── Auth (PBKDF2)
        |
   Reliable UDP transport + independent streams + CUBIC [Đang phát triển]
```

- **TCP/TLS:** bootstrap và cấp `ConnID`, hai khóa UDP (`c2s_key`, `s2c_key`). Không dùng TCP để chuyển nội dung chat/file trong thiết kế đề xuất.
- **UDP:** đăng ký endpoint, xác thực tài khoản, unicast/broadcast, truyền file 1-1 qua server relay (mục tiêu tiếp theo).
- **Độ tin cậy:** nhóm tự triển khai ACK ranges, retransmission, RTT/RTO, sliding window và nhiều stream độc lập.
- **Congestion control:** CUBIC do thành viên A phụ trách, **chưa triển khai**.
- **Bảo mật:** bootstrap dùng TLS (`ssl` Python); UDP dự kiến dùng AES-GCM với khóa được cấp qua TLS. Không gửi password qua TCP bootstrap.

**Lưu ý về đặc tả:** Đọc `docs/protocol_v1_proposed.md`, `docs/teacher_clarifications.md` và `docs/OPEN_DECISIONS.md`. Tài liệu thiết kế là đề xuất và có thể còn thay đổi sau khi nhóm/giảng viên xác nhận.

## 2. Tiến độ thành viên A

| Giai đoạn | Hạng mục | Tình trạng | Kiểm chứng / giới hạn |
|---|---|---|---|
| **A1.1** | Sườn project + TCP framing | ✅ Hoàn thành | `control_framing.py`; 10 bài test TCP framing |
| **A1.2** | Tạo tài khoản mẫu + PBKDF2 authentication | ✅ Hoàn thành | `scripts/create_test_users.py`, `server/auth.py`; tổng 14 bài test đã PASS theo kiểm thử của A |
| **A1.3** | TLS bootstrap, `HELLO/HELLO_ACK`, ConnID và hai khóa UDP | ✅ Hoàn thành | 16/16 tests PASS; client và server in cùng ConnID |
| **A1.4** | `SessionRegistry`, trạng thái phiên, kiểm tra trùng tên, timeout/cleanup | ✅ Đã chạy demo | Server tạo các ConnID khác nhau, ghi `BOOTSTRAPPED` và `EXPIRED`; **chưa có UDP thật** |
| **A1.5** | UDP REGISTER → `UDP_BOUND` | ⏳ Chờ tích hợp với B | B phải xác thực AES-GCM và anti-replay trước khi A bind endpoint |
| **A1.6** | UDP AUTH → `ONLINE` | ⬜ Chưa tích hợp | `verify_password()` sẽ xử lý thông tin AUTH sau khi UDP được xác thực |
| **A2** | CUBIC + packet loss/delay/reordering simulator | ⬜ Chưa bắt đầu | Module/network tests do A phụ trách |
| **Tiếp theo** | Routing, file application logic, HTTP/SSE/UI, integration/load tests | ⬜ Chưa hoàn thiện | Phụ thuộc giao diện giữa tầng ứng dụng và reliable UDP |

**Về bài test:** Trong lộ trình hiện có 10 bài TCP framing + 4 bài authentication + 2 bài bootstrap + 13 bài sessions = **29 bài test được thiết kế**. A đã xác nhận chạy thành công **16/16** trước A1.4 và demo session management hoạt động. Cần chạy lại lệnh tổng để ghi nhận kết quả **29/29** trên đúng commit hiện tại; không coi số test dự kiến là kết quả PASS được xác nhận.

### Những chức năng *chưa* được chứng minh là hoàn thành

- TCP/TLS demo và trạng thái `BOOTSTRAPPED` **không đồng nghĩa** client đã đăng nhập `ONLINE`.
- Chưa có UDP REGISTER/AUTH được mã hóa chạy end-to-end, chưa có reliable chat hoặc UDP file transfer.
- Chưa kiểm chứng 10–20 client online đồng thời; demo TCP hiện vẫn xử lý tuần tự các kết nối bootstrap.
- Chưa có giao diện web hoàn chỉnh, mô phỏng mất gói hoặc CUBIC.
- Tiến độ code của B chưa được kiểm tra trong README này; không đánh dấu hoàn thành dựa trên file TODO.

## 3. Phân công A / B

| Thành viên A | Thành viên B |
|---|---|
| TCP/TLS bootstrap, authentication, session management | UDP packet format, AES-GCM, anti-replay |
| User list, application routing, file offer/accept, reassembly, SHA-256 | ACK ranges, RTT/RTO, retransmission, sliding window |
| **CUBIC**, network simulator, log và đồ thị cwnd | Multiplexed streams, UDP transport, heartbeat |
| HTTP bridge/SSE, HTML/CSS/JS, integration/load tests | UDP file data transport và transport tests |

**Chung:** chuẩn hóa giao diện transport ↔ application, chốt protocol, kiểm thử end-to-end và báo cáo. Chi tiết trong `docs/TEAM_OWNERSHIP.md` và `docs/INTERFACES.md`.

### Hợp đồng tích hợp cần chốt trước A1.5

1. `ConnID`: 64-bit; UDP header, packet number, nonce AES-GCM, AAD, chống replay.
2. Server tìm khóa theo `conn_id`; chỉ gọi `SessionRegistry.bind_udp_verified(conn_id, endpoint)` **sau khi** gói REGISTER được xác thực đầy đủ.
3. Sau `UDP_BOUND`, transport chuyển AUTH đã giải mã cho tầng ứng dụng để gọi `authenticate_after_verified_udp(...)`.
4. Quy ước ACK/response cho REGISTER/AUTH, timeout (bootstrap hiện 10 giây, idle 15 giây), và cách xử lý khi session hết hạn.

## 4. Cài đặt và chạy phần đã hoàn thành

Yêu cầu: Python 3.12+; chạy lệnh từ **thư mục gốc có `README.md`**. Các ví dụ dưới đây dành cho Windows PowerShell.

```powershell
python --version
python -m pip install cryptography
```

Tạo dữ liệu đăng nhập mẫu **chỉ khi chưa có `config/users.json`** (script có thể ghi lại dữ liệu test):

```powershell
Test-Path .\config\users.json
# Nếu False:
python -m scripts.create_test_users
```

Tạo chứng chỉ tự ký để thử TLS trên localhost (không commit khóa riêng):

```powershell
python -m scripts.gen_cert
```

Chạy các bài test:

```powershell
python -m unittest tests.test_auth -v
python -m unittest tests.test_bootstrap -v
python -m unittest tests.test_sessions -v
python -m unittest discover -s tests -v
```

**Demo A1.4:** Mở 2 terminal tại project root.

Terminal server:

```powershell
python -m examples.bootstrap_server
```

Terminal client:

```powershell
python -m examples.bootstrap_client
python -m examples.bootstrap_client
```

Server dự kiến ghi log `BOOTSTRAPPED`, `conn_id`, `pending=...`, rồi `EXPIRED` sau timeout nếu chưa có UDP REGISTER. Chạy 2 client trong vòng 10 giây để quan sát `pending=2`; nếu session đầu hết hạn trước thì thấy `pending=1` là bình thường. `pending` **không phải** số user online.

> Demo hiện chạy `127.0.0.1:9000`; UDP port `9001` mới được công bố trong HELLO_ACK, **chưa có UDP service**. Trước khi chạy trên LAN, cần tạo chứng chỉ có SAN cho địa chỉ server và cấu hình host/port phù hợp.

## 5. Tài liệu, bảo mật và quy tắc commit

- `docs/A1_3_GUIDE.md`, `docs/A1_4_GUIDE.md`: hướng dẫn hai giai đoạn gần nhất (nếu đã thêm patch tương ứng).
- `docs/INTERFACES.md`: API giữa hai thành viên; phải thống nhất trước A1.5.
- File có `TODO`/`NotImplementedError` chỉ là sườn, không đại diện cho chức năng chạy được.
- Không commit `config/users.json`, `certs/server.key`, chứng chỉ/khóa thử nghiệm của từng máy, khóa UDP, mật khẩu thật hoặc file `.part`. Kiểm tra `.gitignore` trước khi push.
- Chỉ dùng dữ liệu tài khoản mẫu để demo/test; không sử dụng mật khẩu mẫu trong môi trường thật.

## 6. Việc cần làm tiếp

**Ưu tiên số 1:** A và B thống nhất UDP packet format, khóa/nonce/AAD, callback của `SessionRegistry`, thứ tự `REGISTER → REGISTER_OK → AUTH → AUTH_OK` và heartbeat/timeout. Sau đó tích hợp **A1.5 — UDP Registration**. Khi liên kết A/B chạy được, tiếp tục UDP Authentication, messaging và file transfer, trong khi A phát triển CUBIC/simulator và UI.
A1.4.5 — Patch bo sung SessionRegistry chuan bi A1.5

Noi dung:
  server/sessions.py                   THAY THE
  tests/test_sessions.py               THAY THE (13 tests cu + 11 tests moi)
  examples/bootstrap_server.py         THAY THE (idle=10, log close event)
  docs/A1_4_5_IMPLEMENTATION_GUIDE.md  MOI

Giu nguyen server/auth.py, config/users.json, TLS certs, B UDP code.

PowerShell tu thu muc goc network-collab-v1:
  python -m unittest tests.test_sessions -v
  python -m unittest discover -s tests -v

Da kiem thu khi ghep project goc A1.3 + A1.4: 40 tests PASS.
A1.5 UDP REGISTER that CHUA DUOC trien khai trong patch.
