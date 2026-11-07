# Network Collaboration — v1 Proposed Skeleton

**Trạng thái:** SƯỜN THƯ MỤC + demo TCP framing cũ + 10 tests cũ. **CHƯA** phải app chat/file có thể chạy.

- Ngôn ngữ: Python 3.12+; VS Code; Windows PowerShell có thể dùng trực tiếp.
- Kiến trúc đề xuất: TLS/TCP bootstrap → UDP có mã hóa; UDP streams độc lập; CUBIC; server relay file 1-1.
- Nguồn: `docs/protocol_v1_proposed.md` và `docs/teacher_clarifications.md`.
- **Chưa được thầy phê duyệt toàn bộ kiến trúc**; tránh coi các TODO là code đã hoàn thiện.

## Bắt đầu ngay trên Windows (PowerShell)

1. Giải nén, mở đúng thư mục **network-collab-v1** trong VS Code.
2. Mở **Terminal → New Terminal** (đang ở thư mục có `README.md`).
3. Chạy:
   ```powershell
   python --version
   python -m unittest discover -s tests -v
   ```
   Kết quả dự kiến: **Ran 10 tests ... OK** (chỉ test TCP framing từ starter).
4. Chạy demo TCP căn bản ở **hai terminal**:
   Terminal server: `python -m examples.demo_server`
   Terminal client: `python -m examples.demo_client`
   Demo **không có TLS, không có AUTH, không có UDP, chỉ chạy trên localhost**.

## Chuyển các file bạn đã viết ở project cũ

Sườn này có bản gốc của `common/control_framing.py`, `tests/test_control_framing.py`,
`examples/demo_*.py` lấy từ starter đã cung cấp trước đây. **Không đảm bảo đây là
phiên bản được bạn chỉnh sửa gần đây trên máy riêng.**

Hãy so sánh và chép có chọn lọc từ project cũ của bạn:
- `scripts/create_test_users.py` — thay TODO bằng code tạo test users của bạn.
- `server/auth.py` — thay TODO bằng `verify_password` của bạn (nếu đã viết).
- `config/users.json` — chỉ chép nếu đang có dữ liệu đúng; file này mặc định không đóng gói.
- `tests/test_auth.py` — nếu bạn đã làm unit tests, hãy chép sang.
- `common/control_framing.py` / `examples/demo_*.py` — so sánh các thay đổi trước khi ghi đè.

**KHÔNG chép nguyên folder mới lên folder cũ để tránh mất code.** Dùng thư mục mới riêng, chỉ chuyển file có chủ đích.

## Chia A/B

- **A**: TLS/TCP bootstrap; auth; session; router; file protocol + reassembly/hash;
  **CUBIC**; simulator; HTTP/SSE/UI; integration & load tests.
- **B**: UDP packet + crypto; ACK/retransmit/RTT; flow control; multiplexed streams;
  UDP sender/receiver transport; heartbeat/liveness; UDP-focused tests.
- **Chung**: protocol và API, nối transport với server/client, end-to-end demo/report.

Đọc `docs/TEAM_OWNERSHIP.md`, `docs/INTERFACES.md`, `docs/PHASE_A1.md` trước khi code.

## Quy tắc quan trọng

- File có chữ `TODO` hoặc `NotImplementedError` là **bộ khung**, chưa dùng được.
- **CUBIC không thuộc B** trong lần chia mới.
- Tin nhắn và file không đi qua TCP trong kiến trúc hiện tại; dùng UDP.
- Đăng nhập qua UDP chỉ sau khi đã thiết lập khóa mã hóa; không gửi password plaintext qua mạng.
- Không commit key TLS, khóa UDP, mật khẩu thật, `users.json` local.
- Tên file và API có thể thay đổi khi A/B thống nhất và giảng viên duyệt.
