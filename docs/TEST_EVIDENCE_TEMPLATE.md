# TEST EVIDENCE TEMPLATE — Sao chép cho từng lần chạy

> **Không chỉnh kết quả cũ để thay bằng kết quả mới.** Mỗi lần chạy dùng một mục mới, tên bài test/commit rõ ràng. Không commit password, UDP/TLS private/session keys, nội dung chat riêng, file của người dùng hay endpoint công khai không cần thiết.

## Run metadata

- Test ID: `Lxx / Txx / Mxx`:
- Date/time + timezone:
- Người chạy: `A` / `B` / cả hai:
- Máy/OS + Python version:
- Vai trò: `server` / `client` / `test driver`:
- Git commit hash trên máy A:
- Git commit hash trên máy B:
- Protocol/Integration Contract version (status):
- Kiểu mạng: `loopback` / `LAN` / `simulated loss`:
- Config **không chứa secret**: server LAN alias, TCP port, UDP port, simulator seed/loss/delay/reorder:

## Test case

- Requirement/milestone liên quan:
- Mục đích:
- Preconditions (server/bootstrap/keys/trust config):
- Các bước/lệnh chạy **đúng theo source hiện tại**:
- Expected result:
- Actual result:
- Status: `PASS` / `FAIL` / `BLOCKED` / `NOT RUN`:
- Logs/screenshots/sha256/cwnd chart (đường dẫn đến bằng chứng đã được khử secret):
- Lỗi/điểm khác biệt:
- Người review kết quả:
- Follow-up issue / Git commit sửa:

## Với test file transfer

- Sender file size (bytes):
- Sender SHA-256:
- Receiver file size (bytes):
- Receiver SHA-256:
- Packet loss/delay/reorder seed:
- Mất packet/ACK và retransmission count:
- Thời gian hoàn thành hoặc lý do thất bại:

## Với test cross-stream HoL

- File stream ID, chat stream ID:
- Thời điểm bắt đầu file + loss simulation:
- Thời điểm chat được gửi/nhận/hiển thị:
- Bằng chứng file stream đang thiếu offset khi chat vẫn xử lý được:

## Với test CUBIC/flow

- cwnd initial/min/current, bytes_in_flight, flow credit:
- Số ACK/loss/RTO và thời điểm xảy ra:
- Đường dẫn biểu đồ `cwnd(t)` và số liệu có thể tái lập:

## Với lỗi bảo mật

- Tamper input (metadata an toàn, không ghi key):
- Server/client drop/reject thay vì xử lý app?
- Có session state / replay state bị thay đổi không?
- Có lộ secret trong log/console/repository không?
