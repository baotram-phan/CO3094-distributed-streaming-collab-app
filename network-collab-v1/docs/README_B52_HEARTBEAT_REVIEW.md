# B5.2 — Heartbeat / UDP resilience (A+B REVIEW; chưa merge)

> **Nguồn đối chiếu:** A+B live runtime + congestion MSS 1075 + test B5.1b (sửa Pylance). Gói này CHỈ gồm file thay đổi của B, không phải một project hoàn chỉnh để giải nén đè. A sở hữu SessionRegistry, application/UI và coordinator.

## 1. Contract đã triển khai

- **Client B → Server B:** sau REGISTER_OK, `UDPRegistrationClient.pump_reliable_once()` chủ động gửi PING mã hóa sau mỗi **2000 ms**, qua **chính socket, ConnID, c2s key và packet-number space** hiện tại. Không tạo thread/timer socket mới.
- **Server B → Client B:** chỉ PING đã AEAD-authenticated, có endpoint đúng, PING body đúng 8 byte, packet number mới và session còn `UDP_BOUND`/`ONLINE` mới được chấp nhận. Server gọi `SessionRegistry.touch_verified_udp()` ngoài transport lock, rồi phản hồi **PONG với nguyên `timestamp_ms:u64`** (dùng s2c key + packet number mới).
- PING/PONG không là DATA/ACK, không tạo `StreamDelivery` và không tăng `bytes_in_flight` hay CUBIC. `PONG` không được ACK lại.
- Client chỉ chấp nhận PONG đúng key/endpoint/ConnID/packet number và echo một PING đang chờ; packet lặp/không khớp không làm mới client liveness.
- **Client không nhận UDP từ server được xác thực trong 10 giây:** đóng socket và báo `TimeoutError` (`bootstrap again`). Reconnect cần TLS bootstrap mới do A/application xử lý; B không tự dùng lại key cũ.
- Server **giữ timeout của A**: `idle_timeout_s=10` trong `SessionRegistry`, `auth_timeout_s=30` (PING không kéo dài hạn AUTH). **Chỉ A coordinator** drain `SessionClosedEvent` và gọi `udp_service.remove_connection`.

## 2. Bốn file trong ZIP — KHÔNG ghi đè project

1. `common/udp_packet.py` — `encode_heartbeat_body()`/`decode_heartbeat_body()`, validation PING/PONG 8 B.
2. `server/udp_service.py` — `_handle_heartbeat_ping()` và dispatch PING trong `handle_datagram()`.
3. `client/core/udp_connection.py` — lịch PING 2s, check PONG/replay, kiểm tra client-side idle 10s trong `pump_reliable_once()`.
4. `tests/test_b52_heartbeat_resilience.py` — 17 regression tests mới; KHÔNG thay production nào để các test PASS.

`B52_CHANGES_REVIEW.diff` là diff đọc đối chiếu, **không** phải patch phải apply. Không sửa `server/main.py`, `server/sessions.py`, `common/cubic.py`, MSS hoặc test cũ.

### Cài đặt trên máy bạn

**Cách an toàn:** giải nén gói ra một **thư mục riêng** (ví dụ `C:\temp\B52_REVIEW`); trong VS Code mở bản đang làm việc và bản trong ZIP, dùng Compare để xem thay đổi. **Nếu A vừa cập nhật file thì phải merge các đoạn thay đổi, không chép đè file mới nhất của A.**

Nếu ba file của bạn đúng cùng baseline, chép ba file production vào đúng các đường dẫn trong `network-collab-v1` và thêm file test vào `tests`. Đừng thay thế cả thư mục dự án bằng ZIP này.

### Chạy test bằng PowerShell tại `network-collab-v1`

```powershell
python -m unittest discover -s tests -p "test_b52_heartbeat_resilience.py" -v
python -m unittest discover -s tests -p "test_b51b_reorder_duplicate_hol.py" -v
python -m unittest discover -s tests -p "test_a_b_live_network.py" -v
python -m unittest discover -s tests -v
```

Không cần cài package thêm. Test B5.2 có một trường hợp kiểm tra heartbeat thời gian thật, mất khoảng >4 giây.

## 3. Kết quả bản sao (không phải máy Windows của bạn)

- B5.2: **17/17 PASS**, real UDP socket loopback; bảo vệ AEAD/replay/endpoint, PONG echo, periodic PING, PONG drop/recovery, AUTH deadline, A coordinator cleanup.
- B5.1b reordering/duplicate/No HoL: **8/8 PASS**.
- Tích hợp A+B TLS/UDP AUTH/chat: **2/2 PASS**.
- Full regression: **758 test chạy, còn 18 failures**. Đây là những assertions cũ kỳ vọng congestion MSS 1024 (các file `test_congestion_feedback.py`, `test_udp_send.py`), xuất hiện từ trước B5.2. Test tài khoản demo được tạo **chỉ trong bản sao** để 2 lỗi AUTH do thiếu file mẫu không làm nhiễu. **Chưa sửa 18 assertions để ép PASS**.
- B5.1a 7 test loss không có trong snapshot dùng để đóng gói; bạn cần chạy trên repo của mình nếu file đó hiện diện.

## 4. Chưa được tuyên bố hoàn thành

- Không có client-side reconnect tự động hoặc resume/khôi phục file; phải TLS bootstrap lại với key mới.
- Không implement authenticated `CLOSE`/graceful logout hay server-initiated PING; server nhận PING và trả PONG. Application A sở hữu logout/session policy.
- Chưa có file-transfer end-to-end, UI, 10–20 client load test, LAN thật và đo packet loss của heartbeat ở tỷ lệ 5–10% trên môi trường tích hợp.
- Chưa merge vào Git chính; trước khi chốt A cần review cách thông báo server close cho client UI, dùng `SessionRegistry`/coordinator đúng ranh giới.

## 5. Test giải thích

- Heartbeat hợp lệ: `REGISTER_OK` → PING sau 2s → server kiểm tra endpoint/AEAD/replay → `touch_verified_udp` → PONG echo → client xác thực, cập nhật thời điểm nhận gói hợp lệ.
- Heartbeat sai: AEAD sai, body 7 B, sai endpoint, duplicate PING hoặc PONG không khớp timestamp đều **không refresh liveness**.
- Nếu client ngừng gửi dữ liệu/heartbeat: Registry của A hết idle timeout và phát close event; coordinator của A giải phóng trạng thái B và báo presence (nếu ONLINE).
- `PONG` bị mất: client vẫn gửi PING chu kỳ tiếp theo với packet number **mới**, có thể tiếp tục phiên nếu chưa hết timeout.
