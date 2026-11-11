# A1.6 B3.1 — ACK Tracking implementation

**Ngày:** 2026-11-11  
**Chủ sở hữu:** Thành viên B  
**Trạng thái:** Code và unit/regression tests PASS **trên bản sao A1.5 + B1 + B2.3**; chưa tích hợp UDP thực, chưa phải ABI A–B chính thức.

## 1. Nguồn yêu cầu và giới hạn

- Assignment 1 yêu cầu reliable transfer trên UDP, ACK/retransmission, sliding window và congestion control.
- Protocol Specification **v1.0-proposed** §4.2: ACK body `ack_delay_ms:u16 | range_count:u8 | [start:u64, end:u64]`, 1–16 ranges giảm dần, inclusive, không chồng lấn; **không ACK ACK-only packet**.
- Protocol §6: RTT/RTO, selective retransmit và packet number **mới** cho mỗi lần retransmit (cùng stream offset và bytes); B3.1 **chưa** hiện thực RTT/RTO/retransmit.
- A–B Integration Contract v1.1-approved Addendum: A coordinator là bên duy nhất drain `SessionClosedEvent`; B remove/tombstone ConnID, không gọi Registry/callback trong transport locks.
- `A1_6_AB_HANDOFF.md` là **callback proposal**: chỉ giao contiguous stream 0 cho A worker; không đóng thêm length prefix của AUTH, không gọi A trong receive loop. B3.1 chưa chạm callback.

## 2. Files mới, không sửa file khác

- `common/transport.py` (mới):
  - `ReceivedPacketAckTracker`: lịch sử packet đã nhận và các khoảng ACK.
  - `SentPacketTracker`: metadata của packet đã phát, tính bytes in flight và xử lý ACK.
  - `ConnectionAckState`: ghép cả hai với **chính `TransportConnectionState` đã có**.
  - `AckSnapshot`, `SentPacket`, `AckReceipt`: immutable data objects.
- `tests/test_ack_tracking.py` (mới): **59 unit tests**.
- Không thay đổi `common/streams.py`, `common/udp_packet.py`, `common/replay.py`, `server/main.py`, `server/udp_service.py`, CUBIC hoặc source A.

## 3. Quy trình sử dụng dự kiến của B3.2/B4 (chưa nối socket)

### Gửi DATA

1. B3 scheduler phải **đảm bảo có send-tracking capacity** (hoặc bộ đệm staging riêng có giới hạn), tránh `next_send_frame()` làm mất DATA khi tracking bị đầy.
2. Lấy `StreamSendFrame` từ `StreamManager.next_send_frame()`; giữ frame gốc.
3. Gọi **bộ cấp packet number duy nhất** `ConnectionAckState.allocate_packet_number()` (delegate tới `TransportConnectionState.allocate_packet_number()`).
4. Dùng `encode_data_body()` và `encode_packet()` để có UDP datagram; kiểm tra congestion/window ở lớp B3.3 trước khi gửi.
5. `SentPacketTracker.track_sent(pkt_num, DATA, len(packet), monotonic_ms, frame=frame)` trước khi packet có thể thất lạc trong send path. Nếu biết chắc send thất bại, `cancel_sent(pkt_num)` và giữ/khôi phục frame trong một staging queue có giới hạn; **không được coi như ACK**.
6. ACK-only packet cũng tiêu thụ packet number từ cùng allocator, nhưng `track_sent(..., ACK, ...)` **không tạo entry in-flight**.
7. ACK có thể tới các packet được gửi trước/sau; `process_ack(body)` trả `AckReceipt` gồm metadata của packet **mới được xác nhận**. Duplicate ACK không giảm `bytes_in_flight` lần nữa.

### Nhận DATA/ACK

1. Kiểm tra endpoint/ConnID, decrypt và xác minh AES-GCM, validate body đúng packet type, rồi kiểm tra replay; xử lý event **tuần tự theo ConnID**.
2. DATA: đảm bảo stream tồn tại, credit và bounded stream buffer/callback staging có chỗ **trước khi ACK**; nếu ứng dụng chưa thể nhận delivery thì phải giữ nó an toàn trong queue. Chỉ ghi ACK khi nội dung đã được chấp nhận và không thể bị drop âm thầm. A worker/callback chạy ngoài transport lock.
3. `ReplayWindow.commit()` trên packet hợp lệ; **sau khi** receive state đã nhận/giữ an toàn, gọi `received.note_received(pkt_num, packet_type, monotonic_ms)`. Nếu bị drop do thiếu tài nguyên thì **không được ACK như đã nhận**.
4. ACK packet: xử lý `sent.process_ack(body)` sau xác thực và replay; gọi `received.note_received(..., ACK, ...)` sẽ trả `False` (tránh ACK storm).
5. Khi cần ACK, `snapshot = received.build_ack(now_ms)`. Gói body này bằng `encode_packet(key, ACK, conn_id, NEW_PKT_NUM, snapshot.body)`. Chỉ sau khi gửi **thành công** mới gọi `received.mark_ack_sent(snapshot)`. Nếu thất bại, trạng thái ACK vẫn pending. Nếu DATA mới đến giữa build và mark, snapshot cũ không được xóa pending mới.
6. Nếu packet DATA trùng được xác thực lại nhưng `ReplayWindow` từ chối, có thể gọi `request_reack(pkt_num)` (không chuyển dữ liệu trùng cho stream) nếu packet vẫn trong ACK history.
7. Nếu có >16 ranges rời rạc, `build_ack()` + `mark_ack_sent()` tuần tự tạo nhiều snapshot đúng protocol, đảm bảo không bỏ hẳn các khoảng thấp hơn. Scheduler thực tế **phải tiếp tục gửi batch** nếu `ack_pending=True`.

**Chú ý:** thứ tự reassembly, replay commit, ACK commit ở bước tích hợp phải bảo đảm tính nguyên tử hoặc rollback/staging thích hợp; tài liệu này là thiết kế, không giả vờ đã có receive/send loop thật.

## 4. Các hạn mức tài nguyên

| Thông số | Giá trị mặc định | Ý nghĩa |
|---|---:|---|
| Receive ACK history | 4096 packet numbers | Không lớn hơn `ReplayWindow` §4.1 |
| ACK ranges/packet | 16 | Giới hạn wire-format §4.2 |
| In-flight sent packets | 1024 | Chính sách bộ nhớ **nội bộ đề xuất** |
| In-flight datagram bytes | 1 MiB | Chính sách bộ nhớ **nội bộ đề xuất**, không phải cwnd |

`bytes_in_flight` tính byte datagram của packet ack-eliciting đang theo dõi; không tự thay thế CUBIC/cwnd. Hạn mức nội bộ phải xem lại cùng A khi load test 20 clients.

## 5. Test evidence

Chạy từ root `network-collab-v1`:

```powershell
python -m unittest discover -s tests -p "test_ack_tracking.py" -v
python -m unittest discover -s tests -v
```

Trên bản sao repository tích hợp:

- `Ran 59 tests ... OK` (B3.1).
- `Ran 317 tests ... OK` (258 base + 59 B3.1).

Các tests gồm: ACK ranges tăng/giảm/reorder; 20 disjoint ranges phân batch 16+4; ACK-only không kích ACK; duplicate ACK idempotence; preflight bộ nhớ; timestamp validation; packet number uint64; không tái sử dụng số packet đã ghi nhận; stale snapshot; authenticated DATA/ACK qua AES-GCM; bảo toàn `StreamSendFrame` cho retransmit sau này.

**Không tuyên bố:** UDP transfer hoạt động end-to-end, loss 5–10%, resend thực, RTT/RTO, CUBIC, AUTH stream 0, LAN, load 20 users, callback A, T01–T13.

## 6. Điểm cần A/B chốt trước khi tích hợp

- ABI chính thức cho enqueue stream bytes, callback nhận data + worker queue và send-failure.
- Semantics của `on_reliable_stream_data(...)->bool`; thời điểm delivery được xem là accepted, cách backpressure.
- Chính sách ACK delay/scheduler, cơ chế re-ACK khi lost ACK, tối đa 16 ranges mỗi packet.
- Cách kết nối `SentPacketTracker` với RTT/RTO, packet-threshold loss và CUBIC của A mà không hold lock khi gọi Registry/callback.
- Hủy state khi coordinator gọi `remove_connection(conn_id)`; không sinh lại keys/counters cho ConnID tombstone.

## 7. Git traceability

```powershell
git status
git add common/transport.py tests/test_ack_tracking.py
git commit -m "feat(transport): add bounded ACK tracking for reliable UDP"
```

Chỉ commit khi **tests của máy bạn PASS**; nếu cần ghi docs, đưa Markdown này vào `docs/` và `git add docs/B3_1_ACK_TRACKING_IMPLEMENTATION.md`.
