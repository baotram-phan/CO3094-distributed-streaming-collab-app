# B4.2.0 — CUBIC Feedback Integration (phần của B)

## Kết quả kiểm thử trên bản sao tích hợp

- `test_congestion_feedback.py`: **31/31 PASS**.
- `tests/test_cubic.py` của A: **12/12 PASS** (source A chỉ có sửa kiểu Pylance, không thay thuật toán).
- Toàn bộ repo bản sao B4.1 + B4.2.0: **590/590 PASS** (`python -m unittest discover -s tests -q`).
- Demo `python -m examples.demo_congestion_feedback`: `cwnd 10240 -> 10245` khi `b"hello"` được ACK; `bytes_in_flight 56 -> 0`.
- **Chưa có UDP sendto thật, timer loop hay AUTH/chat/file callback end-to-end**. Chỉ phản hồi CUBIC và send scheduling ở tầng logic; A/B vẫn phải test B4.2.1/B4.3.

## Cài trên máy bạn (không ghi đè CUBIC của A)

**Tiền đề:** B1, B2, B3.2.3, B3.3.1, B3.3.2 và B4.1 đã hiện diện, cùng **`common/cubic.py` thật do A cung cấp**, không phải TODO skeleton.

1. Sao lưu hoặc commit branch trước khi thay đổi.
2. Chép `common/congestion_feedback.py` (MỚI).
3. Chép `tests/test_congestion_feedback.py` (MỚI).
4. Chép `examples/demo_congestion_feedback.py` (MỚI, tùy chọn).
5. **Sửa nhỏ** `common/reliable_receive.py` của B4.1 theo `patches/reliable_receive_B4_2_0.patch` hoặc đối chiếu với file đầy đủ trong `reference_only/common/reliable_receive.py`. ĐỪNG ghi đè file B4.1 đã được A/B sửa sau đó.
6. **KHÔNG sửa/ghi đè `common/cubic.py`** và không thay `server/udp_service.py`, `client/core/udp_connection.py` của A ở bước này.

Chạy từ gốc `network-collab-v1`:

```powershell
python -m unittest discover -s tests -p "test_cubic.py" -v
python -m unittest discover -s tests -p "test_congestion_feedback.py" -v
python -m examples.demo_congestion_feedback
python -m unittest discover -s tests -v
```

## A. Logic CUBIC, ACK và flow control khác nhau như thế nào?

- **Flow control** ở B2/B3.3.1 kiểm tra receiver `max_offset` theo stream; tránh gửi nhiều hơn khả năng nhận/tiêu thụ của peer.
- **Congestion control** dùng CUBIC của A để giới hạn `bytes_in_flight` **trên cả kết nối**. Scheduler chỉ gửi khi `bytes_in_flight + udp_datagram_size <= cubic.cwnd_bytes`. Hai giới hạn đều phải thỏa.
- **ACK** ở B3 xác nhận datagram. `SentPacketTracker.bytes_acked` là byte UDP đã mã hóa (56B cho `hello`), nhưng `cubic.on_ack()` nhận **DATA payload bytes** (`5B` cho `hello`), không cộng overhead.
- **ACK của 2 packet number cùng mang lại một StreamSendFrame** chỉ được tăng cwnd một lần. ACK cũ sau retry vẫn có thể kết thúc logical frame qua `DataRetransmissionQueue.on_ack()`.

### Ví dụ 5 byte

```text
application queue b"hello" (5B)
  -> StreamManager/WindowUpdateFlow đảm bảo còn credit
  -> ConnectionSendScheduler.prepare_next(..., cwnd=cubic.cwnd_bytes)
  -> tạo UDP DATA 56B, theo dõi bytes_in_flight = 56
  -> B4.2.1 socket.sendto() thực tế thành công
  -> ReliableReceiveState.commit_send(plan) -- ghi nhận pkt đã gửi
  -> nhận ACK có AEAD + replay + endpoint hợp lệ
  -> SentPacketTracker giải phóng 56B
  -> CongestionFeedback đối chiếu attempt packet number, cộng 5 DATA bytes
  -> CubicController.on_ack(5, 1.1, 0.1): cwnd 10240 -> 10245
```

Trong demo, `sendto()` được giả lập; chưa phải chứng minh truyền qua mạng.

## B. API đã bổ sung vào `ReliableReceiveState`

```python
r = ReliableReceiveState(existing_transport_connection_state)
# giữ SAME connection state sau REGISTER, KHÔNG tạo state mới

r.streams.queue_bytes(1, b"hello")
plan = r.prepare_send(outbound_key, now_ms=1000.0)
if plan is not None:
    try:
        n = sock.sendto(plan.datagram, endpoint)  # CHỈ LÀ PSEUDOCODE CHO B4.2.1
        if n != len(plan.datagram):
            raise OSError("short UDP send")
    except OSError:
        r.abort_send(plan)
    else:
        r.commit_send(plan)

# B4.3 gọi trên timer đúng giờ, KHÔNG từ callback A:
loss_reports = r.check_rto(now_ms=1500.0)
```

`commit_send()` chỉ được gọi sau khi socket đã chấp nhận gửi trọn datagram. `note_sent()` chỉ ghi lại DATA đã commit (kể cả retransmit), không tính các packet chuẩn bị rồi abort. `prepare_send()` lấy `cubic.cwnd_bytes` THẬT thay vì hằng số demo.

**Lưu ý:** Các thao tác `prepare_send`/`commit_send`/`accept`/`check_rto` phải được serialize per ConnID (một owner loop hoặc lock phối hợp). Không thực hiện callback A trong transport lock. Chỗ `sendto()` ở trên là minh họa bước kế tiếp, không dán trực tiếp vào UDP receive loop hiện tại khi chưa thống nhất concurrency.

## C. Recovery epoch và loss

- `_highest_sent_data_pn` chỉ lấy DATA packet number của **lần gửi đã commit**; không dùng packet number vừa allocate.
- Khi `PacketLossDetector` báo `packet_threshold` cho DATA mới hơn `recovery_marker`, B chốt marker bằng DATA PN lớn nhất đã gửi và gọi A `cubic.on_loss(now_s, marker)` đúng **một lần**.
- Các mất gói có `packet_num <= recovery_marker` cùng đợt không lặp lại giảm cwnd.
- ACK xác nhận attempt có `packet_num <= recovery_marker` chỉ giải phóng bookkeeping, **không tăng cwnd**. ACK của DATA attempt mới hơn boundary có thể tăng cwnd.
- Khi RTO được báo qua `check_rto()`, B3 đã tự backoff RTT (một lần mỗi batch), B chỉ gọi thêm `cubic.on_timeout(now_s)` tối đa một lần cho đợt ấy; KHÔNG gọi `rtt.on_timeout()` lần nữa.
- Thời gian transport luôn `monotonic milliseconds`; `CongestionFeedback` chia cho 1000 khi gọi CUBIC seconds. RTT SRTT chia cho 1000, **không tự tạo RTT giả**.

## D. Limitations / điểm cần chốt với A

1. `WINDOW_UPDATE` chưa làm CUBIC giảm cửa sổ khi bị mất: B3 vẫn retransmit theo loss detector; cần A quyết định chính sách congestion response chung. WINDOW_UPDATE vẫn tính vào `bytes_in_flight` khi gửi.
2. CUBIC ACK growth hiện dùng **DATA payload bytes** theo đúng A1.6; `bytes_in_flight` dùng **datagram bytes**. Đề nghị A kiểm tra lại quyết định này trước khi merge.
3. `DataRetransmissionQueue.note_loss()` hoặc `WindowUpdateFlow.note_loss()` có thể báo `BufferError`/`TimeoutError` khi full/max retry. B4.4 phải chuyển sang `on_transport_failed(conn_id, code)` ngoài lock, thông qua coordinator A. KHÔNG im lặng bỏ loss signal (one-shot).
4. `check_rto()` là **hàm tick thủ công**, chưa phải periodic timer thực sự; B4.3 mới thực hiện lịch timer và hủy worker khi session đóng.
5. `common/reliable_receive.py` vẫn chưa gọi app callback; B4.4 cần worker tuần tự per ConnID, không chạy PBKDF2 trong socket loop; B4.1 queue phải được tiêu thụ trước khi `flow.note_consumed()`.
6. Vì B4.1 có thể được A chỉnh, chỉ áp dụng patch có review, tránh overwrite upstream.

## E. Cần gửi A review những gì?

Gửi `common/congestion_feedback.py`, `tests/test_congestion_feedback.py`, patch `reliable_receive_B4_2_0.patch`, ghi rõ `common/cubic.py` không thay. Nhờ A review `recovery_marker`, ACK growth theo DATA payload, RTT seconds, phản ứng loss của WINDOW_UPDATE, terminal failure và worker ABI. Chưa merge B4 như end-to-end cho đến B4.2.1/B4.3/B4.4/B5.
