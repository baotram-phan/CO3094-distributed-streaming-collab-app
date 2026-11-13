# B4.4.1 — Reliable Stream Delivery Bridge + Consumption Feedback

Nguồn dùng để tạo patch: `network-collab-v1(1).rar` mà nhóm gửi gần nhất, **đã có B4.3.1 và B4.3.2**. Patch KHÔNG sửa `server/main.py`, CUBIC, codec, SessionRegistry, hay wire format.

## 1. Vì sao patch sửa 3 production files?

- `common/reliable_receive.py`: `pop_delivery()` lưu **exclusive end offset** đã bàn giao cho ứng dụng, theo từng stream. Hàm `confirm_consumed(stream_id, consumed_offset)` từ chối việc xác nhận byte vẫn đang nằm trong delivery queue, rồi sử dụng `WindowUpdateFlow.note_consumed()` hiện có.
- `server/udp_service.py`: `pop_reliable_delivery(conn_id)` và `confirm_consumed(conn_id, stream_id, consumed_offset)` thực hiện dưới lifecycle lock, **không gọi Registry/callback khi đang giữ lock**. Đọc Registry để kiểm tra phiên sống ở ngoài lock.
- `client/core/udp_connection.py`: cung cấp cùng chức năng dưới `_transport_lock` để ứng dụng client không phải truy cập trực tiếp vào `reliable_receiver` trong lúc UDP loop đang chạy.
- `tests/test_b441_delivery_bridge.py`: 22 test mới, bao gồm hai chiều UDP thực với `WINDOW_UPDATE`.

Không có module production mới. Không tự động đăng nhập, xử lý chat/file, tạo worker cho A hoặc thay đổi flow credit cho file chưa được chấp thuận.

## 2. Cách áp dụng trên Windows (Git root là thư mục CHA)

Đứng tại PowerShell trong thư mục `network-collab-v1`:

```powershell
git rev-parse --show-toplevel
git status --short
```

Nếu Git root là `CO3094-distributed-streaming-collab-app` thì patch trong ZIP đã có tiền tố `network-collab-v1/`. Chép file `.patch` vào `network-collab-v1/patches/` rồi chạy:

```powershell
git apply --verbose --check .\patches\B441_DELIVERY_BRIDGE_GITROOT.patch
git apply --verbose .\patches\B441_DELIVERY_BRIDGE_GITROOT.patch
```

**Không thêm `--directory=network-collab-v1`**, vì patch đã chứa đường dẫn đó. Patch sẽ tự tạo `tests/test_b441_delivery_bridge.py`; **không chép thêm bản test tham khảo trong ZIP**.

Nếu Git root là **chính** `network-collab-v1`, dùng `-p2` thay vì mặc định `-p1`:

```powershell
git apply -p2 --verbose --check .\patches\B441_DELIVERY_BRIDGE_GITROOT.patch
git apply -p2 --verbose .\patches\B441_DELIVERY_BRIDGE_GITROOT.patch
```

Nếu `--check` lỗi (khác source, hoặc các API đã có), **không chạy lệnh apply**. Kiểm tra tên API hoặc gửi thông báo lỗi để đối chiếu; không ghi đè code của A.

## 3. Sử dụng API từ A worker (ví dụ minh họa, chưa nối worker)

```python
# Không chạy phần này khi giữ Registry lock hay transport lock.
delivery = server.udp_service.pop_reliable_delivery(conn_id)
if delivery is not None:
    # A làm framing/parse/handle theo stream_id. Một delivery không nhất
    # thiết là một message hoàn chỉnh.
    application_accepts_or_stores(delivery)
    server.udp_service.confirm_consumed(
        conn_id, delivery.stream_id,
        delivery.offset + len(delivery.data),
    )
```

Client tương ứng:

```python
delivery = udp_client.pop_reliable_delivery()
if delivery is not None:
    application_accepts_or_stores(delivery)
    udp_client.confirm_consumed(
        delivery.stream_id, delivery.offset + len(delivery.data)
    )
```

`application_accepts_or_stores` chỉ là ví dụ API của A, **chưa được triển khai**. Nếu A chưa xử lý/chưa nhận trách nhiệm lưu byte, **đừng gọi confirm**. Nếu xử lý một phần, chỉ xác nhận phần contiguous đã xử lý.

Luồng chính:

`UDP AEAD/replay → B stream reassembly → bounded delivery queue → pop (handoff) → A accept/consume → confirm_consumed() → WindowUpdateFlow.note_consumed() → B4.3.2 scheduler gửi WINDOW_UPDATE`.

`pop()` **không cấp credit**. `confirm_consumed()` không tự gửi socket; việc phát WINDOW_UPDATE do pump B4.3.2 đảm nhiệm. Chức năng stream 0/1 dùng initial credit 64 KiB; file stream vẫn yêu cầu application phê duyệt `FILE_START` và cấp initial credit riêng.

## 4. Quy tắc bắt buộc

- API server pop/confirm không gọi callback của A hoặc Registry khi đang giữ transport lock.
- ACK UDP không được nhầm với ACK đã xử lý application.
- Confirmation phải là **exclusive end offset** của byte đã tiêu thụ **liên tục**, không phải số byte của riêng delivery.
- Chỉ xác nhận byte đã *popped*; không thể xác nhận vượt đoạn đã handoff; duplicate confirmation trả `False`; offset lùi báo `ValueError`.
- Nếu đã pop nhiều delivery nhưng worker xử lý không theo thứ tự, **A phải tự giữ nguyên thứ tự consumption**; xác nhận offset cao khi còn dữ liệu phía trước chưa xử lý sẽ là lỗi của A.
- Sau đóng session/cleanup, server không handoff thêm và `confirm_consumed` từ chối.
- Không gọi trực tiếp `reliable_receiver.pop_delivery()` từ thread khác khi có UDP loop: hãy dùng wrapper `udp_client.pop_reliable_delivery()`.
- B4.4.1 chỉ bàn giao dữ liệu. B4.4.2 còn phải thống nhất worker/callback và runtime activation với A; không coi milestone AUTH/chat/file đã hoàn thành.

## 5. Kiểm thử

```powershell
python -m unittest discover -s tests -p "test_b441_delivery_bridge.py" -v
python -m unittest discover -s tests -v
```

Kiểm tra API:

```powershell
python -c "from common.reliable_receive import ReliableReceiveState; from client.core.udp_connection import UDPRegistrationClient; from server.udp_service import UDPTransportService; print(hasattr(ReliableReceiveState, 'confirm_consumed'), hasattr(UDPRegistrationClient, 'confirm_consumed'), hasattr(UDPTransportService, 'confirm_consumed'))"
```

Kết quả trên snapshot của mình: **22/22 test B4.4.1 PASS**, **660/660 test toàn bộ PASS** (gồm 638 test nền với 8 test B4.3.2 bổ sung). Số bài test trên máy bạn phụ thuộc các file test thực tế có trong `tests/`.

Patch đã được thử với `git apply --verbose --check` / `git apply --verbose` **từ thư mục con** dưới Git root cha, áp dụng sạch và file sau patch khớp byte-for-byte với bản đã test.
