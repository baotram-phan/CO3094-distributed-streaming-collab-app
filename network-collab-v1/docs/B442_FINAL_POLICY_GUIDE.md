# B4.4.2 — Chốt lại contract A/B: callback failure 4 tham số và A fail-close

**Ngày:** 2026-11-13  
**Baseline B:** `network-collab-v1(1).rar` + B4.4.1 + patch B4.4.2 cũ (nếu đã áp dụng).  
**Baseline A:** `server/main.py` SHA256 `cb63213b35309a684bc494d4d141ff01c80e592972a98dcb7beda72a1a12fd30` trong `A_B442_ServerMain_API_Handoff.zip` (hoặc main có wiring B4.4.2 cũ).

## 1. Contract chính thức của A

```python
# A callback dữ liệu đã reassemble:
on_reliable_stream_data(conn_id: int, stream_id: int, offset: int, data: bytes, fin: bool = False) -> bool

# B báo lỗi cho A coordinator, không tự đóng Registry:
on_reliable_delivery_failed(conn_id: int, stream_id: int, offset: int, code: str) -> None
```

- **True**: application đã *tiếp nhận an toàn bytes* (kể cả frame chưa đủ). B xác minh connection còn hợp lệ, sau đó confirm `offset + len(data)`. Một kết quả AUTH_FAIL/CHAT_ERROR hợp lệ vẫn có thể `True`.
- **False**: B giữ delivery trong `pending`, đánh dấu `rejected`, không confirm, không cấp credit, không gọi callback lại. Thông báo A **một lần** với `APPLICATION_REJECTED`; A `registry.close()`, coordinator `dispatch_closed_events()`.
- **Exception**: tương tự False, với `APPLICATION_EXCEPTION` và traceback trong Python logging. Sender lỗi sau side effect không khiến callback bị gọi lại.
- **Confirm thất bại khi session vẫn active**: `CONSUMPTION_CONFIRM_FAILED`, thông báo A đóng session. Session đã đóng trước confirm: B bỏ qua, không tạo lại transport state.
- **Không có `resume_rejected()` trong B4.4.2 cuối cùng**. Không có application retry API.
- **Mỗi ConnID một worker cố định theo hash**, không tạo thread/packet. B không gọi ứng dụng dưới transport lock/Registry lock và không drain Registry events.
- `StreamDelivery` là đoạn bytes, *không nhất thiết là một bản tin JSON hoàn chỉnh*.

## 2. Chọn ĐÚNG MỘT patch B

**Trường hợp B4.4.2 cũ đã được áp dụng** (đã có `server/reliable_dispatcher.py`, `tests/test_b442_delivery_dispatcher.py`):

`B442_FINAL_B_INCREMENTAL_GITROOT.patch` — cập nhật 2 file có sẵn, không sửa UDP adapter.

**Trường hợp mới có B4.4.1, CHƯA áp dụng B4.4.2 cũ**:

`B442_FINAL_B_FULL_FROM_B441_GITROOT.patch` — thêm dispatcher + tests, cập nhật `udp_service.py`.

**KHÔNG ÁP DỤNG CẢ HAI PATCH.** Không chép `tests/test_b442_delivery_dispatcher.py` vào `tests/` *trước* khi apply patch FULL vì patch đã tự tạo file đó.

Từ PowerShell đang đứng ở `network-collab-v1`, khi Git root là `CO3094-distributed-streaming-collab-app` ở thư mục cha:

```powershell
# Ví dụ khi đã có B4.4.2 cũ
 git status --short
 git apply --verbose --check .\patches\B442_FINAL_B_INCREMENTAL_GITROOT.patch
 git apply --verbose .\patches\B442_FINAL_B_INCREMENTAL_GITROOT.patch
```

Nếu mới có B4.4.1, đổi tên patch trong hai lệnh thành `B442_FINAL_B_FULL_FROM_B441_GITROOT.patch`. Phải thấy `Checking patch ...`, **không được có `Skipped patch`**. Nếu `--check` thất bại, DỪNG; không dùng `--force`, không ghi đè source. Nếu Git root *chính là* `network-collab-v1`, đường dẫn patch có tiền tố `network-collab-v1/` nên cần `-p2` thay vì cách trên.

Xác minh:

```powershell
python -c "from server.reliable_dispatcher import ReliableDeliveryDispatcher as D; print('resume_rejected' in dir(D))"
# False
python -m unittest discover -s tests -p "test_b442_delivery_dispatcher.py" -v
python -m unittest discover -s tests -v
```

**Kết quả tại môi trường kiểm thử:** B4.4.2 mới **24/24 PASS**, toàn bộ **684/684 PASS** trên snapshot baseline 660 test. Số lượng tests trên máy bạn có thể khác.

## 3. Patch A chỉ để A review/merge

Chọn **ĐÚNG MỘT**:

- `B442_FINAL_A_MAIN_INCREMENTAL_GITROOT.patch` nếu A đã merge wiring B4.4.2 *cũ* (`main.py` đã có `self.delivery_dispatcher`). Patch đổi hook 2→4 tham số và fail-close cho cả False/exception.
- `B442_FINAL_A_MAIN_FROM_HANDOFF_GITROOT.patch` nếu A vẫn ở đúng `main.py` nguyên bản từ ZIP bàn giao (chưa có wiring). Patch nối `auto_drive`, sender stream 0/1, worker và hook 4 tham số.

**Không apply patch A lên file `server/main.py` A1.5 cũ**, hoặc file đã được A thay đổi mà không đối chiếu. A quản lý `server/main.py`, `A16AuthService`, `A17ChatService`, `SessionRegistry` và `dispatch_closed_events()`.

A coordinator nhận `on_reliable_delivery_failed(cid,sid,offset,code)` và gọi `registry.close(cid, reason="app_delivery_failure")` cho **tất cả failure codes**, kể cả `APPLICATION_REJECTED`. A chỉ drain close events từ coordinator; B không drain.

## 4. Kiểm thử và hạn chế

**Đã kiểm thử trong môi trường bản sao:**
- 24 test dispatcher: True/False/exception, code và offset không bằng 0, không retry, không tăng credit khi lỗi, sender raise sau side effect, callback ngoài lock, đóng session giữa callback/confirm, duplicate, reassembly, WINDOW_UPDATE qua UDP loopback, coordinator đóng session/cleanup.
- 684 regression tests PASS (Python 3.13.5).
- Smoke với `main.py` của A + **A16/A17 giả lập** + UDP socket thật: DATA stream 0 → callback → sender hook → client response; False → hook bốn tham số → A Registry.close → coordinator cleanup.
- **Chưa** kiểm thử AUTH/Chat *thật* vì A chỉ bàn giao `main.py`, không kèm source A16/A17. Phải merge với branch A thực tế rồi chạy integration end-to-end.

**Điểm cần chú ý:** Khi failure hook A tự raise, B ghi log và giữ pause, không retry callback. Nếu A không cài đặt hook thì B ghi lỗi nhưng không tự đóng Registry, kết nối có thể pause đến timeout; wiring A đầy đủ là bắt buộc khi triển khai thật.

## 5. Thay đổi source

- **Patch B incremental:** chỉ sửa `server/reliable_dispatcher.py` và `tests/test_b442_delivery_dispatcher.py`.
- **Patch B full:** tạo hai file trên, thêm `is_delivery_connection_active()` vào `server/udp_service.py`.
- **Patch A:** chỉ sửa `server/main.py`, phải do A review.
- **Không thay đổi:** AES-GCM, stream codec, ACK/RTO, scheduler, CUBIC, raw UDP wire format.

Nếu bạn đã áp dụng patch và commit, file `.patch` không còn cần thiết để chạy chương trình; tests nên giữ trong repository.
