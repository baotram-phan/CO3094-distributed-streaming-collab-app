# A1.5 — Sửa ba lỗi lifecycle được B review (2026-11-10)

## Áp dụng cho phiên bản nào?

Patch **chỉ** dành cho project đã tích hợp `A1_5_Official_Integration_patch.zip` + `A1_5_B_2026_11_09_compat_patch.zip` của các bước trước (hoặc branch hiện tại có `server/main.py`, `server/udp_service.py`, `common/transport_manager.py`, `SessionRegistry.bind_udp_verified_with_status`). **Không áp dụng thẳng trên skeleton hay branch B độc lập.** Patch không chỉnh sửa `common/crypto.py`, `common/udp_packet.py`, `common/transport_manager.py`, `server/sessions.py`.

## Danh sách file

- `server/main.py`: duy nhất A coordinator drain Registry close queue; gọi B `remove_connection`, callback offline ngoài locks.
- `server/udp_service.py`: xóa `dispatch_closed_events`, thêm lifecycle lock/tombstone và double-check session quanh manager.add; callback `on_udp_registered(conn_id, endpoint)`.
- `tests/test_a1_5_lifecycle_contract.py`: 7 regression tests gồm close-event, presence offline, races, callback.
- `docs/INTEGRATION_CONTRACT_v1_1_APPROVED_ADDENDUM.md`: xác nhận quyền sở hữu, concurrency, API và giới hạn.

## Windows PowerShell

```powershell
# Đang ở thư mục gốc network-collab-v1:
git status
# Nếu worktree còn thay đổi chưa commit: commit hoặc stash trước

git switch feature/thanhvienA
git switch -c fix/a1-5-lifecycle

# ZIP tải từ ChatGPT, đổi đường dẫn thành vị trí thực tế
Expand-Archive -Path "$HOME\Downloads\A1_5_Lifecycle_A_B_Fix.zip" -DestinationPath . -Force

python -m unittest tests.test_a1_5_lifecycle_contract -v
python -m unittest tests.test_a1_5_official_integration -v
python -m unittest discover -s tests -v

git diff -- server/main.py server/udp_service.py
git status
```

Trong bản testbed của assistant đã ghép các patch A+B và kiểm thử bằng Python 3.13: **7 regression tests mới PASS và tổng 117/117 tests PASS**. Số lượng trên máy bạn có thể khác (tùy branch/test hiện có). Dừng và gửi traceback nếu có FAILED/ERROR.

Sau khi test PASS:

```powershell
git add server/main.py server/udp_service.py tests/test_a1_5_lifecycle_contract.py docs/INTEGRATION_CONTRACT_v1_1_APPROVED_ADDENDUM.md
git commit -m "fix(integration): coordinate session cleanup and prevent UDP state resurrection"
git push -u origin fix/a1-5-lifecycle
```

Tạo Pull Request hướng đến branch tích hợp do nhóm thống nhất; nhờ B review riêng UDP service/race vì liên quan phần B. Không push thay đổi này trực tiếp vào branch B và không merge bừa `constants.py`.

## Phân tích kỹ giới hạn race

Bản sửa có tombstone lưu tới khi server process kết thúc và kiểm tra session trước + sau `state.add`. Nó **ngăn tạo lại transport state sau khi coordinator đã cleanup**; nếu `close()` diễn ra giữa các lần kiểm tra, lần sau sẽ xóa state. Tuy nhiên, như mọi thiết kế xử lý network bất đồng bộ, ACK có thể đã được phát khi một `close()` đồng thời vừa bắt đầu. Nếu rubric/contract về sau yêu cầu linearizability mạnh hơn (ACK tuyệt đối không xuất sau mọi close), hai bên phải thiết kế một lock/protocol vòng đời chung cho Registry.close + UDP send; tránh tự phát triển hai lock ngược chiều.

## Sau khi sửa

1. Chạy localhost: `python -m server.main` và `python -m examples.a1_5_official_client` trên hai terminal.
2. Nhờ B chạy lại regression tests của B trên source tích hợp.
3. Chạy cross-machine/LAN theo kế hoạch test hiện có.
4. Chỉ sau khi A1.5 được hai máy xác nhận, bắt đầu A1.6 reliable control stream + AUTH.
