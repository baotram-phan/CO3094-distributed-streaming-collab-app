# Kiểm thử và demo bản hiện tại

## Kiểm thử tự động

Tại thư mục gốc, chạy:

```powershell
python -m scripts.run_all_tests
```

Runner tạo tài khoản test tạm, giữ nguyên tài khoản thật của project. Kết luận dựa trên dòng cuối (`OK`, `FAILED`, `skipped`), không dựa vào một traceback giữa log. Các test dispatcher có chủ đích tạo exception để kiểm tra xử lý lỗi.

Các nhóm test khi cần khoanh vùng:

```powershell
python -m unittest tests.test_duplicate_login_isolation -v
python -m unittest tests.test_gui_bridge tests.test_gui3_chat tests.test_gui4_file tests.test_gui5_resilience -v
python -m unittest tests.test_file_live tests.test_gui_b52_integration -v
python -m unittest tests.test_b51_loss_recovery tests.test_b51b_reorder_duplicate_hol tests.test_b52_heartbeat_resilience -v
```

Nhóm loss/reorder có mô phỏng mạng, không tự tạo ra bằng chứng đã chạy LAN hoặc mọi tổ hợp kích thước file/mức mất gói.

## Các test đang skip trên Windows

Các decorator có sẵn được giữ nguyên, không thêm hoặc xóa test trong đợt dọn code này:

| Test | Lý do/giới hạn |
|---|---|
| `TestGUIBridgeUnit.test_post_requires_token` | HTTP từ chối sớm có thể reset kết nối Windows |
| `TestGUI3BridgeUnit.test_reject_extra_chat_fields_and_missing_token` | HTTP từ chối sớm trên Windows |
| `TestGUI4FileAPI.test_upload_validates_filename_and_size` | HTTP upload bị từ chối trên Windows |
| `RejectedPostSocketTests.test_many_unauthorized_json_posts_return_clean_http_403` | WinError 10053 chưa được xử lý dứt điểm |
| `TestUDPReceiveIsolation.test_unrelated_connection_reset_is_not_swallowed` | Giả định errno trong test không phù hợp Windows |

`OK (skipped=5)` không phải tất cả tests đều PASS. Số skip thực tế phụ thuộc môi trường và phiên bản đang chạy. Test tích hợp đăng nhập trùng vẫn được chạy.

## Demo nhiều terminal trên localhost

Khởi động server và ba Bridge ở 8000/8001/8002 theo README. Dùng An, Bình, Chi với tài khoản thực có trong cấu hình.

| Bài thử | Thao tác | Kết quả cần quan sát |
|---|---|---|
| Đăng nhập/online | Đăng nhập lần lượt ba tài khoản | Danh sách người dùng cập nhật đúng |
| Mật khẩu sai | Dùng Bridge thứ tư đăng nhập sai | Không vào ONLINE; phiên cũ không rớt |
| Đăng nhập trùng | Mở Bridge 8003, đăng nhập An đang online | Chỉ lượt mới bị từ chối; chờ 15 giây, ba client cũ vẫn chat |
| Chat riêng | An gửi Bình | Bình nhận đúng một lần; Chi không nhận |
| Chat chung | Bình gửi Global Chat | Cả ba nhận đúng một bản |
| Nhận file | An gửi file nhỏ, Bình accept | File hoàn tất; kích thước và SHA-256 khớp |
| Từ chối/lượt tiếp | Reject một file, rồi gửi file khác | Trạng thái đúng, không kẹt transfer |
| File lớn | Thử lần lượt 5, 20, 50 MiB | Hoàn tất và hash khớp từng file |
| Vượt giới hạn | Thử 51 MiB hoặc file rỗng | Bị từ chối; sau đó vẫn gửi file hợp lệ được |
| Chat khi gửi file | Gửi file lớn và chat khi file còn truyền | Chat tiếp tục hoạt động, file cuối cùng hash khớp |
| Heartbeat | Idle 30–60 giây rồi chat | Phiên vẫn hoạt động |
| Server tắt | Ctrl+C server khi online/đang truyền | GUI báo mất phiên, không báo file thành công giả |
| Khôi phục | Chạy server, đăng nhập lại | Chat/file hoạt động; không tự phát lại lệnh cũ |
| Bridge tắt | Chỉ tắt Bridge An | An báo lỗi HTTP; Bình/Chi vẫn hoạt động |

Đối chiếu file bằng PowerShell, thay bằng đường dẫn thực tế:

```powershell
Get-FileHash -LiteralPath "D:\Demo\original.pdf" -Algorithm SHA256
Get-FileHash -LiteralPath "C:\Users\LENOVO\Downloads\received.pdf" -Algorithm SHA256
```

## Khi chạy LAN

Server phải bind địa chỉ có thể truy cập (ví dụ `--host 0.0.0.0`). Chứng chỉ cần SAN chứa IP server, client phải tin đúng chứng chỉ. Cho phép TCP 9000/UDP 9001 trên mạng thử nghiệm. Bridge vẫn bind localhost tại mỗi máy client.

Ví dụ khi đã cấu hình chứng chỉ phù hợp:

```powershell
# Máy server
python -m server.main --host 0.0.0.0
# Máy client: thay 192.168.1.10 bằng IP server thực, dùng cert được sao chép từ server.
python -m client.bridge.http_server --server-host 192.168.1.10 --trust .\certs\server.crt --port 8000
```

Không sao chép private key sang client. Ghi nhận riêng kết quả LAN, mức mất gói, kích thước file, thời gian và hash; không suy ra đã đạt từ test localhost.

## Kết quả kiểm tra đợt dọn source

- Nền gốc: 808 tests, OK trên Linux.
- Sau dọn: 808 tests, OK trên Linux.
- 114 module Python giữ nguyên AST thực thi sau khi loại thông tin docstring; JavaScript giữ nguyên AST thực thi sau khi loại metadata định dạng/comment.
- Tài khoản, chứng chỉ, HTML, CSS và dependency runtime giữ nguyên bytes. Không đổi API, tên module hoặc quy tắc SKIP.
- Black 25.1.0 và Prettier 3.5.3 kiểm tra định dạng đạt.
- Đây không phải kết quả nghiệm thu trên Windows hoặc mạng LAN thực tế.
