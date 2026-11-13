# A + B: chạy TLS → UDP REGISTER → AUTH → Chat thực tế

**Nền:** ZIP B `feature-thanhvienB (3)` ngày 13/11/2026, giữ nguyên UDP codec, CUBIC, loss, retransmission và dispatcher của B. Phía A bổ sung wiring `server/main.py`, client session/CLI và tests.

## Kết quả đã kiểm tra

- `python -m unittest tests.test_a_b_live_network -v`: **2/2 PASS** — dùng socket TCP/TLS + UDP thật; hai client `an` và `binh` đăng nhập, chat direct và broadcast; case sai mật khẩu nhận `AUTH_FAIL`. Tài khoản và chứng chỉ chỉ được tạo trong thư mục tạm của test, **không dùng session fixture**.
- `python -m scripts.run_all_tests`: **733/733 PASS** (chạy trên máy kiểm thử với Python 3.13, không khẳng định kết quả Windows trước khi chạy tại đó). Có các regression tests của B và A, kể cả callback failure.
- Test mạng localhost chưa thay thế kiểm thử hai máy LAN, packet loss 5–10%, timeout và load 20 clients.

## Cách dùng an toàn trên Windows PowerShell

**Nên thử trên thư mục mới**, không chép cả ZIP lên branch A hiện tại. Giải nén `network-collab-v1-A_B-live-demo-safe.zip` và mở terminal trong `network-collab-v1` của bản giải nén.

Cài dependency:

```powershell
python -m pip install -r requirements.txt
```

Kiểm tra **không cần tạo dữ liệu tài khoản/cert vào project**:

```powershell
python -m unittest tests.test_a_b_live_network -v
python -m scripts.run_all_tests
```

Để chạy 2 client thủ công, tạo certificate và **tài khoản demo** (không chạy trên hệ thống có `config/users.json` thật — script sẽ ghi đè):

```powershell
python -m scripts.gen_cert
python -m scripts.create_test_users
```

Terminal 1 — server:

```powershell
python -m server.main --host 127.0.0.1 --idle-timeout-s 120
```

**Cờ `--idle-timeout-s 120` chỉ phục vụ demo tương tác bằng tay**, không tuân thủ timeout 10 giây trong protocol khi chưa có heartbeat. Khi nghiệm thu giao thức, bỏ cờ và B phải bổ sung heartbeat PING/PONG 2 giây để giữ connection hợp lệ.

Terminal 2 — client An:

```powershell
python -m client.cli --user an
```

Mật khẩu demo: `an123456` (nhập trong prompt của `getpass`, không nằm trong command line).

Terminal 3 — client Bình:

```powershell
python -m client.cli --user binh
```

Mật khẩu demo: `binh123456`. Từ client An nhập:

```text
/to binh Xin chao Binh
```

Ở client Bình sẽ xuất hiện `[direct] an: Xin chao Binh`. Từ Bình nhập:

```text
/all Chao ca phong!
```

Cả hai client nhận `[broadcast] binh: Chao ca phong!`. Dùng `/quit` để dừng client; Ctrl+C để dừng server.

## Ghép vào branch Git A hiện tại

Không dùng `git merge` hoặc giải nén ZIP toàn bộ đè thẳng lên thư mục làm việc. Vì B đã thay nhiều module UDP, làm theo thứ tự:

1. Commit/backup code A, tạo branch `integration/a-b-live-runtime`.
2. Dùng **full ZIP B (3)** hoặc merge branch B mới nhất để có `server/udp_service.py` với `auto_drive`, `server/reliable_dispatcher.py` và bộ `common/reliable_receive.py` của B. Không dùng B3.1 cũ.
3. Chép **các file trong `A_B_LIVE_A_only_patch.zip`** (chọn lọc) vào branch đã có B mới nhất. File `server/main.py` là phiên bản A đã review, thay thế wiring patch B nếu chưa áp dụng. **Không áp dụng B442 FINAL A MAIN patch thêm lần nữa**.
4. `python -m unittest tests.test_a_b_live_network -v`, rồi `python -m scripts.run_all_tests`.
5. Dùng `git diff --check`, xem `git diff -- server/main.py server/auth.py client/`, rồi mở Pull Request để B review. Nếu có thay đổi ngoài dự kiến, không ghi đè.

Trong `server/main.py`, `enable_reliable_bridge=True` theo mặc định (chạy thật). Một số regression test A cũ sử dụng mock sender và gọi hook thủ công, vì vậy chúng được cập nhật dùng `enable_reliable_bridge=False` trong **fixture test**. Không tắt bridge trong server demo.

## Phân công A/B còn lại

- A: `server/main.py`, session auth/chat, `client/core/session.py`, CLI, lifecycle và ứng dụng sau đăng nhập.
- B: reliable transport UDP, scheduler, CUBIC integration, ACK, flow control, retransmit, PING/PONG và kiểm thử mất gói/mạng thật.
- Chưa hoàn tất: heartbeat PING/PONG, phát hiện session bị server đóng ở client, reconnect/resume, UI/HTTP bridge, file transfer, kiểm thử loss 5–10% và LAN. `client/cli.py` phục vụ demo/troubleshooting, **chưa phải client hoàn thiện**.

## Lưu ý bảo mật

- ZIP an toàn không có `certs/server.key`, `certs/server.crt`, `config/users.json`, cache hay file `.part`.
- Không push tài khoản demo, khóa TLS, khóa phiên AES hoặc log chứa password lên GitHub.
- Client luôn kiểm tra hostname/IP trong SAN của certificate. Nếu test LAN, tạo chứng chỉ có SAN IP bằng `python -m scripts.gen_cert --san-ip <IP_MAY_SERVER>` và chỉ chép `server.crt` sang máy client; dùng `--trust <duong_dan_crt>` trong CLI. Mở firewall TCP 9000 và UDP 9001 khi cần.
