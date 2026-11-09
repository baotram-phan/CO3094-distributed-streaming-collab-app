# KẾ HOẠCH KIỂM THỬ HAI MÁY — A/B (2026-11-09)

> **Trạng thái:** KẾ HOẠCH, chưa có kết quả LAN được xác minh.  
> **Nguồn:** Assignment 1; Giải đáp Assignment 1; `PROTOCOL_SPECIFICATION_v1_PROPOSED`; `INTEGRATION_CONTRACT_v1_1_review`.  
> **Thứ tự ưu tiên:** Assignment → giải đáp giảng viên → protocol của nhóm (đang PROPOSED) → integration contract (đang REVIEW).  
> **Nguyên tắc:** Chỉ ghi PASS sau khi chạy đúng lệnh trên đúng Git commit, lưu bằng chứng. Không dùng kết quả demo loopback thay kết quả LAN.

## A. Phân biệt ba môi trường

| Môi trường | Cấu hình | Chứng minh được | Chưa chứng minh |
|---|---|---|---|
| Unit/local | Module `common/`, unit tests | Logic packet/crypto/replay/state | UDP networking, integration |
| Local multi-process | Server + client riêng, cùng máy qua `127.0.0.1` | Socket thật và integration ở mức loopback | Giao tiếp giữa hai máy, firewall/LAN |
| **Hai máy LAN** | Máy A chạy server, máy B chạy client (đảo chiều vai trò nếu có thể) | TCP/TLS bootstrap, UDP REGISTER và app traffic giữa các host | Chịu loss/concurrency/file integrity nếu chưa chạy test tương ứng |

## B. Những điều PHẢI chốt trước khi kiểm thử LAN

- Cùng một Git commit (hoặc cùng release tag) trên cả hai máy; kiểm tra `git rev-parse HEAD`. Không lấy code khác phiên bản rồi so sánh kết quả.
- Python theo cấu hình dự án (bản protocol đề xuất **Python 3.12+**); phụ thuộc từ file môi trường chung **sẽ được chốt**, không coi bản `requirements.txt` là đã tồn tại khi chưa kiểm tra.
- **Không ghi đè** `common/constants.py` của A bằng B: đối chiếu `PROTOCOL_VERSION` và `WIRE_VERSION`, giữ cả import bootstrap và UDP hoạt động.
- Chốt một tên module service thật (`server/udp_service.py` do A đề xuất; còn chờ A/B xác nhận). Một tiến trình server phải sử dụng **cùng instance `SessionRegistry`** cho bootstrap và UDP service.
- UDP listener server bind interface LAN (`0.0.0.0` hoặc LAN IP do cấu hình), không chỉ `127.0.0.1`; TCP listener cũng phải truy cập được từ máy B. Giá trị mặc định protocol: TCP/TLS `9000`, UDP `9001`; có thể cấu hình.
- Client kết nối đến **IP/DNS LAN của server**, lấy UDP port từ HELLO_ACK; UDP client phải dùng cùng socket/endpoint trong vòng đời phiên vì v1 không hỗ trợ rebinding.
- Bootstrap TLS phải **xác minh chứng chỉ server** qua CA/certificate đã phân phối hợp lệ; tên DNS/IP dùng khi kết nối phải phù hợp SAN của chứng chỉ. **Không dùng `CERT_NONE` hoặc bỏ kiểm tra chứng chỉ để vượt bài test**.
- Windows Firewall: cho phép chính xác inbound TCP 9000 và UDP 9001 trên profile Private/LAN của máy server (tùy config); **không tắt toàn bộ firewall**. UI HTTP mỗi client chỉ bind `127.0.0.1:8765`, không mở UI ra LAN.
- Không commit private keys TLS, UDP session keys, password, file bí mật hay log chứa các dữ liệu đó. Chỉ chia sẻ CA/public certificate cần thiết để xác thực TLS.
- Trước khi chạy test: A xác nhận deadline REGISTER 10s, AUTH 30s từ first UDP bind, idle 10s, heartbeat 2s; xử lý cleanup `drain_closed_events()` → `transport.remove_connection()`.

## C. Lệnh tiền kiểm cho Windows PowerShell (có thể chạy ngay)

Trên **cả hai máy**, trong thư mục gốc repository:

```powershell
python --version
python -m pip --version
python -m pip check
git rev-parse HEAD
git status --short
python -m unittest discover -s tests -v
```

Trên **máy chạy server**:

```powershell
ipconfig
```

Trên **máy client**, với `<SERVER_LAN_IP>` do nhóm điền:

```powershell
Test-NetConnection <SERVER_LAN_IP> -Port 9000
```

> `Test-NetConnection -Port` ở đây chỉ xác minh **TCP 9000**. Nó **không kiểm tra UDP 9001**; UDP chỉ được chứng minh bằng REGISTER/REGISTER_OK thực tế. `ping` thất bại không nhất thiết đồng nghĩa TCP/UDP bị chặn (ICMP có thể bị chặn).

### Lệnh chạy ứng dụng chính thức

**Chưa thể cung cấp lệnh chạy thật** vì chưa xác minh entrypoint server/client sau merge. A+B phải cập nhật README bằng lệnh chính xác và các tham số `--host`, `--server-host`, `--tcp-port`, `--udp-port`, `--ca-cert` hoặc tên tương đương mà source thực tế hỗ trợ. **Không giả định các tùy chọn CLI đã tồn tại.**

## D. Kịch bản kiểm thử A/B theo thứ tự

| ID | Kịch bản | Máy thực hiện | Điều kiện PASS và bằng chứng |
|---|---|---|---|
| L00 | Cùng version | A+B | Git hash trùng; unit tests chạy trên cả hai máy |
| L01 | TCP/TLS Bootstrap | A server, B client | HELLO/HELLO_ACK; client xác thực chứng chỉ; nhận ConnID/2 keys khác nhau; **sai trust/cert phải bị từ chối** |
| L02 | UDP REGISTER thực tế | A server, B client | REGISTER encrypted, server lấy key từ shared registry, bind đúng IP/UDP source port, client xác thực REGISTER_OK, registry `UDP_BOUND`, chưa `ONLINE` |
| L03 | Retry/replay | A+B | Cùng datagram/pkt_num: drop; REGISTER mới/pkt_num mới: OK mới, `newly_bound=False`, không reset AUTH deadline |
| L04 | Lỗi UDP | A+B | ConnID lạ, sai key/tag, packet size sai, endpoint khác: drop; không tạo session, không crash |
| L05 | Timeout/cleanup | A+B | 10s REGISTER/idle, 30s AUTH theo contract; heartbeat không kéo dài AUTH; close event dẫn đến xóa state B |
| L06 | AUTH trên reliable stream 0 | A+B | AUTH/AUTH_OK/FAIL qua UDP DATA reliable, không qua TCP; ONLINE/presence đúng và không phát trùng |
| L07 | Chat direct/broadcast | 2–3 client qua LAN | Đúng người nhận; không lộ sender giả; ACK app không nhầm đã xem |
| L08 | Reliable DATA/ACK | A+B + simulator | Loss 0%, 5%, 10%; reorder/delay/ACK loss, retransmit chọn lọc với pkt_num mới; không giao data trùng |
| L09 | File 1-1 | A client → server → B client | File 0B, 1KiB, 1MiB, 10MiB; sha256 khớp, server relay hữu hạn; không dùng TCP mang file |
| L10 | Cross-stream HoL | A+B | Vừa chuyển file 10MiB có loss, chat vẫn được giao khi file stream bị thiếu chunk; lưu timestamp/log |
| L11 | CUBIC + flow | A+B | Có log cwnd/bytes_in_flight, không vượt credit; đồ thị cwnd dưới loss, B tích hợp controller của A |
| L12 | 10–20 concurrent clients | A+B | Tối thiểu 10–20 client theo đề, không nhầm session/keys, không treo; kiểm tra cleanup |
| L13 | UI | Mỗi máy tự mở local UI | Browser kết nối `127.0.0.1:8765` cục bộ, trạng thái/login/chat/file progress chính xác; UI không mở ra LAN |

**Lưu ý trạng thái:** `L01–L13` hiện là **chưa kiểm chứng LAN**; không đánh dấu PASS vì 33 tests B hoặc 54 tests A đã được báo. Các test thuộc bản protocol nhóm đề xuất; 10 milestone của assignment ở file `REQUIREMENTS_TRACEABILITY.md`.

## E. Quy trình kiểm tra và xử lý lỗi LAN

1. Kiểm tra Git commit/version, import Python, dependencies và unit tests trên **hai máy**.
2. Chạy server duy nhất có **cùng registry instance** với TLS và UDP; xác nhận log server đang lắng nghe TCP/UDP ở đúng interface LAN.
3. Kiểm tra khả năng kết nối TCP 9000 từ máy còn lại, TLS handshake và certificate validation. Không bỏ qua TLS verification.
4. Sau HELLO_ACK, gửi REGISTER qua UDP 9001; nếu không có REGISTER_OK, kiểm tra firewall UDP, địa chỉ đích, bind interface, session deadlines, khóa/nonce và nguồn UDP endpoint.
5. Kiểm tra close/retry không dùng lại khóa cũ hoặc packet number 0 trong cùng khóa; không tự thay endpoint (v1 không hỗ trợ NAT rebinding).
6. Mở rộng test AUTH, chat, file, loss, concurrency và UI **chỉ sau khi** luồng REGISTER thật đạt.
7. Lưu kết quả theo `docs/TEST_EVIDENCE_TEMPLATE.md`; ghi FAIL/BLOCKED đầy đủ, không xóa dấu vết lỗi.

## F. Quy tắc xác nhận giữa hai thành viên

- A làm owner của TLS Bootstrap, SessionRegistry, app, CUBIC, loss simulator; B owner UDP packet/AEAD/replay/REGISTER, reliability, streams, flow, transport state.
- Khi merge: mỗi bên review code phía còn lại ở ranh giới API; bổ sung test contract và cập nhật `docs/DEVELOPMENT_LOG.md`, `docs/INTEGRATION_STATUS.md` cùng PR/commit.
- Báo cáo cuối cùng cần bằng chứng chạy trên **máy A và máy B**, kịch bản LAN, thông số loss, log được ẩn bí mật, hash file, UI screenshot và biểu đồ cwnd.
