# A1.5 — UDP Registration thật (bản tích hợp tham chiếu)

**Trạng thái:** Code chạy và kiểm thử bằng adapter AES-GCM trong `examples/`. **Chưa tích hợp source UDP chính thức của B.** Không đánh dấu A1.5 hoàn tất toàn nhóm chỉ dựa trên demo này.

## 1. Mục tiêu

- Giữ nguyên 40 bài test A1.1–A1.4.5.
- Dùng **cùng một `SessionRegistry`** trong một tiến trình phục vụ TCP/TLS và UDP.
- Client bootstrap qua TLS, nhận `conn_id`, `c2s_key`, `s2c_key` thật.
- Client gửi REGISTER mã hóa bằng `c2s_key` trên UDP.
- Server giải mã, chống replay, bind endpoint rồi phản hồi REGISTER_OK bằng `s2c_key`.
- Client kiểm tra AES-GCM ở REGISTER_OK. Không dùng `ConnID=42` hoặc khóa demo.

**Không thuộc A1.5:** AUTH qua reliable stream, PING/PONG, dữ liệu chat/file, congestion control. Chúng sẽ được phát triển trong các bước sau.

## 2. Những file mới — không ghi đè code B

```text
examples/a1_5_reference_udp.py     # Adapter REGISTER tạm để học/kiểm thử; sẽ thay bằng B
examples/a1_5_server.py            # TCP/TLS + UDP chung tiến trình, chung registry
examples/a1_5_client.py            # TLS bootstrap rồi UDP REGISTER
 tests/test_a1_5_register.py       # 7 tests mới
 docs/A1_5_IMPLEMENTATION_GUIDE.md
```

Không thay đổi `server/sessions.py`, `server/bootstrap.py`, `common/tls.py`, `tests/test_sessions.py` và **mọi file của B**.

## 3. Cài môi trường và chạy tests (Windows PowerShell)

Mở terminal trong thư mục chứa `common/`, `server/`, `examples/`, `tests/`.

```powershell
python -m pip install -r requirements.txt
# Nếu requirements.txt chưa khai báo: python -m pip install cryptography
python -m unittest tests.test_a1_5_register -v
python -m unittest discover -s tests -v
```

Với đúng bộ test cũ: kỳ vọng **7 test mới, tổng 47 tests, OK**. Test tự sinh chứng chỉ trong thư mục tạm, không dùng `certs/` của bạn.

## 4. Chạy demo thủ công

Nếu bạn đã có `certs/server.crt` và `certs/server.key` từ A1.3, **không cần sinh lại**. Nếu chưa có:

```powershell
python -m scripts.gen_cert
```

**Đóng `examples.bootstrap_server` cũ**, vì nó đang dùng TCP port 9000. Cũng đóng server UDP của B đang giữ port 9001. Sau đó mở hai terminal:

Terminal 1:

```powershell
python -m examples.a1_5_server
```

Dự kiến:

```text
[SERVER] TCP/TLS :9000, UDP :9001
[TCP] BOOTSTRAPPED conn_id=...
[UDP] REGISTER_OK conn_id=... state=UDP_BOUND first=True peer=127.0.0.1:<client-udp-port>
```

Terminal 2:

```powershell
python -m examples.a1_5_client
```

Dự kiến:

```text
[CLIENT] TLS: TLSv1.3
[CLIENT] TLS HELLO_ACK conn_id=...
[CLIENT] REGISTER_OK verified, local UDP port=...
[CLIENT] A1.5 UDP_BOUND demo OK (AUTH not implemented yet)
```

Do chưa có UDP AUTH/PING, session sẽ **hết hạn sau 10 giây**. Đó là kết quả đúng ở thời điểm hiện tại.

Nếu các port đang được dùng, chạy server bằng:

```powershell
python -m examples.a1_5_server --tcp-port 19000 --udp-port 19001
```

Và client:

```powershell
python -m examples.a1_5_client --tcp-port 19000
```

`udp_port` được đọc từ HELLO_ACK; client không hardcode 9001.

## 5. Luồng trong code

### Server

`A15Server.__init__` khởi tạo **một** registry: `self.registry = SessionRegistry()`. Hai nhánh TCP và UDP đều dùng registry này.

- TCP: `handle_bootstrap(..., registry=self.registry)` → lưu BOOTSTRAPPED trước khi gửi `HELLO_ACK`.
- UDP: nhận `REGISTER`, parse header → `registry.get(conn_id)` → kiểm tra replay → AES-GCM decrypt → `registry.bind_udp_verified(conn_id, endpoint)` → phát `REGISTER_OK`.
- Cleanup: `cleanup_expired()` và `drain_closed_events()` dọn trạng thái liên quan.

`ConnID` không tự xác thực người dùng. Chỉ sau khi AES-GCM hợp lệ mới bind UDP endpoint.

### Client

- `examples.bootstrap_client.bootstrap()` thực hiện TLS, trả `conn_id` dưới dạng `int`, khóa dưới dạng bytes.
- `register_udp()` gửi REGISTER trong **cùng một UDP socket**, nhận và xác thực REGISTER_OK.
- Nếu timeout, gửi lại **datagram mới với packet number mới**, không gửi lại ciphertext cũ. Sau khi hết số lần thử thì báo lỗi.

## 6. Điểm cần thống nhất với B khi ghép source thật

Adapter `examples/a1_5_reference_udp.py` **không phải implementation của B** và không nên đưa vào transport chính thức. Nó chỉ triển khai REGISTER/REGISTER_OK và một replay-window mẫu. B thay bằng codec + state transport của B sau khi hai bên kiểm tra tương thích wire:

| Thành phần | Contract A/B |
|---|---|
| Header | `struct.pack('!HBBQQ', 0x4E43, 1, type, conn_id, pkt_num)` — 20 bytes |
| REGISTER | type `0x01`, plaintext rỗng, gói 36 bytes |
| REGISTER_OK | type `0x02`, plaintext rỗng, gói 36 bytes |
| Nonce | `4 byte zero + pkt_num.to_bytes(8, 'big')` |
| AAD | Header nguyên 20 byte |
| Keys | Server nhận bằng `c2s_key`, trả bằng `s2c_key` |
| Registry | B được `get`, `bind_udp_verified` sau khi xác thực; không tạo SessionRegistry khác |
| Duplicate REGISTER | Packet number mới → phản hồi REGISTER_OK mới; không reset `udp_bound_at` |
| Replay | Reject cùng packet number dù ciphertext đúng; commit **sau khi** xác thực/tag hợp lệ |
| Cleanup | A đóng session → B hủy transport state theo ConnID |
| Timeout | REGISTER 10s, AUTH 30s sau REGISTER, idle 10s |

**B sẽ tiếp tục làm** `udp_packet.py`, `crypto_udp.py`, `transport.py`, replay/ACK/streams. **A sẽ giữ** `SessionRegistry`, bootstrap, AUTH application. Đừng gộp code demo UDP trong `examples/` vào production transport.

## 7. Các bài test mới

1. Header/AEAD gói REGISTER 36 bytes.
2. Sai khóa và sửa header (AAD) bị từ chối.
3. ReplayWindow không chấp nhận packet number trùng; hỗ trợ reordering trong cửa sổ.
4. TCP/TLS thật → UDP REGISTER → UDP_BOUND, khóa phiên thật.
5. REGISTER trùng packet number bị bỏ; REGISTER mới có packet number mới nhận REGISTER_OK, không reset thời gian AUTH.
6. REGISTER dùng khóa sai không được bind endpoint.
7. REGISTER từ endpoint khác bị từ chối; endpoint chính xác vẫn có thể gửi packet number tiếp theo.

## 8. Tiêu chí hoàn thành

- **Demo A tham chiếu:** 47/47 tests pass; TLS + UDP REGISTER/REGISTER_OK thật.
- **A1.5 tích hợp nhóm:** B gửi source UDP codec/transport, cả hai ghép **chung một tiến trình/registry**, chạy những test tương đương trên source của B. Phải xác nhận phản hồi REGISTER_OK được B mã hóa và A nhìn thấy `UDP_BOUND`.
- **A1.6:** AUTH, AUTH_OK/FAIL qua UDP control stream đáng tin cậy, có retransmission dưới packet loss.
