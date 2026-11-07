# A1.3 — TCP/TLS Bootstrap: hướng dẫn Windows / PowerShell

**Phạm vi:** TCP/TLS `HELLO` -> `HELLO_ACK`, cấp `ConnID` và hai khóa UDP 32-byte qua TLS; **chưa** có UDP REGISTER, UDP AUTH hay login thành công. Module chạy demo tạm thời, đến A1.4 sẽ lưu các phiên có timeout trong `server/sessions.py`.

## Chép file

Giải nén ZIP overlay này rồi chép các thư mục `common`, `scripts`, `server`, `examples`, `tests`, `docs` vào thư mục gốc `network-collab-v1` của bạn. Chọn **merge thư mục**, không xóa project cũ. Overlay không chứa `server/auth.py`, `config/users.json`, hoặc `tests/test_auth.py` để tránh mất dữ liệu.

## Lệnh (terminal gốc project)

1. `python -m pip install cryptography`
2. `python -m scripts.gen_cert`
3. `python -m unittest tests.test_bootstrap -v` → 2 tests PASS.
4. `python -m unittest discover -s tests -v` → 14 tests cũ + 2 mới = 16 PASS (nếu project cũ có 14 tests).
5. Mở Terminal A: `python -m examples.bootstrap_server`
6. Mở Terminal B: `python -m examples.bootstrap_client`

Dự kiến client sẽ in `TLS: TLSv1.3` hoặc `TLSv1.2`, `HELLO_ACK OK`, `ConnID=...`, `UDP port=9001`. Server in `conn_id=...` khớp client. Khóa không được in ra.

## Giải thích nhanh

- `scripts/gen_cert.py`: sinh `certs/server.crt` (public certificate) và `certs/server.key` (private key) cho môi trường học tập.
- `common/tls.py`: server TLS context dùng cert + key; client TLS context **tin cậy certificate cụ thể** và kiểm tra hostname/IP.
- `server/bootstrap.py`: nhận JSON HELLO qua framing TCP cũ, cấp ConnID 64-bit, hai khóa ngẫu nhiên cho hai chiều UDP, gửi HELLO_ACK qua TLS.
- `examples/bootstrap_server.py`: chạy server demo, giữ phiên bootstrap tạm trong RAM. **Không đủ để production**, chưa có timeout 10 giây và chưa làm UDP REGISTER.
- `examples/bootstrap_client.py`: mở TLS socket, gửi HELLO, nhận ACK, kiểm tra kết quả.
- `tests/test_bootstrap.py`: kiểm thử kết nối TLS thật trên localhost và **đảm bảo certificate sai bị từ chối**.

## Bảo mật

`certs/` phải có trong `.gitignore` (sườn hiện tại đã có). Không chia sẻ `server.key`, không ghi log khóa UDP hay mật khẩu. Chứng chỉ sinh sẵn có SAN `localhost` và `127.0.0.1`: chưa hỗ trợ dùng một địa chỉ LAN khác. Khi lên LAN hãy sinh chứng chỉ có SAN cho IP/tên miền LAN và phân phối **chỉ** certificate cho client. Trong demo, client phải dùng file certificate tin cậy phù hợp. Không thêm `CERT_NONE` hoặc tắt kiểm tra hostname để sửa lỗi.

## Nối tiếp

A1.4: chuyển dictionary `pending` sang `server/sessions.py`, kiểm soát `conn_id` trùng và expiration 10 giây. A1.5: B triển khai AES-GCM UDP REGISTER (phải chứng minh sở hữu key); sau REGISTER mới dùng `verify_password` cho UDP AUTH. **Không gửi password qua TCP bootstrap.**
