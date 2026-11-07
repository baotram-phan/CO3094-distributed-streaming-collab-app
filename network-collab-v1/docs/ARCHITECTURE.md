# Kiến trúc dự kiến

```text
Browser (HTML/JS)
        | HTTP/SSE localhost, không dùng WebSocket
Python client core (A)
        |                   \
        | TCP/TLS bootstrap  \ Reliable UDP (B, dùng CUBIC của A)
        v                     v
TCP bootstrap (A)        UDP transport (B)
        \                   /
              SERVER (A: sessions/router/transfers)
                  |
               UDP relay
                  |
             Other clients
```

TCP chỉ dùng bootstrap/điều khiển; **không chở nội dung chat hoặc file**.
Sau bootstrap, UDP mã hóa AUTH, unicast, broadcast và file. Mỗi file dùng stream riêng.

### Trạng thái tối thiểu
`DISCONNECTED → TCP_TLS_CONNECTING → BOOTSTRAPPED → UDP_BOUND → ONLINE → CLOSED`.

### Kênh dữ liệu
- UDP packet: `conn_id + packet_number + ciphertext + AES-GCM tag`.
- ACK tham chiếu packet number; offset tham chiếu vị trí byte trong stream.
- Không dùng lại nonce trong cùng key; packet retransmit phải có packet number mới.

### Các điểm chưa được thầy xác nhận riêng cho Python
- `http.server` chuẩn Python chỉ chạy local interface tương tự Go `net/http`.
- TLS bootstrap cấp AES-GCM UDP key là thiết kế nhóm đề xuất.
- Tin nhắn unicast chạy UDP theo tài liệu giải đáp viết, khác chỉ dẫn miệng cũ.
