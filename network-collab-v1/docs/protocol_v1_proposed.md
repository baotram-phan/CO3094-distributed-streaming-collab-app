# PROTOCOL SPECIFICATION — LAN Collaboration Application

**Version:** v1.0-proposed  
**Date:** 2026-11-02  
**Status:** DỰ THẢO ĐỂ HAI THÀNH VIÊN REVIEW VÀ XIN GIẢNG VIÊN XÁC NHẬN — **KHÔNG PHẢI chuẩn đã được phê duyệt**  
**Language:** Python 3.12+ (raw `socket`; được dùng thư viện mật mã tiêu chuẩn/phổ biến cho thuật toán mã hóa)  
**Reference priority:** (1) Assignment 1; (2) *Giải đáp Assignment 1* của giảng viên; (3) các lựa chọn thiết kế của nhóm. Khi các tài liệu chưa thống nhất, ghi rõ điểm cần hỏi lại thay vì tự coi là yêu cầu đã chốt.

> **Ghi chú cập nhật 2026-11-06:** Theo phân công mới: thành viên **A phụ trách CUBIC, network simulator, application/TLS/UI**; **B phụ trách UDP packet, encryption, ACK/retransmission, flow/streams**. Xem `docs/TEAM_OWNERSHIP.md`.

## 0. Phạm vi, quyết định và điểm còn chờ xác nhận

### 0.1. Phương án đề xuất

- Mạng **client–server**; server chuyển tiếp tin nhắn và **file 1-1**. Không hỗ trợ gửi cùng một file đến tất cả client trong phiên bản nộp.
- **TCP + TLS** chỉ thực hiện bootstrap (HELLO, HELLO_ACK, cung cấp ConnID/khóa UDP), **không mang nội dung chat hoặc file**.
- **UDP tự triển khai** mang AUTH, user list, tin nhắn riêng, chat chung, điều khiển file, dữ liệu file, heartbeat. Không dùng QUIC/KCP/transport library làm thay.
- Các **logical streams độc lập** trong mỗi kết nối UDP: stream 0 = control, stream 1 = chat, stream ≥2 = file.
- Tin cậy dùng **packet ACK ranges**, selective retransmission, RTT/RTO, packet-threshold loss, per-stream flow control, connection-level **CUBIC**.
- Bảo mật dùng **TLS có xác thực server** cho bootstrap, **AES-256-GCM** với khóa riêng cho mỗi chiều UDP. Password lưu PBKDF2-HMAC-SHA256.
- Web UI chỉ là lớp **HTTP trên localhost**, dùng HTML/CSS/JS và SSE; logic client–server không chạy qua HTTP/WebSocket.

### 0.2. Điểm cần giảng viên xác nhận trước khi coi là final

1. Hướng dẫn miệng trước nói unicast TCP, trong khi tài liệu giải đáp mới nói **mọi tin nhắn UDP**. Bản này tuân theo tài liệu mới và yêu cầu xác nhận quy định ưu tiên.
2. Tài liệu giải đáp cho phép `net/http` chuẩn của **Go** ở lớp UI cục bộ; nhóm đề xuất dùng **`http.server` của Python** với phạm vi tương đương, cần xác nhận.
3. Phương án **TLS cấp khóa phiên + AES-GCM UDP** là *lựa chọn của nhóm* (không phải yêu cầu chỉ định thuật toán), cần trình bày rõ để thầy duyệt.

## 1. Kiến trúc và trách nhiệm

```text
             CLIENT A                                         SERVER                                         CLIENT B
   Browser --HTTP localhost--> Python client           Python server/router                        Python client <--HTTP-- Browser
                                  |                          |                                                |
                                  +---- TCP/TLS bootstrap -->+<---- TCP/TLS bootstrap ----------------------+
                                  |                          |                                                |
                                  +==== Encrypted UDP ======>+====== Encrypted UDP ==========================>+
                                       stream 0: control      relay        stream 0: control
                                       stream 1: chat         relay        stream 1: chat
                                       stream 2+: file        relay        stream 2+: file
```

- Các cặp `(client, server)` có **ConnID và khóa riêng**. Một transfer qua relay tạo hai chặng vận chuyển tin cậy độc lập, mỗi chặng ACK riêng.
- **Broadcast ở tầng ứng dụng**: client gửi đến server một message; server gửi riêng một bản tới mỗi client ONLINE. Không yêu cầu IP broadcast của LAN.
- Lớp mạng, lớp xử lý ứng dụng và lớp UI phải tách nhau. UI chỉ trao đổi thông qua event queue/API nội bộ.

## 2. Quy ước và cấu hình mặc định

- Số nguyên nhiều byte: **unsigned, big-endian** (`struct` với ký hiệu `!`). Chuỗi: **UTF-8**.
- `CONTROL_PORT = 9000` (TCP/TLS), `UDP_PORT = 9001`, `UI_PORT = 8765` (chỉ bind `127.0.0.1`). Có thể đổi bằng config/CLI.
- `WIRE_VERSION = 1`; `MAX_UDP_DATAGRAM = 1200` byte (bao gồm header, ciphertext và GCM tag).
- `MAX_DATA_PER_PACKET = 1024` byte để có dư địa cho header và tag (DATA cần thêm 15 byte metadata; 20+15+1024+16=1075 byte <1200).
- `MAX_JSON_MESSAGE = 8192` byte; `MAX_CHAT_TEXT = 1000` byte UTF-8; `MAX_USERNAME = 32` ký tự ASCII `[A-Za-z0-9_.-]`.
- `MAX_FILE_SIZE = 50 MiB` (giới hạn **tự chọn**, có cấu hình); `MAX_ACTIVE_TRANSFERS_PER_USER = 1` ở bản đầu.
- `HEARTBEAT_INTERVAL = 2 s`, `UDP_IDLE_TIMEOUT = 10 s`, `BOOTSTRAP_UDP_TIMEOUT = 10 s`, `AUTH_TIMEOUT = 30 s`.
- `ACK_DELAY_MAX = 25 ms`, `ACK_RANGE_MAX = 16`, `RTO_INIT = 500 ms`, `RTO_MIN = 100 ms`, `RTO_MAX = 3000 ms`, `PACKET_LOSS_THRESHOLD = 3`.
- `CONTROL_CHAT_INITIAL_WINDOW = 64 KiB/stream`, `FILE_INITIAL_WINDOW = 512 KiB/stream sau khi FILE_START mở stream`, `FILE_RELAY_BUFFER = 512 KiB/transfer`.
- Các giá trị số trong mục này là **mặc định nhóm đề xuất**, không phải thông số thầy bắt buộc. Đặt tập trung ở `common/constants.py`.

## 3. Bootstrap bằng TCP + TLS

### 3.1. Kênh và framing

- TCP listener mở port cấu hình, TLS do Python `ssl.SSLContext` thiết lập; client **xác thực chứng chỉ** server bằng CA/certificate đã phân phối trước. Không dùng `CERT_NONE` trong sản phẩm demo chính thức.
- Sau khi TLS thành công, TCP messages dùng cấu trúc hiện có từ `common/control_framing.py`: `length:u32 | JSON_UTF8[length]`, length tối đa **65.536** byte.
- JSON envelope: `{ "v":1, "type":"...", "id":uint, "reply_to":uint|null, "body":object }`.
- Chỉ được gửi `HELLO`, `HELLO_ACK`, `BOOTSTRAP_ERROR` qua TCP. Không gửi `AUTH`, `CHAT_*`, `FILE_*` qua TCP.

### 3.2. Thứ tự bắt tay

1. Client mở TCP rồi hoàn thành TLS handshake và kiểm tra chứng chỉ.
2. Client gửi `HELLO { "client_version":"1.0" }`.
3. Server cấp duy nhất một `conn_id` ngẫu nhiên 64-bit khác 0 và sinh **hai khóa ngẫu nhiên 32 byte**: `c2s_key` (client→server), `s2c_key` (server→client).
4. Server gửi `HELLO_ACK { "conn_id":hex16, "udp_port":9001, "c2s_key":base64, "s2c_key":base64, "heartbeat_ms":2000, "udp_register_deadline_ms":10000 }`. Các khóa nằm **bên trong TLS**, không truyền plaintext trên đường mạng.
5. Hai bên đóng kết nối TCP; server giữ phiên ở trạng thái `BOOTSTRAPPED` tối đa 10 giây để chờ gói UDP.
6. Client gửi UDP `REGISTER` được mã hóa đến UDP port đã cấp. Server xác thực AES-GCM, kiểm tra `conn_id`, ghi nhận IP/port của datagram đầu tiên và trả `REGISTER_OK`. Nếu ACK mất, client gửi REGISTER mới với `pkt_num` mới (mỗi 500 ms, tối đa 10 lần); server xử lý lặp **idempotent**.
7. Sau `REGISTER_OK`, client gửi `AUTH` qua control stream UDP đã mã hóa; server kiểm tra username/password, quản lý phiên và trả `AUTH_OK`/`AUTH_FAIL`.

**Lưu ý:** `conn_id` không phải mật khẩu; nó dùng để tìm đúng phiên và khóa. Sở hữu khóa AES-GCM hợp lệ mới xác thực được UDP datagram. TCP source port không được xem là UDP source port.

### 3.3. Timeouts

- TLS/HELLO không hoàn thành trong 5 s → đóng TCP và xóa bootstrap state.
- UDP REGISTER không hoàn thành trong 10 s → hủy bootstrap state, client phải bootstrap lại.
- AUTH không xong trong 30 s sau REGISTER → hủy phiên. Sai mật khẩu 3 lần → đóng phiên.

## 4. UDP packet format (binary)

### 4.1. Header và mã hóa

```text
+-----------------+-----------+----------+----------------+----------------+
| magic:u16 = NC  | version:u8| type:u8  | conn_id:u64    | pkt_num:u64    |
+-----------------+-----------+----------+----------------+----------------+
| ciphertext:0..1164 bytes                                         |
+-------------------------------------------------------------------+
| AES-GCM authentication tag: 16 bytes                             |
+-------------------------------------------------------------------+
```

- Header cố định **20 byte**, tag 16 byte, ciphertext không quá **1164 byte**; tổng ≤1200.
- `magic = 0x4E43` (`NC`); `version = 1`.
- `pkt_num` tăng đơn điệu, bắt đầu bằng 0 **theo từng chiều của mỗi conn_id**; không dùng lại số packet dù gửi lại cùng dữ liệu.
- Header được dùng nguyên 20 byte làm AES-GCM **AAD**.
- `nonce` 12 byte = `0x00000000:u32 || pkt_num:u64`. Phương án này an toàn về tính duy nhất nonce nhờ **khóa riêng cho mỗi chiều** và không lặp pkt_num trong cùng phiên; khi restart/reconnect phải tạo khóa mới.
- Không xử lý dữ liệu ứng dụng khi AES-GCM kiểm tra tag thất bại. Header không hợp lệ hoặc replay → bỏ gói, rate-limit log.
- Chống phát lại bằng cửa sổ đánh dấu `pkt_num` đã thấy (mặc định 4096), cho phép packet đến sai thứ tự trong cửa sổ; không chỉ giữ giá trị lớn nhất.
- **Mỗi liên kết client-server có hai khóa UDP riêng**, không dùng chung key giữa các client. Chỉ ghi nhận `pkt_num` vào replay bitmap **sau khi** xác minh AES-GCM tag thành công.
- Mã hóa là **client↔server theo từng chặng**, không phải end-to-end: server có thể đọc nội dung chat/file để routing và relay; nêu rõ giới hạn này trong báo cáo. Không ghi khóa phiên và mật khẩu vào log.

### 4.2. Packet types

| type | Mã | Body plaintext sau khi giải mã | Ghi chú |
|---|---:|---|---|
| `REGISTER` | `0x01` | Rỗng | C→S; chứng minh sở hữu khóa UDP cấp trong bootstrap |
| `REGISTER_OK` | `0x02` | Rỗng | S→C; ACK logic của REGISTER |
| `DATA` | `0x10` | `stream_id:u32 | offset:u64 | flags:u8 | data_len:u16 | data` | Tin cậy, có thứ tự **trong stream** |
| `ACK` | `0x11` | `ack_delay_ms:u16 | range_count:u8 | [start:u64,end:u64] × count` | Xác nhận **packet numbers**, không xác nhận stream offset |
| `WINDOW_UPDATE` | `0x12` | `stream_id:u32 | max_offset:u64` | Cấp thêm credit gửi cho stream |
| `PING` | `0x20` | `timestamp_ms:u64` | Heartbeat, có thể yêu cầu ACK |
| `PONG` | `0x21` | `timestamp_ms:u64` | Echo timestamp |
| `CLOSE` | `0x30` | `code:u16` | Báo đóng phiên khi có thể |

`DATA.flags & 0x01` là `FIN` (kết thúc stream ở `offset + data_len`), các bit khác phải bằng 0. Packet với type không biết → bỏ. `ACK` dùng các đoạn `[start,end]` bao gồm cả hai đầu, không chồng lấn, sắp xếp giảm dần và tối đa 16 ranges; ACK hợp lệ phải có ít nhất 1 range. Bộ nhận phải xác thực cấu trúc trước khi cập nhật state.

## 5. Logical streams và message framing

### 5.1. Định nghĩa stream

- `stream_id = 0`: **CONTROL**, gồm AUTH, AUTH_OK/FAIL, USER_LIST, PRESENCE, FILE_OFFER/ACCEPT/REJECT/START/DONE/CANCEL/RESULT và ERROR.
- `stream_id = 1`: **CHAT**, gồm CHAT_DIRECT, CHAT_BROADCAST, CHAT_EVENT, CHAT_ACCEPTED.
- `stream_id ≥ 2`: mỗi stream chuyển **byte thô của một file**, có `transfer_id` liên kết thông qua FILE_START.
- Stream ID có thể giống nhau trên các **kết nối khác nhau** mà không xung đột; server cấp ID file mới chưa dùng cho từng `conn_id`.
- Với cùng stream ID, **mỗi chiều có không gian offset riêng**, bắt đầu từ 0. Khi mất một `DATA` packet, chỉ phần thiếu của stream đó phải chờ, không ngăn giải mã/giao dữ liệu stream khác.
- Tầng ứng dụng nhận `on_stream_data(conn_id, stream_id, offset, data, fin)`; tầng transport chịu trách nhiệm ACK, reorder, retransmission, flow và congestion control.

### 5.2. Control/chat framing bên trong stream

Mỗi thông điệp ứng dụng trong stream 0 hoặc 1 dùng `message_length:u32 | UTF8_JSON[message_length]` (tối đa 8192 byte, kiểm tra trước khi cấp bộ nhớ). Bởi vậy, một message có thể được chia thành nhiều `DATA` packets rồi ghép lại theo **stream offset**.

Cấu trúc JSON thống nhất:

```json
{ "v": 1, "type": "CHAT_DIRECT", "id": 12, "reply_to": null, "body": { "to": "binh", "text": "Hello" } }
```

- `id`: số nguyên tăng dần từ phía gửi **trong phiên**; `reply_to` tham chiếu request cần trả lời.
- Client không được tự quyết định trường `from` trong tin hiển thị; **server lấy sender từ authenticated session**.
- `CHAT_ACCEPTED` = server đã tiếp nhận và đưa tin vào hàng đợi gửi; **không khẳng định người nhận đã xem**.
- Server đánh `server_msg_id` và timestamp cho `CHAT_EVENT` để UI hiển thị nhất quán. Mỗi kết nối người nhận có một outbound chat stream và hàng đợi hữu hạn; client chậm không được khiến server cấp phát bộ nhớ vô hạn.
- Chat nhận dữ liệu và hiển thị theo thứ tự trong chat stream; file stream không chặn chat stream.

### 5.3. Application message types

| Type | Chiều | `body` mẫu | Tác dụng |
|---|---|---|---|
| `AUTH` | C→S | `{username,password}` | Chỉ gửi **sau khi UDP đã mã hóa** |
| `AUTH_OK` | S→C | `{username}` | User chuyển ONLINE |
| `AUTH_FAIL` | S→C | `{code}` | Mật khẩu sai hoặc đăng nhập trùng |
| `USER_LIST` | S→C | `{users:["an","binh"]}` | Danh sách hiện online |
| `PRESENCE` | S→C | `{username,status}` | `online` / `offline` |
| `CHAT_DIRECT` | C→S | `{to,text}` | Chỉ một người nhận |
| `CHAT_BROADCAST` | C→S | `{text}` | Server phân phối cho user ONLINE |
| `CHAT_ACCEPTED` | S→C | `{server_msg_id}` | `reply_to` trỏ tới yêu cầu gửi |
| `CHAT_EVENT` | S→C | `{server_msg_id,from,to,scope,text,ts}` | Tin server đã định tuyến |
| `FILE_OFFER` | C→S hoặc S→C | `{to,filename,size,sha256}` / `{transfer_id,from,...}` | Đề nghị gửi file |
| `FILE_OFFER_ACK` | S→C | `{transfer_id}` | Server cấp mã 128-bit hex |
| `FILE_ACCEPT` | C→S | `{transfer_id}` | Đồng ý nhận |
| `FILE_REJECT` | C→S | `{transfer_id}` | Từ chối |
| `FILE_START` | S→C | `{transfer_id,stream_id,role,size,sha256}` | Bắt đầu stream file |
| `FILE_DONE` | C→S | `{transfer_id,sha256_ok}` | Người nhận báo kiểm tra hoàn tất |
| `FILE_CANCEL` | C→S | `{transfer_id}` | Hủy theo yêu cầu |
| `FILE_RESULT` | S→C | `{transfer_id,status,reason}` | COMPLETED/FAILED/REJECTED/CANCELLED |
| `ERROR` | S→C | `{code,message}` | Lỗi có thể phản hồi |
| `LOGOUT` | C→S | `{}` | Rời ứng dụng |

Một người dùng đăng nhập một phiên tại một thời điểm: đăng nhập trùng → `AUTH_FAIL(ALREADY_LOGGED_IN)` (lựa chọn nhóm). Không lưu tin offline; nếu người nhận offline, trả `ERROR(USER_OFFLINE)`.

## 6. Reliability trên UDP (tầng transport tự viết)

### 6.1. Phân biệt packet number và stream offset

- `pkt_num` chỉ **lần gửi UDP datagram**; phục vụ nonce/ACK/replay/RTT.
- `(stream_id, offset)` chỉ **vị trí dữ liệu** cần giao; phục vụ reorder và chống giao dữ liệu trùng.
- Nếu `DATA(stream=2,offset=2048,data=...)` với `pkt_num=100` bị mất, lần gửi lại phải có **`pkt_num=105` nhưng giữ nguyên `stream=2,offset=2048,data`**.

### 6.2. ACK ranges và retransmission

- Mỗi bên duy trì danh sách packet numbers nhận hợp lệ và báo qua các `ACK` ranges (tối đa 16 ranges, các range cũ có thể bỏ bớt nếu quá lớn).
- ACK ngay khi thấy gap/reordering/duplicate DATA; trường hợp bình thường ACK sau 2 gói hoặc tối đa 25ms. **Không ACK một ACK-only packet** để tránh vòng lặp ACK vô tận.
- Khi gửi packet có nội dung cần tin cậy (`DATA`, `WINDOW_UPDATE`), lưu metadata: `pkt_num`, thời gian gửi, inner frame, số byte trong flight, trạng thái.
- Khi nhận ACK, xóa packet đã xác nhận; những phần `(stream_id,offset,len)` đã được xác nhận không cần truyền lại. ACK packet-level cho biết **bên kia nhận thành công packet đã xác thực**, chưa có nghĩa người nhận cuối đã mở/xem nội dung chat.
- Gói chưa ACK được coi là thất lạc khi: có ACK cho **ít nhất 3 packet numbers của những gói ack-eliciting được gửi sau nó**, hoặc hết RTO theo RTT. Khi retransmit, tạo packet UDP mới và `pkt_num` mới, giữ nội dung frame gốc.
- Đánh dấu loss không đồng nghĩa với việc packet cũ tuyệt đối không thể đến: receiver phải loại trùng bằng **stream offset**; sender không đưa dữ liệu đã xác nhận vào stream lần nữa.
- Khi ACK thất lạc, sender có thể retransmit dư; giao dữ liệu lên ứng dụng **chỉ một lần** nhờ kiểm soát offset.
- Nếu không tiến triển trong 30s hoặc quá 8 lần gửi lại cùng nội dung, báo `TIMEOUT` và hủy transfer/phiên liên quan. Các retry counter là mặc định để tránh gửi vô hạn.

**RTT/RTO:** Đo RTT từ packet được ACK; trừ `ack_delay_ms` có giới hạn và không được cho ra RTT âm. Cập nhật `SRTT`, `RTTVAR`; đề xuất `RTO = clamp(SRTT + 4*RTTVAR, 100ms, 3000ms)`; timeout backoff ×2. Mỗi lần retransmit có packet number mới, nên ACK chỉ rõ bản truyền nào được nhận. Tham khảo ý tưởng packet-based loss detection của RFC 9002, **không coi đây là triển khai QUIC hoàn chỉnh**.

### 6.3. Flow control và sliding window

- Mỗi stream có `next_offset`, reorder/received map, `delivered_offset`, `advertised_max_offset`.
- Sender chỉ phát `DATA` khi `offset + data_len <= advertised_max_offset` và toàn kết nối còn `bytes_in_flight + packet_payload <= cwnd_bytes`.
- `WINDOW_UPDATE(stream_id,max_offset)` cho phép tăng credit; giá trị `max_offset` chỉ **tăng**, gửi lại packet chứa thông tin cập nhật khi bị mất. Mỗi stream file khởi tạo credit bằng 0 cho tới FILE_START/initial WINDOW_UPDATE.
- Bên nhận chỉ tăng credit khi dữ liệu đã được xử lý hoặc ghi an toàn. Với chat, giữ giới hạn buffer; với file, ghi chunk theo offset vào `.part`.
- **Relay backpressure:** server chỉ quảng bá thêm credit trên chặng upload khi lượng dữ liệu còn nằm trong relay buffer thấp hơn 512 KiB, nhờ đó client nhận chậm sẽ làm chậm bên gửi mà không làm server giữ cả file trong RAM.

### 6.4. Tránh Head-of-Line Blocking

- Mỗi stream có **reorder buffer và `delivered_offset` riêng**. Mất offset trên file stream không làm `delivered_offset` của chat stream dừng.
- Scheduler ưu tiên control/chat, nhưng cho file được phục vụ công bằng; không đẩy file hàng loạt vào một hàng đợi FIFO vô hạn.
- HoL có thể vẫn tồn tại **bên trong từng stream**, và congestion/link saturation có thể tăng độ trễ tất cả stream; báo cáo phải phân biệt giới hạn này.

## 7. Congestion control CUBIC (theo RFC 9438)

- Một `cwnd` và một `bytes_in_flight` **cho từng kết nối UDP**, dùng chung các stream; không tạo `cwnd` riêng cho mỗi stream rồi cộng vượt quá khả năng đường truyền.
- Đơn vị tiện cài: `MSS = 1024` bytes; `cwnd_init = 10*MSS`, `cwnd_min = 2*MSS`, `ssthresh_init = 256*MSS` (giá trị khởi tạo đề xuất).
- **Slow start** khi `cwnd < ssthresh`: tăng cwnd xấp xỉ số byte DATA mới được ACK.
- **Congestion avoidance CUBIC:** quản lý `W_max`, epoch và `t` (giây kể từ epoch), với `C = 0.4`, `β = 0.7`, `K = cuberoot(W_max*(1-β)/C)` và `W_cubic(t)=C*(t-K)^3 + W_max` khi `W` tính bằng số segments. Cập nhật cwnd theo ACK và các giới hạn tăng của RFC 9438; dùng Reno-friendly estimate theo RFC nếu triển khai đầy đủ.
- **Khi xác nhận mất gói:** đặt `W_max` dựa trên cwnd trước loss, giảm cwnd xuống xấp xỉ `β*cwnd` (β=0.7), cập nhật `ssthresh`, bắt đầu recovery epoch; **không giảm nhiều lần cho cùng một đợt loss**.
- **Khi timeout nghiêm trọng:** giảm về cửa sổ an toàn nhỏ và tiếp tục slow start; khi khôi phục, không bơm ồ ạt packet.
- Log mỗi lần cập nhật `{time,cwnd_bytes,ssthresh,W_max,RTT,loss_event,bytes_in_flight}`. Báo cáo vẽ biểu đồ `cwnd` theo thời gian dưới 5–10% loss.
- **Chú ý kiểm định:** Các công thức trên là bộ khung cho thiết kế. Nhóm vẫn phải đối chiếu từng quy tắc tăng/giảm/recovery với **RFC 9438** khi code; không được tự nhận đã cài CUBIC đúng chỉ vì có hàm bậc ba.

## 8. File transfer 1-1 (qua server relay)

### 8.1. Negotiation trên control stream (UDP)

1. A tính `size`, `sha256`, lọc `filename=basename`, gửi `FILE_OFFER(to=B,...)`.
2. Server kiểm tra user B ONLINE, giới hạn size/quota; cấp `transfer_id` ngẫu nhiên 128-bit; gửi OFFER tới B.
3. B gửi `FILE_ACCEPT` hoặc `FILE_REJECT`.
4. Nếu accept, server cấp `stream_id` tương ứng trên kết nối A–server và B–server; gửi `FILE_START` tới hai bên. Stream file có **credit** riêng.

### 8.2. Truyền, ghép và kết thúc

- A đọc file thành đoạn tối đa **1024 bytes**, gửi trên `DATA(stream_id,offset,data)`; offset chính là vị trí byte trong file, bắt đầu 0.
- Server nhận chunk, lưu trong relay buffer có giới hạn, gửi lại trên **kết nối UDP riêng với B** ở stream file tương ứng. ACK trên hai chặng **không phụ thuộc vào nhau**.
- B ghi vào `<safe_filename>.part` bằng cách seek theo offset (không cần chờ chunk trước), ghi nhận bitmap/interval các byte đã có. Không bao giờ sử dụng đường dẫn người gửi cung cấp để ghi ra ngoài thư mục download.
- A gửi DATA với `FIN=1` ở offset kết thúc. File 0 byte sử dụng một DATA FIN-only (`offset=0`, `data_len=0`). FIN cũng phải được ACK/retransmit nếu mất.
- Khi B đã nhận đủ các byte `[0,size)`, đã thấy FIN, kích thước khớp và SHA-256 trùng → đổi tên `.part`, gửi `FILE_DONE(sha256_ok=true)`; server gửi `FILE_RESULT(COMPLETED)` cho A và B.
- Nếu sai SHA, hết thời gian chờ, người dùng hủy hoặc peer mất kết nối → `FILE_RESULT(FAILED|CANCELLED)`, đóng stream và dọn file `.part` theo chính sách.
- Không lưu file offline và không có chế độ file broadcast ở phiên bản này.

### 8.3. Bằng chứng hoàn thành

- File 0 byte, 1 KiB, 1 MiB, 10 MiB truyền đúng SHA-256.
- 10 MiB, loss 5–10%, delay/reorder: vẫn hoàn tất trong giới hạn demo hoặc báo lỗi có nguyên nhân; log selective retransmission và chat không bị chặn bởi file stream.

## 9. Trạng thái (state machines)

### 9.1. Client

```text
DISCONNECTED
  -> TCP_TLS_CONNECTING
  -> HELLO_SENT
  -> BOOTSTRAPPED (có conn_id + 2 UDP keys)
  -> UDP_REGISTERING
  -> UDP_BOUND
  -> AUTHENTICATING
  -> ONLINE
  -> CLOSING -> DISCONNECTED

Bất kỳ lỗi nặng/timeout: -> DISCONNECTED, hủy khóa/phiên cũ, bootstrap mới.
```

### 9.2. Server per client

```text
NEW -> BOOTSTRAPPED -> UDP_BOUND -> ONLINE -> CLOSED
          |               |           |
          +----timeout----+---logout--+----idle timeout----> CLOSED
```

- `BOOTSTRAPPED` chưa phải login thành công. `UDP_BOUND` chỉ cho biết đã xác thực được UDP key và nhận biết `(IP,port)`; **chỉ `AUTH_OK` mới chuyển ONLINE**.
- `PRESENCE online` và `USER_LIST` chỉ được gửi sau ONLINE; REGISTER lặp không tạo thêm phiên hoặc lặp sự kiện presence.
- TCP đã đóng **không đồng nghĩa user offline**, vì bootstrap được thiết kế kết thúc trước khi phiên UDP hoạt động.
- Không nhận UDP hợp lệ trong 10s → đóng phiên, xóa keys, giải phóng stream/transfer, thông báo peer; client phải **bootstrap lại từ đầu**, không re-REGISTER bằng key đã bị hủy.
- Đổi UDP source IP/port giữa phiên: phiên bản 1 **không hỗ trợ NAT rebinding tự động**; yêu cầu bootstrap lại để tránh thay đổi địa chỉ thiếu xác thực đường đi.

## 10. Mã lỗi và xử lý ngoại lệ

- `BAD_FRAME`, `UNSUPPORTED_VERSION`, `BAD_PACKET`, `AUTH_FAILED`, `ALREADY_LOGGED_IN`, `NOT_AUTHENTICATED`, `UNKNOWN_USER`, `USER_OFFLINE`, `CHAT_TOO_LARGE`, `FILE_TOO_LARGE`, `TRANSFER_BUSY`, `TRANSFER_NOT_FOUND`, `HASH_MISMATCH`, `TIMEOUT`, `PEER_DISCONNECTED`, `INTERNAL`.
- TCP/TLS sai hoặc vượt giới hạn → đóng bootstrap connection, không crash server.
- UDP không xác thực / sai tag / replay → bỏ im lặng và giới hạn log; không để datagram tùy ý tạo session.
- Phía nhận xác thực thành công nhưng message ứng dụng sai trạng thái/schema → trả `ERROR` trên control stream nếu còn có thể.
- `CLOSE` không thay thế cleanup timeout; các tài nguyên phải được giải phóng trong mọi đường thoát.
- Giới hạn số phiên chưa hoàn tất bootstrap, bộ nhớ buffer, file size và tốc độ thử AUTH để tránh cạn tài nguyên.

## 11. Web UI (chỉ trên localhost)

- Python client chạy một HTTP server **chỉ bind `127.0.0.1`**, không mở ra LAN. Đây là kiến trúc đề xuất, cần thầy xác nhận áp dụng `http.server` chuẩn Python như `net/http` chuẩn Go.
- Các endpoint nội bộ dự kiến:
  - `GET /` và `/static/*`: HTML/CSS/JS.
  - `GET /api/state`: trạng thái client, online users, transfer progress.
  - `POST /api/connect`: khởi tạo bootstrap/session; `POST /api/login`: submit credentials đến lõi client, **không ghi log password**.
  - `POST /api/chat`: gửi tin nhắn.
  - `POST /api/file`: nhận file upload từ browser theo dạng streaming/có giới hạn rồi đưa xuống file manager.
  - `GET /events`: SSE (`EventSource`), đẩy sự kiện login, presence, message, transfer-progress.
- HTTP handler **không gọi trực tiếp socket UDP/TCP**; nó đưa command vào queue của Python client core và lấy event từ queue. Giới hạn request body; kiểm tra `Origin`/local token, không cấu hình CORS mở rộng.
- Đây là giao diện demo nội bộ, **không triển khai như một HTTP server công khai cho Internet**.

## 12. Concurrency, chia module và giao diện tích hợp

### 12.1. Concurrency

- Một UDP socket cho mỗi tiến trình client/server; một vòng xử lý nhận datagram (thread hoặc `selectors`) và hàng đợi non-blocking; không dùng một thread mới cho từng datagram.
- TCP bootstrap xử lý đồng thời bằng thread pool/async trên socket; server không chặn việc phục vụ client khác trong khi TLS/HELLO của một client đang chờ.
- File I/O không được khóa vòng nhận UDP; dùng hàng đợi/bộ đệm có hạn. Các bảng session/transfer dùng synchronization phù hợp.

### 12.2. Cấu trúc project khuyến nghị

```text
network-collab/
  common/
    constants.py
    control_framing.py       # TCP bootstrap, giữ code A đã test
    udp_packet.py            # binary header, AES-GCM
    transport.py             # ACK, RTO, streams, flow, CUBIC
    crypto.py                # UDP crypto, helper (thư viện chuẩn/cryptography)
    models.py                # message types, validation
  server/
    main.py                  # khởi tạo TCP+UDP và app
    bootstrap.py             # TLS HELLO/ACK, cấp conn_id/keys
    auth.py                  # giữ code A đã viết và test
    sessions.py              # trạng thái & key lifecycle
    router.py                # direct/broadcast, presence
    transfers.py             # offer, accept, relay, SHA-256
  client/
    main.py
    core/session.py          # bootstrap, UDP register, AUTH, state
    core/events.py           # event queue
    core/files.py            # file sender/receiver
    bridge/http_server.py    # localhost HTTP/SSE
    ui/index.html
    ui/app.js
    ui/style.css
    cli.py                   # CLI phục vụ debug
  scripts/
    create_test_users.py
    gen_cert.sh              # TLS cert self-signed cho LAN demo
  config/users.json          # salt+hash, không chứa password gốc
  tests/
    test_control_framing.py
    test_auth.py
    test_udp_packet.py
    test_reliability.py
    test_streams.py
    test_cubic.py
    test_file_transfer.py
    load_20_clients.py
  protocol.md
  README.md
```

### 12.3. API nội bộ A/B phải ký duyệt trước khi code

**API minh họa** (không phải code đã có):

```python
# A (application) -> B (UDP transport)
transport.send_message(conn_id, stream_id, payload_bytes)
transport.open_file_stream(conn_id, transfer_id, stream_id)
transport.close_stream(conn_id, stream_id)
transport.register_connection(conn_id, udp_c2s_key, udp_s2c_key, state)

# B -> A (callbacks/queue)
on_udp_registered(conn_id, ip, port)
on_stream_data(conn_id, stream_id, offset, data, fin)
on_transport_failed(conn_id, reason)
on_file_progress(conn_id, transfer_id, acked_bytes)
```

- A sở hữu authentication, session rules, routing, file negotiation, UI; B sở hữu UDP packet/crypto/transport/streams, bộ truyền bytes file; A sở hữu **CUBIC** và bộ giả lập mất gói, B gọi CUBIC thông qua interface thống nhất. `on_stream_data` giao chat/control sau khi đủ byte theo thứ tự; với file, có thể thông báo chunk **không theo thứ tự** kèm `offset` để ghi thẳng vào đĩa. A và B tích hợp stream mapping & relay cùng nhau.
- Khóa phiên và ConnID là dữ liệu nhạy cảm dùng chung giữa bootstrap và UDP transport; module quản lý session cấp cho UDP qua interface rõ ràng, không ghi log khóa.

## 13. Kiểm thử bắt buộc trước demo

| ID | Kiểm thử | Điều kiện đạt |
|---|---|---|
| T01 | TCP TLS HELLO/ACK | Client nhận ConnID/khóa, sai certificate bị từ chối |
| T02 | UDP REGISTER | UDP port được học đúng; REGISTER lặp không tạo session lặp |
| T03 | AUTH | Đúng/sai password, user trùng, 3 lần sai, USER_LIST đúng |
| T04 | Chat direct | A→B, C không nhận; ACK app không nhầm là người nhận đã xem |
| T05 | Chat broadcast | 3+ user nhận; một user mất gói không chặn user khác |
| T06 | Packet reliability | Mất, duplicate, reorder, ACK mất, selective retransmit |
| T07 | No cross-stream HoL | Mất chunk file nhưng chat đến và được hiển thị ngay |
| T08 | Flow/CUBIC | Không vượt credit/cwnd; log cwnd tăng/giảm hợp lý dưới loss |
| T09 | File integrity | File 0 B, 1 KiB, 1/10 MiB; SHA-256 match |
| T10 | Failure cleanup | Đóng client, timeout, cancel; server không crash/rò rỉ state |
| T11 | Security | Không đọc được plaintext UDP; sửa ciphertext/tag/replay → drop |
| T12 | Load | 10–20 client trên localhost; test không treo/hỏng dữ liệu |
| T13 | UI | Login/chat/online list/progress phản ánh đúng trạng thái |

- Loss emulator áp dụng cho UDP *trước khi gửi* và *sau khi nhận*: `--loss 0.0/0.05/0.10 --delay-ms 0/50 --reorder 0/0.05 --seed 42`.
- Khi demo lưu bằng chứng: SHA-256, log loss/retransmit, screenshot/chat delay khi file chạy, đồ thị CUBIC `cwnd`, output 20 client. Localhost được chấp nhận, nhưng server IP/port phải cấu hình được để chạy trong LAN.

## 14. Mapping với 10 milestones của assignment

1. **Protocol design:** tài liệu này + sơ đồ state/sequence, packet definition.
2. **Handshake:** TCP/TLS HELLO, HELLO_ACK cấp ConnID.
3. **Authentication/state:** UDP AUTH bảo mật, user/IP/UDP port/session table.
4. **Concurrency:** 20 clients, event/thread handling.
5. **Streaming messaging:** UDP direct/broadcast routing, chat stream độc lập.
6. **File transfer:** UDP file stream relay, chunk, SHA-256 match.
7. **Resilience:** timeout, heartbeat, retry, cleanup.
8. **Security:** TLS bootstrap và AES-GCM UDP (plus PBKDF2 password storage).
9. **UI:** localhost HTTP HTML/JS + SSE.
10. **Testing:** local simulations, loss, 20 clients, clean code, báo cáo.

## 15. Changelog và quy tắc chốt

- `v1.0-proposed` — 2026-11-02: Tách khỏi v0.2; chuyển direct chat sang UDP theo tài liệu giải đáp mới; TCP/TLS chỉ bootstrap; file 1-1 server relay; packet-level ACK ranges + stream offsets; CUBIC connection-level; security TLS→UDP AES-GCM.
- Khi thầy và hai thành viên xác nhận, đổi thành `v1.0-approved` kèm ngày, tên người duyệt. Mọi thay đổi các trường on-wire, security, ACK, stream allocation phải cập nhật protocol và test trước khi merge.

## Tài liệu tham khảo (để ghi vào báo cáo)

- Assignment 1 — Distributed Streaming-based Client-Server Collaboration Application (tài liệu môn học).
- Giải đáp Assignment 1 — giảng viên cung cấp (6 trang).
- RFC 9000 / RFC 9002 — tham khảo cách tách packet number khỏi stream offset và phát hiện mất gói (không dùng thư viện QUIC).
- RFC 9438 — CUBIC Congestion Control.
- Python `ssl`, `socket`, `struct`, `hashlib`, `http.server` documentation; thư viện `cryptography` cho AES-GCM.
