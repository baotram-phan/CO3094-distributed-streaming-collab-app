# REQUIREMENTS TRACEABILITY — Assignment 1 → Protocol → Code → Test

> **Tạo ngày:** 2026-11-09  
> **Trạng thái:** Baseline cho kiểm thử; không tự coi milestone đạt chỉ vì đã viết code.  
> **Ưu tiên tài liệu:** Assignment 1 → Giải đáp giảng viên → Protocol Specification v1.0-proposed → Contract A/B v1.1-review.  
> **Chưa được xác nhận:** protocol được ghi PROPOSED; cách dùng Python `http.server` cho UI và các điểm nhóm ghi phải hỏi giảng viên.

## A. Bảng 10 milestone chấm điểm

| Milestone (1 điểm/mốc) | Yêu cầu cốt lõi | Owner | Code/artefact cần có | Bằng chứng tối thiểu | Trạng thái hiện tại |
|---|---|---|---|---|---|
| M01 Protocol design | Custom packet/message + state/sequence diagrams | A+B | `PROTOCOL_SPECIFICATION`, contract đã chốt | Tài liệu được hai người duyệt, sơ đồ chính xác | **Có draft**, chưa xác nhận GV |
| M02 Handshake | TCP/TLS HELLO, HELLO_ACK, ConnID/keys | A | `server/bootstrap.py`, client bootstrap | TLS trust check, cấp session thật, chạy hai máy | **A báo có code**, LAN chưa xác nhận |
| M03 Authentication/state | AUTH, user list, IP/UDP port, trạng thái ONLINE | A+B | `server/sessions.py`, AUTH trên reliable control stream | Login đúng/sai/trùng, presence, UDP endpoint | **Chưa end-to-end** |
| M04 Concurrency | 10–20 client đồng thời | A+B | Socket/event loop, queues/locks, registry | Chạy load test 10–20 client, không treo | **Chưa xác nhận** |
| M05 Streaming messaging | UDP routing direct/broadcast; streams độc lập | A+B | Reliable stream 1 + router | 3+ client, chat đúng, file loss không HoL | **Chưa làm** |
| M06 File transfer | Chunking/reassembly trên UDP, không hỏng dữ liệu | A+B | DATA stream ≥2, relay, SHA-256 | File 0B, 1KiB, 1/10MiB qua UDP, hash match | **Chưa làm** |
| M07 Resilience | Timeout, retry, disconnect, cleanup | A+B | REGISTER retry, retransmission, heartbeat, closed events | Loss/timeout/reconnect, cleanup state, không crash | **Một phần nền tảng** |
| M08 Security | TLS bootstrap + UDP payload encryption | A+B | TLS verification, AES-GCM AEAD, anti-replay | Bad key/tag/replay drop; packet capture không lộ plaintext | **B có unit AES-GCM**, chưa E2E |
| M09 HTTP UI | HTTP-based UI + JavaScript | A | Local HTTP/SSE UI | UI login/chat/file/progress hoạt động | **Chưa xác nhận**; cần GV duyệt `http.server` |
| M10 Testing/code quality | Unit, integration, LAN/network simulation | A+B | Tests, README, logs, reports | Tất cả bài test và bằng chứng reproducible | **B báo 33, A báo 54**, LAN chưa xác nhận |

## B. Thêm các điều kiện kỹ thuật xuyên milestone

| ID | Quy định trong protocol nhóm | Cách chứng minh | Trạng thái |
|---|---|---|---|
| P01 | TCP/TLS chỉ mang HELLO/HELLO_ACK/BOOTSTRAP_ERROR, không mang chat/file/AUTH | Kiểm tra source & packet flow | Chưa xác nhận |
| P02 | Header `!HBBQQ`, 20B, AES-GCM tag16, datagram ≤1200 | Packet unit tests/known vectors | B đã code/test theo báo cáo |
| P03 | Nonce = 4 zero B + pkt_num:u64; mỗi chiều key riêng, retransmit pkt_num mới | Tests + packet metadata logs | B đã code nonce/counter, retransmit chưa làm |
| P04 | Replay 4096, out-of-order chấp nhận, commit sau tag + Registry accept | Unit + concurrent REGISTER tests | B đã có class, integration chưa làm |
| P05 | ACK ranges tối đa 16, selective retransmission, RTT/RTO | Loss/ACK-lost/reorder logs | Chưa làm |
| P06 | Streams 0 control, 1 chat, ≥2 file; offset riêng từng chiều | Reorder test, HoL test | Chưa làm |
| P07 | Flow credit & CUBIC per connection, bounded relay buffer | Counters, logs & cwnd chart | Chưa làm |
| P08 | No endpoint rebinding v1; rebootstrap khi đổi UDP port | Integration negative test | Chưa làm |
| P09 | Client/server chạy LAN, port cấu hình; UI chỉ local 127.0.0.1 | Two-host smoke + inspect listener | Chưa làm |
| P10 | File size 0B..10MiB integrity; 5–10% loss simulation | SHA-256 & logs | Chưa làm |

## C. Cổng nghiệm thu theo giai đoạn (gates)

| Gate | Điều kiện qua gate | Chưa đủ nếu chỉ có |
|---|---|---|
| G0 — Repository reproducible | Cùng commit, dependencies được ghi lại, unit tests cả A/B, không conflict constants, API contract có chữ ký | 33+54 tests ở hai nhánh khác nhau |
| G1 — REGISTER thật | Shared Registry cùng process, TLS valid, REGISTER/REGISTER_OK, `UDP_BOUND`, replay/bad tag/cleanup | Demo ConnID=42/key cố định |
| G2 — AUTH + messaging | Reliable stream0 AUTH; direct/broadcast stream1 | UDP socket gửi/nhận thô |
| G3 — Reliability/file | ACK/retransmission, flow/cwnd, file relay SHA-256, loss/reorder | File chỉ chạy không loss |
| G4 — Demo/grade readiness | LAN 2 máy + load 20 client + HoL + TLS negatives + UI + README/reports/evidence | Chạy được một lần trên localhost |

## D. Rủi ro còn mở (không được bỏ qua)

1. `common/constants.py`: A cần `PROTOCOL_VERSION`, B có `WIRE_VERSION`; chưa xác nhận gộp đúng semantic.
2. Tên module UDP service: A đề xuất `server/udp_service.py`, cần quyết định một tên và không có server trùng nhiệm vụ.
3. `TransportStateManager` và `transport.remove_connection(conn_id)` chưa được audit trực tiếp trong nhánh tích hợp.
4. Cần một instance `SessionRegistry` chia sẻ giữa TCP/TLS và UDP trên server.
5. Lệnh chạy ứng dụng thật và cấu hình CLI chưa được xác minh từ code (không tự ghi lệnh giả vào README).
6. Protocol đang PROPOSED: cần xác nhận ưu tiên yêu cầu UDP chat/file, Python `http.server` UI và TLS/key design với giảng viên theo chính bản protocol.

**Định nghĩa PASS:** Có Git commit, môi trường (máy A/B), lệnh thực thi, expected/actual, log/screenshot đã khử bí mật, kết quả được hai bên review và ghi vào `TEST_EVIDENCE_TEMPLATE.md`.
