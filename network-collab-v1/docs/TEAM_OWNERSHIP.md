# Phân công A/B — đã thống nhất trong nhóm (bản sườn)

## Thành viên A (bạn)
| Module | Vai trò |
| --- | --- |
| `common/control_framing.py` | TCP length-prefix JSON (đã có baseline) |
| `common/cubic.py` | **CUBIC congestion control**; chỉ thuật toán, không trực tiếp gửi UDP |
| `common/models.py` | App-level JSON schema, validation |
| `server/bootstrap.py` | TCP/TLS HELLO-ACK, tạo ConnID và khóa UDP |
| `server/auth.py` | Xác thực password (nên chuyển code đã viết) |
| `server/sessions.py` | Sessions, online status, UDP endpoint |
| `server/router.py` | Direct/broadcast routing dựa trên user list |
| `server/transfers.py` | FILE_OFFER/ACCEPT, relay coordination, quotas |
| `server/main.py` | Khởi chạy server + quản lý tiến trình |
| `client/core/session.py`, `client/core/files.py` | Vòng đời session, file I/O, SHA-256, `.part` |
| `client/core/events.py` | Event queue giữa app core và UI |
| `client/bridge/http_server.py`, `client/ui/*` | Localhost HTTP + SSE, giao diện |
| `client/main.py`, `client/cli.py` | Khởi chạy client/debug |
| `scripts/create_test_users.py`, `scripts/gen_cert.py` | Tạo user/cert thử nghiệm |
| `tools/network_simulator.py` | **Loss/delay/reorder simulator** |
| `tests/test_cubic.py`, `tests/test_auth.py`, `tests/test_bootstrap.py`, `tests/load_20_clients.py` | Test A |

## Thành viên B
| Module | Vai trò |
| --- | --- |
| `common/udp_packet.py` | Binary UDP packet encoding/decoding |
| `common/crypto_udp.py` | AES-GCM + nonce/AAD/replay protection |
| `common/transport.py` | Reliable UDP send/recv, ACK ranges, retransmission, RTT/RTO; gọi A.CUBIC |
| `common/streams.py` | Multiplexing, offset, ordering, per-stream windows |
| `server/udp_service.py` | UDP socket/service adapter ở server (tích hợp A) |
| `client/core/udp_connection.py` | UDP socket/service adapter ở client (tích hợp A) |
| `tests/test_udp_packet.py`, `tests/test_reliability.py`, `tests/test_streams.py`, `tests/test_udp_crypto.py` | Test B |

## Cả hai
- Phê duyệt `docs/INTERFACES.md` trước khi implement các module phụ thuộc.
- A sở hữu thuật toán CUBIC, **B sở hữu việc gọi CUBIC từ transport**, tránh tranh chấp cùng file.
- A quản lý dữ liệu file và kiểm tra hash; B truyền byte qua UDP đáng tin cậy.
- Cùng test toàn hệ thống: auth, direct, broadcast, file loss 5–10%, stream HoL, 20 clients.

## Nguyên tắc Git
- Dùng branch `feature/a-...`, `feature/b-...`.
- Thay đổi API giao nhau hoặc gói tin phải được cả hai review.
- Không sửa module của người còn lại khi chưa trao đổi.
