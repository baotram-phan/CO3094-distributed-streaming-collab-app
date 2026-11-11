# INTEGRATION CONTRACT v1.1-approved — Addendum lifecycle (2026-11-10)

> Không thay đổi wire format, packet types, AES-GCM, replay window, `SessionRegistry` API, timeout hoặc phân công CUBIC. Đây là bổ sung triển khai cho ba vấn đề A/B/C sau review của B. Các quy tắc dưới đây **thay thế** các đoạn mâu thuẫn trong v1.1 trước đó.

## A. Quyền sở hữu SessionClosedEvent

**Chỉ A coordinator (`CollaborationServer.dispatch_closed_events()` trong `server/main.py`) được gọi** `registry.cleanup_expired()` + `registry.drain_closed_events()`.

```python
# A coordinator — chạy định kỳ, ngoài Registry lock
registry.cleanup_expired()
for event in registry.drain_closed_events():
    udp_service.remove_connection(event.conn_id)
    on_session_closed(event)  # A quản lý presence / offline
```

`UDPTransportService` của B **không đọc Registry close-event queue**. `UDPTransportService.serve_once()` chỉ xử lý UDP; `remove_connection(conn_id) -> bool` là API cleanup B cung cấp, cần idempotent và hủy các future send/retransmit jobs. `on_session_closed` được A gọi đúng một lần cho mỗi event, kể cả khi transport không còn state. Callback ứng dụng ở ngoài Registry và transport/coordinator locks.

## B. Race REGISTER vs CLOSE

- B tiếp tục **xử lý REGISTER tuần tự theo ConnID**, thứ tự: anti-replay check (peek) -> AES-GCM verify -> Registry bind -> replay commit -> fresh pkt_num -> REGISTER_OK. Không commit nếu Registry từ chối.
- `UDPTransportService` có **lifecycle lock** để tuần tự hóa thao tác manager `add`/`remove`/packet-number commit; nó **không được giữ trong lúc gọi Registry/callback**.
- `remove_connection(conn_id)` đặt **tombstone cho ConnID** trước khi xóa transport state; REGISTER in-flight nhìn thấy tombstone thì bỏ, không tái tạo state.
- Sau `bind`, handler **kiểm tra lại Registry** trước và sau tạo state. Nếu session đã đóng thì drop, xóa state cục bộ (nếu có). Nếu A close xảy ra đồng thời, A coordinator vẫn phải dispatch close event và tombstone cuối cùng sẽ dọn state.
- Khi `remove_connection` đã xử lý xong, không được tái khởi tạo packet number cho ConnID/khóa phiên đó. Bootstrap mới phải tạo keys + ConnID mới.
- Không nên hiểu các check thêm là bảo đảm không có *bất kỳ* ACK nào chạy đua với một `close()` đồng thời: không có khóa chung giữa mọi Registry.close và UDP send. Các check/tombstone bảo đảm cleanup không bị đảo ngược, giúp giới hạn stale sends; event có thể được xử lý ngay sau một lần send đã bắt đầu.

## C. Chữ ký callback đăng ký UDP — CHỐT

```python
on_udp_registered(conn_id: int, endpoint: tuple[str, int]) -> None
```

B gọi **chỉ khi** `UDPBindResult.newly_bound is True`, **ngoài transport locks**; lần REGISTER mới có pkt_num mới cùng endpoint được ACK, nhưng `newly_bound=False` và **không gọi callback nữa**. A implement callback với hai đối số; `on_session_closed(event: SessionClosedEvent)` là callback riêng của A coordinator, không phải B.

## Nghiệm thu

- Một consumer drain queue; không mất event `username` để cập nhật presence offline.
- CLOSE + drain giữa bind/add => không có state mồ côi/tái tạo state; CLOSE khi add => state được xóa sau khi kiểm tra lại.
- REGISTER mới và lặp vẫn ACK theo contract; anti-replay giữ nguyên; callback 2 tham số chạy lần đầu đúng một lần.
- Integration TLS + UDP và tất cả tests A/B đang có vẫn PASS.

**Phân công:** A sở hữu `server/main.py` / callback presence / event dispatcher; B sở hữu `UDPTransportService` lifecycle / transport state. Nếu `server/udp_service.py` đang nằm trong nhánh A integration, hai bên cần review và thống nhất patch trước merge.
