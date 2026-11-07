# API giữa A và B — DRAFT (chưa khóa chữ ký)

Tập tin này mô tả **hợp đồng cần hai thành viên thống nhất trước khi viết transport**.
Những chữ ký dưới đây là ví dụ, không phải API hiện đã triển khai.

## A gọi UDP transport của B
```python
transport.register_connection(conn_id, client_to_server_key, server_to_client_key, role)
transport.send_bytes(conn_id, stream_id, payload: bytes, fin=False)
transport.close_stream(conn_id, stream_id)
transport.remove_connection(conn_id)
```

## B báo event cho A
```python
on_udp_registered(conn_id, source_ip, source_port)
on_stream_data(conn_id, stream_id, offset, data: bytes, fin: bool)
on_transport_failed(conn_id, code)
on_transport_progress(conn_id, stream_id, acked_bytes)
```

- `stream_id=0`: control; `stream_id=1`: chat; file `stream_id>=2`.
- Chat/control: gửi lên ứng dụng theo thứ tự byte trong stream.
- File: có thể gửi chunk kèm offset không theo thứ tự để A ghi `.part`.
- ACK của transport không đồng nghĩa người nhận đã xem tin nhắn hay ghi file thành công.
- B quản lý `packet_number` + ACK/RTO, A quản lý `transfer_id` + file metadata.
- Crypto key truyền trong bộ nhớ, không log và không ghi file.

## B gọi CUBIC do A viết
```python
cubic = CubicController(mss_bytes=1024)
cubic.on_ack(acked_bytes: int, now_seconds: float, rtt_seconds: float)
cubic.on_loss(now_seconds: float, recovery_marker: int)
cubic.on_timeout(now_seconds: float)
cwnd = cubic.cwnd_bytes
```

Đơn vị cwnd: **bytes**. `bytes_in_flight` vẫn do B quản lý. B chỉ gửi khi
`bytes_in_flight + next_packet_size <= cubic.cwnd_bytes` và không vượt flow window.
Khi nhiều packet cùng mất trong một recovery event, không gọi `on_loss` gây giảm cwnd nhiều lần.
Chi tiết event model còn cần A/B xác nhận trước khi freeze API. Đối chiếu RFC 9438 khi lập trình.
