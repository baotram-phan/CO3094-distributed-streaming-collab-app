"""TCP demo: chưa TLS, không dùng để triển khai thật."""
import socket
import time

from common.constants import CONTROL_PORT
from common.control_framing import recv_frame, send_frame

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", CONTROL_PORT))
    server.listen(1)
    print(f"Đang chờ client tại 127.0.0.1:{CONTROL_PORT} ...")
    conn, addr = server.accept()
    with conn:
        print("Đã kết nối:", addr)
        message = recv_frame(conn)
        print("Nhận:", message)
        send_frame(conn, {
            "v": 1, "type": "HELLO_ACK", "id": 1,
            "reply_to": message["id"],
            "body": {"server_time": int(time.time() * 1000),
                     "udp_port": 9001, "heartbeat_interval_ms": 2000},
        })
        print("Đã gửi HELLO_ACK. Demo kết thúc.")
