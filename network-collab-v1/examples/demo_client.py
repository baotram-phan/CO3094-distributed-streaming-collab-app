"""TCP demo: chưa TLS, không dùng để triển khai thật."""
import socket

from common.constants import CONTROL_PORT
from common.control_framing import recv_frame, send_frame

with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=5) as sock:
    send_frame(sock, {"v": 1, "type": "HELLO", "id": 1,
                      "reply_to": None, "body": {"client_version": "1.0"}})
    print("Đã gửi HELLO")
    print("Server trả lời:", recv_frame(sock))
