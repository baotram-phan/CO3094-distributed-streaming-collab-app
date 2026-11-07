"""Cấu hình protocol: giá trị đề xuất, thay đổi qua review trước khi đóng băng on-wire."""
# Giữ tên từ starter cũ để control_framing.py + 10 unit tests tương thích.
PROTOCOL_VERSION = 1
MAX_CONTROL_FRAME = 65536
CONTROL_PORT = 9000

# Tham số V1 PROPOSED (chưa phê duyệt).
UDP_PORT = 9001
UI_PORT = 8765
MAX_UDP_DATAGRAM = 1200
MAX_STREAM_CHUNK = 1024
STREAM_CONTROL = 0
STREAM_CHAT = 1
FILE_STREAM_MIN_ID = 2
MAX_FILE_SIZE = 50 * 1024 * 1024
