"""TCP framing: [u32 big-endian length] + [UTF-8 JSON bytes]."""
import json
import struct

from common.constants import MAX_CONTROL_FRAME, PROTOCOL_VERSION


class ProtocolError(Exception):
    """Lỗi protocol; caller quyết định gửi ERROR và đóng kết nối."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def validate_envelope(message: dict) -> None:
    """Kiểm tra các trường chung của JSON envelope (mục 2.2)."""
    if not isinstance(message, dict):
        raise ProtocolError("BAD_FRAME", "Payload phải là JSON object")
    if "v" not in message:
        raise ProtocolError("BAD_FRAME", "Thiếu trường v")
    if type(message["v"]) is not int or message["v"] != PROTOCOL_VERSION:
        raise ProtocolError("UNSUPPORTED_VERSION", "Chỉ hỗ trợ version 1")
    if not isinstance(message.get("type"), str) or not message["type"]:
        raise ProtocolError("BAD_FRAME", "type phải là chuỗi không rỗng")
    msg_id = message.get("id")
    if type(msg_id) is not int or msg_id < 1:
        raise ProtocolError("BAD_FRAME", "id phải là số nguyên dương")
    reply_to = message.get("reply_to")
    if reply_to is not None and (type(reply_to) is not int or reply_to < 1):
        raise ProtocolError("BAD_FRAME", "reply_to phải là null hoặc số nguyên dương")
    if not isinstance(message.get("body"), dict):
        raise ProtocolError("BAD_FRAME", "body phải là JSON object")


def encode_frame(message: dict) -> bytes:
    """dict -> 4 byte độ dài + JSON UTF-8."""
    validate_envelope(message)
    try:
        payload = json.dumps(
            message, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("BAD_FRAME", "Không thể chuyển thành JSON UTF-8") from exc
    if len(payload) > MAX_CONTROL_FRAME:
        raise ProtocolError("FRAME_TOO_LARGE", "JSON vượt quá 65536 byte")
    return struct.pack("!I", len(payload)) + payload


def send_frame(sock, message: dict) -> None:
    """Gửi nguyên frame qua socket TCP."""
    sock.sendall(encode_frame(message))


def recv_exact(sock, n: int) -> bytes:
    """Đọc đúng n byte vì một lần recv có thể nhận thiếu."""
    if n < 0:
        raise ValueError("n phải không âm")
    chunks = []
    remaining = n
    while remaining:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("TCP đóng trước khi nhận đủ dữ liệu")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def recv_frame(sock) -> dict:
    """Đọc đúng một frame và trả về envelope dạng dict."""
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_CONTROL_FRAME:
        raise ProtocolError("FRAME_TOO_LARGE", "Frame vượt quá 65536 byte")
    if length == 0:
        raise ProtocolError("BAD_FRAME", "JSON payload rỗng")
    payload = recv_exact(sock, length)
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("BAD_FRAME", "JSON UTF-8 không hợp lệ") from exc
    validate_envelope(message)
    return message
