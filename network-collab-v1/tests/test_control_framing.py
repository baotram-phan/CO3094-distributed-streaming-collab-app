import json
import struct
import unittest

from common.constants import MAX_CONTROL_FRAME
from common.control_framing import (
    ProtocolError, encode_frame, recv_exact, recv_frame, send_frame,
)


class FakeSocket:
    """Giả lập một socket nhận được tối đa max_chunk bytes/lần recv."""

    def __init__(self, incoming=b"", max_chunk=2):
        self.incoming = incoming
        self.max_chunk = max_chunk
        self.sent = b""

    def recv(self, n):
        size = min(n, self.max_chunk)
        part, self.incoming = self.incoming[:size], self.incoming[size:]
        return part

    def sendall(self, data):
        self.sent += data


def hello(version="1.0"):
    return {"v": 1, "type": "HELLO", "id": 1, "reply_to": None,
            "body": {"client_version": version}}


class TestControlFraming(unittest.TestCase):
    def test_prefix_length_is_big_endian(self):
        frame = encode_frame(hello())
        self.assertEqual(struct.unpack("!I", frame[:4])[0], len(frame) - 4)
        self.assertEqual(json.loads(frame[4:].decode("utf-8")), hello())

    def test_roundtrip_even_if_recv_returns_one_byte(self):
        self.assertEqual(recv_frame(FakeSocket(encode_frame(hello()), 1)), hello())

    def test_two_frames_in_one_tcp_stream(self):
        second = dict(hello("2.0"), id=2)
        stream = FakeSocket(encode_frame(hello()) + encode_frame(second))
        self.assertEqual(recv_frame(stream), hello())
        self.assertEqual(recv_frame(stream), second)

    def test_send_frame(self):
        sock = FakeSocket()
        send_frame(sock, hello())
        self.assertEqual(sock.sent, encode_frame(hello()))

    def test_early_socket_close(self):
        with self.assertRaises(ConnectionError):
            recv_exact(FakeSocket(b"abc"), 4)

    def test_incoming_too_large(self):
        sock = FakeSocket(struct.pack("!I", MAX_CONTROL_FRAME + 1))
        with self.assertRaises(ProtocolError) as e:
            recv_frame(sock)
        self.assertEqual(e.exception.code, "FRAME_TOO_LARGE")

    def test_outgoing_too_large(self):
        with self.assertRaises(ProtocolError) as e:
            encode_frame(hello("x" * MAX_CONTROL_FRAME))
        self.assertEqual(e.exception.code, "FRAME_TOO_LARGE")

    def test_invalid_json(self):
        data = b'{"v":1,'
        sock = FakeSocket(struct.pack("!I", len(data)) + data)
        with self.assertRaises(ProtocolError) as e:
            recv_frame(sock)
        self.assertEqual(e.exception.code, "BAD_FRAME")

    def test_wrong_version(self):
        with self.assertRaises(ProtocolError) as e:
            encode_frame(dict(hello(), v=2))
        self.assertEqual(e.exception.code, "UNSUPPORTED_VERSION")

    def test_missing_envelope_fields(self):
        with self.assertRaises(ProtocolError) as e:
            encode_frame({"v": 1, "type": "HELLO"})
        self.assertEqual(e.exception.code, "BAD_FRAME")


if __name__ == "__main__":
    unittest.main()
