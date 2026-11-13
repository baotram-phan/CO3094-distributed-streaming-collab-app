"""Real A-side session runtime: TLS bootstrap -> REGISTER -> reliable AUTH/chat.

Uses B's UDPRegistrationClient for the entire encrypted reliable connection.
The only socket reader is the client's pump thread. This module does not
implement its own UDP codec, retransmission or congestion algorithm.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path
import queue
import struct
import threading
import time
from typing import Any

from common.control_framing import ProtocolError
from common.control_stream_framing import MAX_CONTROL_JSON, decode_control_json, encode_control_message
from client.core.udp_connection import UDPRegistrationClient
from examples.bootstrap_client import ROOT, bootstrap


class CollaborationClient:
    """One TLS-bootstrapped, UDP-bound client with two reliable app streams.

    The application/event queue is bounded; if it cannot retain a received
    message the connection fails closed rather than falsely confirming flow
    consumption. Not a reconnection or file-transfer client.
    """

    def __init__(self, *, host: str = "127.0.0.1", tcp_port: int = 9000,
                 trusted_cert: Path | None = None, event_queue_size: int = 1024):
        if type(event_queue_size) is not int or event_queue_size < 1:
            raise ValueError("event_queue_size must be positive")
        self.host = host
        self.tcp_port = tcp_port
        self.trusted_cert = trusted_cert or ROOT / "certs/server.crt"
        self.udp: UDPRegistrationClient | None = None
        self.conn_id: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._events: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=event_queue_size)
        self._stream_buffers: dict[int, bytearray] = {0: bytearray(), 1: bytearray()}
        self._receive_offsets: dict[int, int] = {0: 0, 1: 0}
        self._send_ids: dict[int, int] = {0: 1, 1: 1}
        self._send_lock = threading.Lock()
        self._login_done = threading.Event()
        self._login_request_id: int | None = None
        self._login_result: dict | None = None
        self.username: str | None = None
        self.failure: Exception | None = None

    def connect(self) -> None:
        if self.udp is not None:
            raise RuntimeError("Already connected")
        started = time.monotonic()
        info = bootstrap(host=self.host, port=self.tcp_port, trusted_cert=self.trusted_cert)
        udp = UDPRegistrationClient(
            host=self.host, udp_port=info["udp_port"], conn_id=info["conn_id"],
            c2s_key=info["c2s_key"], s2c_key=info["s2c_key"],
            bootstrap_deadline=started + 10.0,
        )
        try:
            udp.register(attempts=10, wait_s=0.5)
        except Exception:
            udp.close()
            raise
        self.udp = udp
        self.conn_id = info["conn_id"]
        self._thread = threading.Thread(target=self._receive_loop, daemon=True,
                                        name=f"a-client-{self.conn_id:016x}")
        self._thread.start()

    def _send_message(self, stream_id: int, kind: str, body: dict) -> int:
        if self.udp is None or self._stop.is_set() or self.failure is not None:
            raise RuntimeError("UDP session is not active")
        with self._send_lock:
            message_id = self._send_ids[stream_id]
            envelope = {"v": 1, "type": kind, "id": message_id,
                        "reply_to": None, "body": body}
            frame = encode_control_message(envelope)
            self.udp.queue_reliable_bytes(stream_id, frame)
            self._send_ids[stream_id] += 1
        return message_id

    def authenticate(self, username: str, password: str, *, timeout_s: float = 5.0) -> bool:
        """Return True on AUTH_OK, False on AUTH_FAIL; otherwise raise timeout/error."""
        if self._login_request_id is not None:
            raise RuntimeError("AUTH already attempted on this session")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._login_done.clear()
        self._login_request_id = self._send_message(0, "AUTH", {
            "username": username, "password": password,
        })
        if not self._login_done.wait(timeout_s):
            if self.failure is not None:
                raise RuntimeError("UDP client worker failed") from self.failure
            raise TimeoutError("No AUTH response before deadline")
        if self.failure is not None:
            raise RuntimeError("UDP client worker failed") from self.failure
        result = self._login_result
        if result is None:
            raise RuntimeError("AUTH response missing")
        if result["type"] == "AUTH_OK":
            self.username = username
            return True
        if result["type"] == "AUTH_FAIL":
            return False
        raise RuntimeError(f"Server refused AUTH: {result['body']}")

    def send_direct(self, recipient: str, text: str) -> int:
        if self.username is None:
            raise RuntimeError("Authenticate before chat")
        return self._send_message(1, "CHAT_DIRECT", {"to": recipient, "text": text})

    def send_broadcast(self, text: str) -> int:
        if self.username is None:
            raise RuntimeError("Authenticate before chat")
        return self._send_message(1, "CHAT_BROADCAST", {"text": text})

    def receive_event(self, timeout_s: float | None = None) -> dict:
        """Read next inbound application envelope; no direct UDP socket reads."""
        return self._events.get(timeout=timeout_s)

    def _process_delivery(self, stream_id: int, offset: int, data: bytes, fin: bool) -> None:
        if stream_id not in (0, 1):
            raise ProtocolError("UNSUPPORTED_STREAM", "Client only handles stream 0/1")
        expected = self._receive_offsets[stream_id]
        if offset < expected and offset + len(data) <= expected:
            return  # B's reassembly normally already suppresses duplicates.
        if offset != expected:
            raise ProtocolError("BAD_OFFSET", "Noncontiguous inbound stream")
        self._receive_offsets[stream_id] += len(data)
        buf = self._stream_buffers[stream_id]
        buf.extend(data)
        while len(buf) >= 4:
            (size,) = struct.unpack("!I", buf[:4])
            if not 1 <= size <= MAX_CONTROL_JSON:
                raise ProtocolError("BAD_FRAME", "Invalid application frame length")
            if len(buf) < size + 4:
                break
            message = decode_control_json(bytes(buf[4:4 + size]))
            del buf[:4 + size]
            # Retain the message before confirming transport consumption.
            self._events.put_nowait(message)
            if (stream_id == 0 and self._login_request_id is not None
                    and message.get("reply_to") == self._login_request_id
                    and message["type"] in ("AUTH_OK", "AUTH_FAIL", "ERROR")):
                self._login_result = message
                self._login_done.set()
        if len(buf) > MAX_CONTROL_JSON + 4:
            raise ProtocolError("BAD_FRAME", "Unbounded incomplete application frame")
        if fin and buf:
            raise ProtocolError("BAD_FRAME", "Incomplete frame at FIN")

    def _receive_loop(self) -> None:
        udp = self.udp
        assert udp is not None
        try:
            while not self._stop.is_set():
                udp.pump_reliable_once(timeout_s=0.01, max_packets=32)
                while not self._stop.is_set():
                    delivery = udp.pop_reliable_delivery()
                    if delivery is None:
                        break
                    self._process_delivery(delivery.stream_id, delivery.offset,
                                           delivery.data, delivery.fin)
                    udp.confirm_consumed(delivery.stream_id,
                                         delivery.offset + len(delivery.data))
        except (OSError, RuntimeError) as exc:
            if not self._stop.is_set():
                self.failure = exc
        except Exception as exc:
            self.failure = exc
        finally:
            self._stop.set()
            self._login_done.set()

    def close(self) -> None:
        self._stop.set()
        if self.udp is not None:
            self.udp.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def __enter__(self) -> "CollaborationClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
