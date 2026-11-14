"""TLS HELLO/HELLO_ACK exchange and optional session registration.

The live server passes a shared SessionRegistry. The optional registry argument
also supports standalone bootstrap tests and examples.
"""

import base64
from dataclasses import dataclass
import secrets

from common.control_framing import ProtocolError, recv_frame, send_frame
from common.constants import PROTOCOL_VERSION
from server.sessions import SessionRegistry


@dataclass(frozen=True)
class BootstrapSession:
    conn_id: int
    c2s_key: bytes
    s2c_key: bytes


def handle_bootstrap(
    tls_sock,
    *,
    udp_port: int = 9001,
    registry: SessionRegistry | None = None,
    peer_ip: str = "127.0.0.1",
) -> BootstrapSession:
    """Nhận HELLO, tạo phiên trước khi gửi HELLO_ACK và trả thông tin cho caller."""
    hello = recv_frame(tls_sock)
    if hello["type"] != "HELLO":
        raise ProtocolError("EXPECTED_HELLO", "TCP bootstrap chỉ nhận HELLO")
    if hello["body"].get("client_version") != "1.0":
        raise ProtocolError("BAD_CLIENT_VERSION", "Cần client_version=1.0")

    c2s_key = secrets.token_bytes(32)
    s2c_key = secrets.token_bytes(32)
    # Hai khóa độc lập; tránh trùng cả khi kiểm thử với RNG được mock.
    while s2c_key == c2s_key:
        s2c_key = secrets.token_bytes(32)

    if registry is None:
        # Dành cho demo/test A1.3 cũ; production phải truyền registry.
        session = BootstrapSession(secrets.randbits(64) or 1, c2s_key, s2c_key)
    else:
        saved = registry.create_bootstrap(
            tcp_ip=peer_ip,
            c2s_key=c2s_key,
            s2c_key=s2c_key,
        )
        session = BootstrapSession(saved.conn_id, saved.c2s_key, saved.s2c_key)

    ack = {
        "v": PROTOCOL_VERSION,
        "type": "HELLO_ACK",
        "id": 1,
        "reply_to": hello["id"],
        "body": {
            "conn_id": f"{session.conn_id:016x}",
            "udp_port": udp_port,
            "c2s_key": base64.b64encode(session.c2s_key).decode("ascii"),
            "s2c_key": base64.b64encode(session.s2c_key).decode("ascii"),
            "heartbeat_ms": 2000,
            "udp_register_deadline_ms": (
                int(registry.bootstrap_timeout_s * 1000) if registry else 10000
            ),
        },
    }
    try:
        send_frame(tls_sock, ack)
    except Exception:
        # Không giữ session nếu TLS ACK không gửi được.
        if registry is not None:
            registry.close(session.conn_id)
        raise
    return session
