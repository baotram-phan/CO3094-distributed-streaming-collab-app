"""Demo A1.3: client xác thực certificate của server rồi HELLO/HELLO_ACK."""

import argparse
import base64
import socket
from pathlib import Path

from common.constants import PROTOCOL_VERSION
from common.control_framing import ProtocolError, recv_frame, send_frame
from common.tls import client_context

ROOT = Path(__file__).resolve().parents[1]


def bootstrap(
    *, host: str = "127.0.0.1", port: int = 9000, trusted_cert: Path | None = None
) -> dict:
    if trusted_cert is None:
        trusted_cert = ROOT / "certs/server.crt"
    ctx = client_context(trusted_cert)
    with socket.create_connection((host, port), timeout=5) as raw:
        raw.settimeout(5)
        # Quan trọng: server_hostname khớp SAN certificate, KHÔNG tắt check_hostname.
        with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
            print("[CLIENT] TLS:", tls_sock.version())
            send_frame(
                tls_sock,
                {
                    "v": PROTOCOL_VERSION,
                    "type": "HELLO",
                    "id": 1,
                    "reply_to": None,
                    "body": {"client_version": "1.0"},
                },
            )
            reply = recv_frame(tls_sock)
    if reply["type"] != "HELLO_ACK" or reply["reply_to"] != 1:
        raise ProtocolError("BAD_HELLO_ACK", "HELLO_ACK không hợp lệ")
    body = reply["body"]
    if not isinstance(body.get("conn_id"), str) or len(body["conn_id"]) != 16:
        raise ProtocolError("BAD_HELLO_ACK", "conn_id phải là 16 hex digits")
    try:
        conn_id = int(body["conn_id"], 16)
        c2s = base64.b64decode(body["c2s_key"], validate=True)
        s2c = base64.b64decode(body["s2c_key"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("BAD_HELLO_ACK", "ConnID/khóa không hợp lệ") from exc
    if conn_id == 0 or len(c2s) != 32 or len(s2c) != 32:
        raise ProtocolError("BAD_HELLO_ACK", "ConnID/khóa không hợp lệ")
    return {
        "conn_id": conn_id,
        "udp_port": body["udp_port"],
        "c2s_key": c2s,
        "s2c_key": s2c,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--trust", type=Path, default=ROOT / "certs/server.crt")
    args = parser.parse_args()
    session = bootstrap(host=args.host, port=args.port, trusted_cert=args.trust)
    print("[CLIENT] HELLO_ACK OK")
    print(f"[CLIENT] ConnID={session['conn_id']:016x}, UDP port={session['udp_port']}")
    print("[CLIENT] Đã nhận hai khóa UDP 32 byte qua TLS (KHÔNG HIỂN THỊ KHÓA)")
    print("[CLIENT] A1.3 hoàn tất; chưa có UDP REGISTER/AUTH")


if __name__ == "__main__":
    main()
