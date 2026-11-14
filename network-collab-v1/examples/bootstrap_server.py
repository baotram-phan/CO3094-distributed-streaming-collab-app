"""A1.4 — TLS bootstrap server có registry thật, timeout cleanup.

Chạy: python -m examples.bootstrap_server
Demo CHƯA có UDP socket, UDP REGISTER hay AUTH qua mạng.
"""

import argparse
import socket
import ssl
from pathlib import Path

from common.tls import server_context
from common.control_framing import ProtocolError
from server.bootstrap import handle_bootstrap
from server.sessions import SessionRegistry

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--udp-port", type=int, default=9001)
    parser.add_argument("--cert", type=Path, default=ROOT / "certs/server.crt")
    parser.add_argument("--key", type=Path, default=ROOT / "certs/server.key")
    args = parser.parse_args()

    ctx = server_context(args.cert, args.key)
    registry = SessionRegistry(bootstrap_timeout_s=10.0, idle_timeout_s=10.0)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(20)
        listener.settimeout(0.5)  # Thoát accept định kỳ để dọn phiên hết hạn.
        print(f"[BOOTSTRAP] TLS server tại {args.host}:{args.port}", flush=True)
        print(
            "[BOOTSTRAP] A1.4+ quản lý session và sự kiện cleanup; UDP chưa kết nối",
            flush=True,
        )
        print("[BOOTSTRAP] Nhấn Ctrl+C để dừng", flush=True)
        try:
            while True:
                registry.cleanup_expired()
                for event in registry.drain_closed_events():
                    print(
                        f"[SESSION] CLOSED conn_id={event.conn_id:016x} reason={event.reason}",
                        flush=True,
                    )
                try:
                    raw, peer = listener.accept()
                except socket.timeout:
                    continue
                try:
                    with raw:
                        raw.settimeout(5)
                        with ctx.wrap_socket(raw, server_side=True) as tls_sock:
                            session = handle_bootstrap(
                                tls_sock,
                                udp_port=args.udp_port,
                                registry=registry,
                                peer_ip=peer[0],
                            )
                            print(
                                f"[SESSION] BOOTSTRAPPED peer={peer[0]} "
                                f"conn_id={session.conn_id:016x} "
                                f"pending={len(registry)}",
                                flush=True,
                            )
                except (ssl.SSLError, OSError, ProtocolError, ValueError) as exc:
                    print(
                        f"[BOOTSTRAP] Từ chối kết nối: {type(exc).__name__}", flush=True
                    )
        except KeyboardInterrupt:
            print("\n[BOOTSTRAP] Đã dừng")


if __name__ == "__main__":
    main()
