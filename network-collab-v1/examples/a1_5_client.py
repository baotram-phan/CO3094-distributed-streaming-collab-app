"""A1.5 client demo using real TLS keys and encrypted UDP REGISTER.

Only REGISTER/REGISTER_OK; reliable control-stream AUTH belongs to A1.6.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import socket

from examples.bootstrap_client import bootstrap, ROOT
from examples.a1_5_reference_udp import (
    BadDatagram,
    REGISTER,
    REGISTER_OK,
    make_register_packet,
    verify_register_packet,
)


def register_udp(
    *,
    host: str,
    udp_port: int,
    conn_id: int,
    c2s_key: bytes,
    s2c_key: bytes,
    attempts: int = 10,
    wait_s: float = 0.5,
):
    """New packet number for each retry; same UDP socket/endpoint throughout.

    Returns bound local address. No heartbeat is implemented in A1.5.
    """
    server_ip = socket.gethostbyname(host)  # IPv4 transport for this A1.5 demo
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(wait_s)
        for packet_number in range(attempts):
            packet = make_register_packet(REGISTER, conn_id, packet_number, c2s_key)
            sock.sendto(packet, (server_ip, udp_port))
            try:
                while True:
                    data, source = sock.recvfrom(2048)
                    if source != (server_ip, udp_port):
                        continue
                    try:
                        received_conn_id, _ = verify_register_packet(
                            data, s2c_key, expected_type=REGISTER_OK
                        )
                    except BadDatagram:
                        continue
                    if received_conn_id != conn_id:
                        continue
                    return sock.getsockname()
            except socket.timeout:
                continue
    raise TimeoutError("No authenticated REGISTER_OK; bootstrap again")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=9000)
    ap.add_argument("--trust", type=Path, default=ROOT / "certs/server.crt")
    args = ap.parse_args()
    session = bootstrap(host=args.host, port=args.tcp_port, trusted_cert=args.trust)
    print(f'[CLIENT] TLS HELLO_ACK conn_id={session["conn_id"]:016x}')
    addr = register_udp(
        host=args.host,
        udp_port=session["udp_port"],
        conn_id=session["conn_id"],
        c2s_key=session["c2s_key"],
        s2c_key=session["s2c_key"],
    )
    print(f"[CLIENT] REGISTER_OK verified, local UDP port={addr[1]}")
    print("[CLIENT] A1.5 UDP_BOUND demo OK (AUTH not implemented yet)")


if __name__ == "__main__":
    main()
