"""A1.5 demo: real TLS HELLO -> B-codec UDP REGISTER -> UDP_BOUND."""
from __future__ import annotations

import argparse
from pathlib import Path
import time

from client.core.udp_connection import UDPRegistrationClient
from examples.bootstrap_client import ROOT, bootstrap


def main() -> None:
    ap = argparse.ArgumentParser(description='TLS bootstrap followed by authenticated UDP REGISTER')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--tcp-port', type=int, default=9000)
    ap.add_argument('--trust', type=Path, default=ROOT / 'certs/server.crt')
    args = ap.parse_args()

    # The server's BOOTSTRAPPED 10 s deadline starts before it sends HELLO_ACK.
    # Starting our clock before the TLS handshake conservatively respects it.
    bootstrap_started_at = time.monotonic()
    session = bootstrap(host=args.host, port=args.tcp_port, trusted_cert=args.trust)
    print(f'[CLIENT] TLS HELLO_ACK conn_id={session["conn_id"]:016x}')
    with UDPRegistrationClient(
        host=args.host,
        udp_port=session['udp_port'],
        conn_id=session['conn_id'],
        c2s_key=session['c2s_key'],
        s2c_key=session['s2c_key'],
        bootstrap_deadline=bootstrap_started_at + 10.0,
    ) as client:
        endpoint = client.register(attempts=10, wait_s=0.5)
        print(f'[CLIENT] REGISTER_OK verified; local UDP port={endpoint[1]}')
        print('[CLIENT] A1.5 UDP_BOUND OK (B codec); AUTH/heartbeat not implemented')
    # One-shot demo only: A1.6 must keep this socket and packet counters alive.


if __name__ == '__main__':
    main()
