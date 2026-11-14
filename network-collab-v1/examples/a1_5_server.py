"""A1.5 reference demo: real TLS bootstrap and real encrypted UDP REGISTER.

One process owns ONE SessionRegistry shared by TCP and UDP threads.
UDP handling here is a temporary adapter; B's code replaces the UDP loop.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import socket
import ssl
import threading

from common.control_framing import ProtocolError
from common.tls import server_context
from examples.a1_5_reference_udp import (
    BadDatagram,
    REGISTER,
    REGISTER_OK,
    ReplayWindow,
    make_register_packet,
    peek_header,
    verify_register_packet,
)
from server.bootstrap import handle_bootstrap
from server.sessions import SessionError, SessionRegistry, SessionState

ROOT = Path(__file__).resolve().parents[1]


class A15Server:
    def __init__(
        self,
        *,
        host="127.0.0.1",
        tcp_port=9000,
        udp_port=9001,
        cert=None,
        key=None,
        registry=None,
        verbose=True,
    ):
        cert = Path(cert) if cert else ROOT / "certs/server.crt"
        key = Path(key) if key else ROOT / "certs/server.key"
        self.tls_context = server_context(cert, key)
        self.registry = registry if registry is not None else SessionRegistry()
        self.verbose = verbose
        self.stop_event = threading.Event()
        self.tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._recv_windows: dict[int, ReplayWindow] = {}
        self._send_pkt_numbers: dict[int, int] = defaultdict(int)
        self._tcp_threads: list[threading.Thread] = []
        try:
            self.tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_listener.bind((host, tcp_port))
            self.tcp_listener.listen(20)
            self.tcp_listener.settimeout(0.2)
            self.udp_socket.bind((host, udp_port))
            self.udp_socket.settimeout(0.2)
        except Exception:
            self.tcp_listener.close()
            self.udp_socket.close()
            raise
        self.tcp_port = self.tcp_listener.getsockname()[1]
        self.udp_port = self.udp_socket.getsockname()[1]

    def _log(self, *args):
        if self.verbose:
            print(*args, flush=True)

    def _serve_bootstrap_client(self, raw: socket.socket, peer: tuple):
        try:
            with raw:
                raw.settimeout(5)
                with self.tls_context.wrap_socket(raw, server_side=True) as tls_sock:
                    sess = handle_bootstrap(
                        tls_sock,
                        udp_port=self.udp_port,
                        registry=self.registry,
                        peer_ip=peer[0],
                    )
                    self._log(f"[TCP] BOOTSTRAPPED conn_id={sess.conn_id:016x}")
        except (ssl.SSLError, ProtocolError, OSError, ValueError) as exc:
            self._log(f"[TCP] Failed: {type(exc).__name__}")

    def _serve_udp_once(self):
        try:
            data, endpoint = self.udp_socket.recvfrom(2048)
        except socket.timeout:
            return
        except OSError:
            if self.stop_event.is_set():
                return
            raise
        # Untrusted header is used ONLY for session/key lookup.
        try:
            kind, conn_id, pkt_num = peek_header(data)
            if kind != REGISTER:
                return
            session = self.registry.get(conn_id)
            if session is None:
                return
            window = self._recv_windows.setdefault(conn_id, ReplayWindow())
            if not window.can_accept(pkt_num):
                return
            verify_register_packet(data, session.c2s_key, expected_type=REGISTER)
            # Must check endpoint and expiry before accepting new packet number.
            binding = self.registry.bind_udp_verified_with_status(conn_id, endpoint)
            updated = binding.session
            window.commit(pkt_num)
            outgoing_pn = self._send_pkt_numbers[conn_id]
            self._send_pkt_numbers[conn_id] += 1
            reply = make_register_packet(
                REGISTER_OK, conn_id, outgoing_pn, updated.s2c_key
            )
            self.udp_socket.sendto(reply, endpoint)
            self._log(
                f"[UDP] REGISTER_OK conn_id={conn_id:016x} state={updated.state.value}"
                f" first={binding.newly_bound} peer={endpoint[0]}:{endpoint[1]}"
            )
        except (BadDatagram, SessionError, ValueError):
            # Never reflect AEAD failures to unauthenticated sender.
            return

    def serve_forever(self):
        self._log(f"[SERVER] TCP/TLS :{self.tcp_port}, UDP :{self.udp_port}")
        udp_thread = threading.Thread(target=self._serve_udp_loop, daemon=True)
        udp_thread.start()
        try:
            while not self.stop_event.is_set():
                self.registry.cleanup_expired()
                for event in self.registry.drain_closed_events():
                    self._recv_windows.pop(event.conn_id, None)
                    self._send_pkt_numbers.pop(event.conn_id, None)
                    self._log(
                        f"[SESSION] CLOSED {event.conn_id:016x} reason={event.reason}"
                    )
                try:
                    raw, peer = self.tcp_listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                t = threading.Thread(
                    target=self._serve_bootstrap_client, args=(raw, peer), daemon=True
                )
                t.start()
                self._tcp_threads.append(t)
        finally:
            self.stop_event.set()
            self.tcp_listener.close()
            self.udp_socket.close()
            udp_thread.join(timeout=2)
            for t in self._tcp_threads:
                t.join(timeout=1)

    def _serve_udp_loop(self):
        while not self.stop_event.is_set():
            self._serve_udp_once()

    def stop(self):
        self.stop_event.set()
        self.tcp_listener.close()
        self.udp_socket.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=9000)
    ap.add_argument("--udp-port", type=int, default=9001)
    ap.add_argument("--cert", type=Path, default=ROOT / "certs/server.crt")
    ap.add_argument("--key", type=Path, default=ROOT / "certs/server.key")
    args = ap.parse_args()
    server = A15Server(
        host=args.host,
        tcp_port=args.tcp_port,
        udp_port=args.udp_port,
        cert=args.cert,
        key=args.key,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
