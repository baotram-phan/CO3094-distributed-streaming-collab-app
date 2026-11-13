"""A1.5 unified TLS bootstrap + B's real UDP codec in ONE server process."""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import ssl
import threading

from common.control_framing import ProtocolError
from common.tls import server_context
from server.bootstrap import handle_bootstrap
from server.sessions import SessionRegistry, SessionClosedEvent
from server.udp_service import UDPTransportService
from server.a16_auth_service import A16AuthService
from server.a17_chat_service import A17ChatService
ROOT = Path(__file__).resolve().parents[1]


class CollaborationServer:
    def __init__(self, *, host: str = "127.0.0.1", tcp_port: int = 9000,
                 udp_port: int = 9001, cert: Path | None = None,
                 key: Path | None = None, registry: SessionRegistry | None = None,
                 logger=print, on_udp_registered=None, on_session_closed=None,
                 send_reliable_control=None, send_reliable_chat=None) -> None:
        self.registry = registry if registry is not None else SessionRegistry()
        self.logger = logger
        self.on_session_closed = on_session_closed
        # A1.6 AUTH is DISABLED until B supplies a genuine reliable UDP stream-0
        # sender. Never route AUTH over the TLS/bootstrap socket or raw UDP.
        self.auth_service = (
            A16AuthService(self.registry, send_reliable_control)
            if send_reliable_control is not None else None
        )
        self.chat_service = None
        if send_reliable_chat is not None:
            self.attach_reliable_chat(send_reliable_chat)
        # A is the *only* consumer of Registry close events.
        self._cleanup_lock = threading.Lock()
        self.tls_context = server_context(cert or ROOT / 'certs/server.crt',
                                          key or ROOT / 'certs/server.key')
        self.stop_event = threading.Event()
        self._client_threads: list[threading.Thread] = []
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((host, tcp_port))
            self.tcp_sock.listen(20)
            self.tcp_sock.settimeout(0.1)
            self.udp_service = UDPTransportService(
                self.registry, host=host, port=udp_port,
                logger=logger, on_udp_registered=on_udp_registered,
            )
        except Exception:
            self.tcp_sock.close()
            raise
        self.tcp_port = self.tcp_sock.getsockname()[1]
        self.udp_port = self.udp_service.port

    def _handle_tls(self, raw: socket.socket, peer: tuple[str, int]) -> None:
        try:
            with raw:
                raw.settimeout(5)
                with self.tls_context.wrap_socket(raw, server_side=True) as tls_sock:
                    session = handle_bootstrap(tls_sock, registry=self.registry,
                                               udp_port=self.udp_port, peer_ip=peer[0])
                    if self.logger:
                        self.logger(f"[TLS] BOOTSTRAPPED conn_id={session.conn_id:016x}")
        except (ssl.SSLError, ProtocolError, OSError, ValueError, ConnectionError) as exc:
            if self.logger:
                self.logger(f"[TLS] Rejected: {type(exc).__name__}")

    def attach_reliable_control(self, send_reliable_control) -> None:
        """A/B integration hook: B provides encrypted reliable stream-0 sender.

        Configure before accepting stream callbacks. Do not connect a raw UDP
        sendto or a TLS socket to this hook.
        """
        if self.auth_service is not None:
            raise RuntimeError("Reliable control sender is already attached")
        self.auth_service = A16AuthService(self.registry, send_reliable_control)

    def attach_reliable_chat(self, send_reliable_chat) -> None:
        """B supplies reliable encrypted stream-1 enqueue sender.

        AUTH/stream-0 must be attached first so chat ERROR can use control.
        """
        if self.auth_service is None:
            raise RuntimeError("Attach reliable control stream 0 before chat")
        if self.chat_service is not None:
            raise RuntimeError("Reliable chat sender is already attached")
        self.chat_service = A17ChatService(
            self.registry, send_reliable_chat,
            self.auth_service.send_application_error,
        )

    def on_reliable_stream_data(self, conn_id: int, stream_id: int,
                                offset: int, data: bytes, fin: bool = False) -> bool:
        """B calls ONLY after verified, reassembled, in-order reliable DATA."""
        if stream_id == 0:
            if self.auth_service is None:
                raise RuntimeError("B's reliable encrypted stream-0 transport is not attached")
            return self.auth_service.on_stream_data(conn_id, stream_id, offset, data, fin)
        if stream_id == 1:
            if self.chat_service is None:
                raise RuntimeError("B's reliable encrypted stream-1 transport is not attached")
            return self.chat_service.on_stream_data(conn_id, stream_id, offset, data, fin)
        raise ValueError("File stream_id >=2 is not integrated yet")

    def dispatch_closed_events(self) -> None:
        """A coordinator is sole owner of the Registry close-event queue.

        Drain once, remove B transport state, then notify A application/presence.
        No Registry lock is held while calling transport or callbacks.
        """
        with self._cleanup_lock:
            self.registry.cleanup_expired()
            events = self.registry.drain_closed_events()
            for event in events:
                self.udp_service.remove_connection(event.conn_id)
        # Application/presence callbacks run outside both Registry and
        # transport/coordinator locks (can trigger new lifecycle actions).
        for event in events:
            if self.chat_service is not None:
                try:
                    self.chat_service.on_session_closed(event)
                except Exception as exc:
                    if self.logger:
                        self.logger(f"[CHAT] on_session_closed failed: {type(exc).__name__}")
            if self.auth_service is not None:
                try:
                    self.auth_service.on_session_closed(event)
                except Exception as exc:
                    if self.logger:
                        self.logger(f"[AUTH] on_session_closed failed: {type(exc).__name__}")
            if self.logger:
                self.logger(f"[SESSION] CLOSED conn_id={event.conn_id:016x} reason={event.reason}")
            if self.on_session_closed:
                try:
                    self.on_session_closed(event)
                except Exception as exc:
                    if self.logger:
                        self.logger(f"[SESSION] on_session_closed failed: {type(exc).__name__}")

    def serve_forever(self) -> None:
        if self.logger:
            self.logger(f"[SERVER] TLS TCP :{self.tcp_port}, UDP :{self.udp_port}")
        udp_thread = threading.Thread(target=self.udp_service.serve_forever, daemon=True)
        udp_thread.start()
        try:
            while not self.stop_event.is_set():
                try:
                    raw, peer = self.tcp_sock.accept()
                except socket.timeout:
                    self.dispatch_closed_events()
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                t = threading.Thread(target=self._handle_tls, args=(raw, peer), daemon=True)
                t.start()
                self._client_threads.append(t)
                self.dispatch_closed_events()
        finally:
            self.stop()
            udp_thread.join(timeout=2)
            for t in self._client_threads:
                t.join(timeout=1)

    def stop(self) -> None:
        self.stop_event.set()
        self.tcp_sock.close()
        self.udp_service.stop()
        self.dispatch_closed_events()


def main() -> None:
    parser = argparse.ArgumentParser(description='A1.5: TLS + B UDP REGISTER integration')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--tcp-port', type=int, default=9000)
    parser.add_argument('--udp-port', type=int, default=9001)
    parser.add_argument('--cert', type=Path, default=ROOT / 'certs/server.crt')
    parser.add_argument('--key', type=Path, default=ROOT / 'certs/server.key')
    args = parser.parse_args()
    srv = CollaborationServer(host=args.host, tcp_port=args.tcp_port,
                              udp_port=args.udp_port, cert=args.cert, key=args.key)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == '__main__':
    main()
