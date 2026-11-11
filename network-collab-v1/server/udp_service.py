"""A1.5 bridge: B's actual packet/crypto/replay/state -> A's SessionRegistry.

The UDP receive loop is the only owner of transport state. Future work by B
can replace this thin adapter with a full reliable transport without changing
SessionRegistry, TLS bootstrap, or the A/B contract.
"""
from __future__ import annotations

import socket
import threading
from typing import Callable

from cryptography.exceptions import InvalidTag

from common.constants import HEADER_SIZE, GCM_TAG_SIZE, MAX_UDP_DATAGRAM, REGISTER, REGISTER_OK
from common.transport_state import TransportConnectionState
from common.transport_manager import TransportStateManager
from common.udp_packet import decode_header, decode_packet, encode_packet
from server.sessions import SessionError, SessionRegistry, SessionState


class UDPTransportService:
    def __init__(
        self,
        registry: SessionRegistry,
        *,
        host: str = "127.0.0.1",
        port: int = 9001,
        on_udp_registered: Callable[[int, tuple[str, int]], None] | None = None,
        logger: Callable[[str], None] | None = print,
    ) -> None:
        self.registry = registry  # MUST be the same instance as TLS bootstrap.
        self.on_udp_registered = on_udp_registered
        self._log = logger
        self._manager = TransportStateManager()
        # Serializes lifecycle operations with coordinator cleanup, NOT Registry calls.
        self._lifecycle_lock = threading.Lock()
        self._closed_conn_ids: set[int] = set()
        self._stopping = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((host, port))
            self.sock.settimeout(0.1)
        except Exception:
            self.sock.close()
            raise
        self.port = self.sock.getsockname()[1]

    def connection_ids(self) -> set[int]:
        """Snapshot for inspection/tests, not a separate source of truth."""
        return self._manager.connection_ids()

    def remove_connection(self, conn_id: int) -> bool:
        """Called ONLY by A's coordinator after a close event.

        Tombstone is set before removing transport state, so an in-flight
        REGISTER cannot recreate the state after cleanup has completed.
        No Registry call or application callback happens under this lock.
        """
        with self._lifecycle_lock:
            self._closed_conn_ids.add(conn_id)
            return self._manager.remove(conn_id)

    def _is_active_bound(self, conn_id: int, endpoint: tuple[str, int]) -> bool:
        """Re-check the Registry after bind without holding transport locks."""
        live = self.registry.get(conn_id)
        return bool(live is not None
                    and live.state in (SessionState.UDP_BOUND, SessionState.ONLINE)
                    and live.udp_endpoint == endpoint)

    def handle_datagram(self, packet: bytes, endpoint: tuple[str, int]) -> bool:
        """Handle one datagram in the SINGLE receive loop, True iff accepted.

        Order per approved contract: replay peek -> AES-GCM verify -> registry
        bind -> replay commit -> fresh server packet number -> REGISTER_OK.
        Do not run this method concurrently for the same ConnID.
        """
        if not (HEADER_SIZE + GCM_TAG_SIZE <= len(packet) <= MAX_UDP_DATAGRAM):
            return False
        try:
            packet_type, conn_id, pkt_num = decode_header(packet[:HEADER_SIZE])
            if packet_type != REGISTER:
                return False
            session = self.registry.get(conn_id)
            if session is None:
                return False

            # Avoid creating persistent state from unauthenticated datagrams.
            state = self._manager.get(conn_id)
            if state is None:
                state = TransportConnectionState(conn_id)
            if not state.recv_replay.can_accept(pkt_num):
                return False

            # B's codec verifies full header AAD, AEAD tag, and empty body.
            kind, checked_conn_id, checked_pkt_num, payload = decode_packet(session.c2s_key, packet)
            if (kind, checked_conn_id, checked_pkt_num, payload) != (REGISTER, conn_id, pkt_num, b""):
                return False

            binding = self.registry.bind_udp_verified_with_status(conn_id, endpoint)
            # Registry may have been closed concurrently after bind returned.
            # Never call Registry with a transport lock held (lock-order safety).
            if not self._is_active_bound(conn_id, endpoint):
                return False

            with self._lifecycle_lock:
                if conn_id in self._closed_conn_ids:
                    return False
                # Commit replay and allocate server PN only for accepted REGISTER.
                # The UDP receive loop itself is sequential for each ConnID.
                state = self._manager.add(conn_id)
                if not state.recv_replay.commit(pkt_num):
                    raise RuntimeError("Unexpected replay race: UDP handler must be sequential")
                response_pn = state.allocate_packet_number()

            # Close might occur *during* add/commit. Revalidate, and locally
            # clean up if coordinator has not had a chance to drain the event.
            if not self._is_active_bound(conn_id, endpoint):
                self.remove_connection(conn_id)
                return False

            # Report first registration only once, outside any transport lock.
            if binding.newly_bound and self.on_udp_registered:
                try:
                    self.on_udp_registered(conn_id, endpoint)
                except Exception as exc:
                    if self._log:
                        self._log(f"[UDP] on_udp_registered failed: {type(exc).__name__}")

            # A callback may close the session; never reply using a stale state.
            if not self._is_active_bound(conn_id, endpoint):
                self.remove_connection(conn_id)
                return False
            with self._lifecycle_lock:
                if conn_id in self._closed_conn_ids:
                    return False
            reply = encode_packet(binding.session.s2c_key, REGISTER_OK, conn_id, response_pn)
            try:
                self.sock.sendto(reply, endpoint)
            except OSError:
                # A lost reply is retried with a NEW client packet number.
                return True
            if self._log:
                self._log(f"[UDP] REGISTER_OK conn_id={conn_id:016x} "
                          f"state={binding.session.state.value} "
                          f"first={binding.newly_bound} peer={endpoint[0]}:{endpoint[1]}")
            return True
        except (InvalidTag, SessionError, ValueError, TypeError):
            # No error response to unauthenticated UDP; avoid leaking secrets.
            return False

    def serve_once(self) -> None:
        try:
            packet, endpoint = self.sock.recvfrom(MAX_UDP_DATAGRAM + 1)
        except socket.timeout:
            pass
        except OSError:
            if not self._stopping.is_set():
                raise
        else:
            self.handle_datagram(packet, endpoint)

    def serve_forever(self) -> None:
        while not self._stopping.is_set():
            self.serve_once()

    def stop(self) -> None:
        self._stopping.set()
        self.sock.close()
