"""A1.5 bridge: B's actual packet/crypto/replay/state -> A's SessionRegistry.

The UDP receive loop is the only owner of transport state. Future work by B
can replace this thin adapter with a full reliable transport without changing
SessionRegistry, TLS bootstrap, or the A/B contract.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

from cryptography.exceptions import InvalidTag

from common.constants import HEADER_SIZE, GCM_TAG_SIZE, MAX_UDP_DATAGRAM, REGISTER, REGISTER_OK, DATA, ACK, WINDOW_UPDATE
from common.transport_state import TransportConnectionState
from common.transport_manager import TransportStateManager
from common.reliable_receive import ReliableReceiveState, ReceiveResult
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamDelivery
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
        auto_drive: bool = False,
        tick_interval_s: float = 0.01,
        max_packets_per_tick: int = 32,
    ) -> None:
        if type(auto_drive) is not bool:
            raise ValueError("auto_drive must be bool")
        if not 0 < tick_interval_s <= 0.025:
            raise ValueError("tick_interval_s must be in (0, 0.025]")
        if type(max_packets_per_tick) is not int or not 1 <= max_packets_per_tick <= 128:
            raise ValueError("max_packets_per_tick must be in 1..128")
        self.auto_drive = auto_drive
        self.tick_interval_s = tick_interval_s
        self.max_packets_per_tick = max_packets_per_tick
        self._pump_cursor = 0
        self.registry = registry  # MUST be the same instance as TLS bootstrap.
        self.on_udp_registered = on_udp_registered
        self._log = logger
        self._manager = TransportStateManager()
        self._reliable: dict[int, ReliableReceiveState] = {}
        # Serializes lifecycle operations with coordinator cleanup, NOT Registry calls.
        self._lifecycle_lock = threading.Lock()
        self._closed_conn_ids: set[int] = set()
        self._stopping = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((host, port))
            self.sock.settimeout(tick_interval_s if auto_drive else 0.1)
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
            self._reliable.pop(conn_id, None)  # cancel receive/retry state with session
            return self._manager.remove(conn_id)

    def _is_active_bound(self, conn_id: int, endpoint: tuple[str, int]) -> bool:
        """Re-check the Registry after bind without holding transport locks."""
        live = self.registry.get(conn_id)
        return bool(live is not None
                    and live.state in (SessionState.UDP_BOUND, SessionState.ONLINE)
                    and live.udp_endpoint == endpoint)

    def get_reliable_receiver(self, conn_id: int) -> ReliableReceiveState | None:
        """For the later A worker bridge; do not mutate it concurrently with UDP."""
        with self._lifecycle_lock:
            return self._reliable.get(conn_id)

    def pop_reliable_delivery(self, conn_id: int) -> StreamDelivery | None:
        """Pop one reassembled delivery; process it OUTSIDE transport locks.

        Popping does not grant credit. The application calls confirm_consumed()
        only after successfully processing/storing bytes through an offset.
        """
        if self._bound_session_for_send(conn_id) is None:
            return None
        with self._lifecycle_lock:
            if self._stopping.is_set() or conn_id in self._closed_conn_ids:
                return None
            receiver = self._reliable.get(conn_id)
            return receiver.pop_delivery() if receiver is not None else None

    def confirm_consumed(self, conn_id: int, stream_id: int, consumed_offset: int) -> bool:
        """After A consumes a popped delivery, enqueue its WINDOW_UPDATE.

        Does not send a datagram or invoke A under the transport lock.
        The B4.3 pump will send the pending credit advertisement.
        """
        if self._bound_session_for_send(conn_id) is None:
            raise RuntimeError("connection is not bound or no longer active")
        with self._lifecycle_lock:
            receiver = self._reliable.get(conn_id)
            if self._stopping.is_set() or conn_id in self._closed_conn_ids or receiver is None:
                raise RuntimeError("reliable transport is no longer active")
            return receiver.confirm_consumed(stream_id, consumed_offset)

    def _bound_session_for_send(self, conn_id: int):
        """Read Registry without any transport lock; A retains lifecycle ownership."""
        session = self.registry.get(conn_id)
        if (session is None
                or session.state not in (SessionState.UDP_BOUND, SessionState.ONLINE)
                or session.udp_endpoint is None):
            return None
        return session

    def queue_reliable_bytes(self, conn_id: int, stream_id: int, data: bytes, *, fin: bool = False) -> None:
        """Queue exact stream bytes in an already REGISTERed connection.

        This is B's internal enqueue API, not A's final control/chat ABI.
        """
        if self._bound_session_for_send(conn_id) is None:
            raise RuntimeError("connection is not bound or no longer active")
        with self._lifecycle_lock:
            receiver = self._reliable.get(conn_id)
            if self._stopping.is_set() or conn_id in self._closed_conn_ids or receiver is None:
                raise RuntimeError("reliable transport is no longer active")
            receiver.streams.queue_bytes(stream_id, data, fin=fin)

    def send_reliable_once(self, conn_id: int) -> PreparedScheduledSend | None:
        """Send at most one DATA/retry/WINDOW_UPDATE over the original UDP socket.

        Only transport state and socket I/O are under the lifecycle lock.
        Never call Registry or an application callback while holding it.
        """
        session = self._bound_session_for_send(conn_id)

        if session is None:
            return None

        endpoint = session.udp_endpoint
        if endpoint is None:
            return None
        with self._lifecycle_lock:
            receiver = self._reliable.get(conn_id)
            if self._stopping.is_set() or conn_id in self._closed_conn_ids or receiver is None:
                return None
            plan = receiver.prepare_send(session.s2c_key, now_ms=time.monotonic() * 1000)
            if plan is None:
                return None
            try:
                size = self.sock.sendto(plan.datagram, endpoint)
                if size != len(plan.datagram):
                    raise OSError("UDP sendto returned a partial datagram")
            except OSError:
                receiver.abort_send(plan)
                raise
            receiver.commit_send(plan)
            return plan

    def send_ack_once(self, conn_id: int) -> bool:
        """Send pending ACK-only packet; ACK ranges advance after sendto success.

        ACK never enters in-flight accounting or triggers a new ACK.
        """
        session = self._bound_session_for_send(conn_id)
        if session is None:
            return False

        endpoint = session.udp_endpoint
        if endpoint is None:
            return False
        with self._lifecycle_lock:
            receiver = self._reliable.get(conn_id)
            if self._stopping.is_set() or conn_id in self._closed_conn_ids or receiver is None:
                return False
            now_ms = time.monotonic() * 1000
            snapshot = receiver.received.build_ack(now_ms)
            if snapshot is None:
                return False
            pn = receiver.connection.allocate_packet_number()
            packet = encode_packet(session.s2c_key, ACK, conn_id, pn, snapshot.body)
            receiver.sent.track_sent(pn, ACK, len(packet), now_ms)
            size = self.sock.sendto(packet, endpoint)
            if size != len(packet):
                raise OSError("UDP sendto returned a partial ACK datagram")
            receiver.received.mark_ack_sent(snapshot)
            return True

    def _handle_reliable_datagram(
        self,
        packet: bytes,
        endpoint: tuple[str, int],
        conn_id: int,
    ) -> bool:
        # Registry phải được gọi ngoài lifecycle/transport lock.
        session = self.registry.get(conn_id)

        if session is None:
            return False

        # Chỉ nhận reliable packet sau khi REGISTER thành công.
        if session.state not in (
            SessionState.UDP_BOUND,
            SessionState.ONLINE,
        ):
            return False

        # Lấy endpoint mà Registry đã xác nhận.
        bound_endpoint = session.udp_endpoint

        # Chưa REGISTER hoặc packet đến từ endpoint khác.
        if bound_endpoint is None or bound_endpoint != endpoint:
            return False

        with self._lifecycle_lock:
            if conn_id in self._closed_conn_ids:
                return False

            receiver = self._reliable.get(conn_id)
            if receiver is None:
                return False

            outcome = receiver.accept(
                packet,
                key=session.c2s_key,
                endpoint=endpoint,
                bound_endpoint=bound_endpoint,
                now_ms=time.monotonic() * 1000,
            )

        if outcome is None:
            return False

        if outcome.duplicate:
            # Packet trùng không được xử lý lại hoặc refresh idle timeout.
            return True

        # Chỉ packet hợp lệ, không replay mới cập nhật hoạt động.
        try:
            self.registry.touch_verified_udp(conn_id, endpoint)
        except SessionError:
            return False

        return True

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
            if packet_type in (DATA, ACK, WINDOW_UPDATE):
                return self._handle_reliable_datagram(packet, endpoint, conn_id)
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
                if conn_id not in self._reliable:
                    self._reliable[conn_id] = ReliableReceiveState(state)
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

    def pump_reliable_once(self, *, max_packets: int | None = None) -> int:
        """One bounded, fair timer/scheduling round for all live ConnIDs.

        Never calls Registry with the lifecycle lock held. Timer checks occur
        for every active connection even when the send budget is exhausted.
        No new thread or independently owned connection state is created.
        `remove_connection()` tombstones immediately cancel later sends.

        Returns the count of ACK/DATA/WINDOW_UPDATE datagrams sent. A single
        sendto OSError is logged and leaves the staged DATA/ACK eligible for
        a later pump, rather than killing the server receive loop.
        """
        budget = self.max_packets_per_tick if max_packets is None else max_packets
        if type(budget) is not int or not 1 <= budget <= 128:
            raise ValueError("max_packets must be in 1..128")
        if self._stopping.is_set():
            return 0
        with self._lifecycle_lock:
            ids = sorted(self._reliable)
            if not ids:
                return 0
            start = self._pump_cursor % len(ids)
            ids = ids[start:] + ids[:start]
            self._pump_cursor = (start + 1) % len(ids)
        now_ms = time.monotonic() * 1000
        due_ids: list[int] = []
        active_ids: list[int] = []
        for conn_id in ids:
            # Registry calls are ALWAYS outside the transport/lifecycle lock.
            if self._bound_session_for_send(conn_id) is None:
                continue
            with self._lifecycle_lock:
                receiver = self._reliable.get(conn_id)
                if (self._stopping.is_set() or conn_id in self._closed_conn_ids
                        or receiver is None):
                    continue
                due = receiver.timer_tick(now_ms=now_ms).ack_due
            active_ids.append(conn_id)
            if due:
                due_ids.append(conn_id)

        sent = 0
        # ACK-first: do not let a queued file transfer starve pending ACKs.
        for conn_id in due_ids:
            if sent >= budget:
                return sent
            try:
                if self.send_ack_once(conn_id):
                    sent += 1
            except OSError as exc:
                if self._log and not self._stopping.is_set():
                    self._log(f"[UDP] ACK send error conn_id={conn_id:016x}: {exc}")
        # One datagram per connection per round, repeated while budget lasts.
        while sent < budget:
            progressed = False
            for conn_id in active_ids:
                if sent >= budget or self._stopping.is_set():
                    break
                try:
                    if self.send_reliable_once(conn_id) is not None:
                        progressed = True
                        sent += 1
                except OSError as exc:
                    if self._log and not self._stopping.is_set():
                        self._log(f"[UDP] DATA send error conn_id={conn_id:016x}: {exc}")
            if not progressed:
                break
        return sent

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
        if self.auto_drive and not self._stopping.is_set():
            self.pump_reliable_once()

    def serve_forever(self) -> None:
        while not self._stopping.is_set():
            self.serve_once()

    def stop(self) -> None:
        self._stopping.set()
        self.sock.close()