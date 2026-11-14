"""B4.4.2: bridge B's verified stream-delivery queue to A's application callback.

A fixed-size worker pool (NOT one thread per connection/packet) shards by
ConnID. One worker owns a ConnID, so callbacks for that ConnID are serial.
Application code runs outside UDP/Registry locks and outside the receive loop.

A callback returning True means it has safely accepted all bytes (including a
partial application frame). A False result is *not* accepted; an exception may
have produced side effects before failing. Therefore neither case is retried
automatically. The A coordinator closes the session on rejection or exception;
B never drains Registry close events and never calls Registry.close().
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import threading
from typing import Callable, TYPE_CHECKING

from common.streams import StreamDelivery
from server.udp_service import UDPTransportService

if TYPE_CHECKING:
    from server.main import CollaborationServer


ApplicationCallback = Callable[[int, int, int, bytes, bool], bool]
FailureCallback = Callable[[int, int, int, str], None]

APPLICATION_REJECTED = "APPLICATION_REJECTED"
APPLICATION_EXCEPTION = "APPLICATION_EXCEPTION"
CONSUMPTION_CONFIRM_FAILED = "CONSUMPTION_CONFIRM_FAILED"
DISPATCHER_EXCEPTION = "DISPATCHER_EXCEPTION"


@dataclass(slots=True)
class _PendingDelivery:
    delivery: StreamDelivery
    # 'active' (first attempt), 'rejected', or 'failed'.
    status: str = "active"


class ReliableDeliveryDispatcher:
    """Bounded, per-ConnID-ordered A callback dispatcher for a B UDP service.

    - No application callback or failure hook is invoked under a transport lock.
    - Callback False pauses *that ConnID* with one retained delivery. No credit.
      A coordinator is notified and is responsible for closing the session.
    - Callback exception freezes that ConnID and emits failure once. It never
      retries automatically because the callback may have committed side effects.
    - The Registry/A coordinator owns session close and closed-event draining.
    """

    def __init__(
        self,
        udp_service: UDPTransportService,
        on_data: ApplicationCallback,
        *,
        on_reliable_delivery_failed: FailureCallback | None = None,
        worker_count: int = 4,
        poll_interval_s: float = 0.01,
        max_callbacks_per_poll: int = 64,
    ) -> None:
        if not callable(on_data):
            raise TypeError("on_data must be callable")
        if on_reliable_delivery_failed is not None and not callable(
            on_reliable_delivery_failed
        ):
            raise TypeError("on_reliable_delivery_failed must be callable")
        if type(worker_count) is not int or not 1 <= worker_count <= 16:
            raise ValueError("worker_count must be 1..16")
        if (
            not isinstance(poll_interval_s, (int, float))
            or not 0 < poll_interval_s <= 0.1
        ):
            raise ValueError("poll_interval_s must be in (0, 0.1]")
        if (
            type(max_callbacks_per_poll) is not int
            or not 1 <= max_callbacks_per_poll <= 256
        ):
            raise ValueError("max_callbacks_per_poll must be 1..256")
        self.udp_service = udp_service
        self.on_data = on_data
        self.on_reliable_delivery_failed = on_reliable_delivery_failed
        self.worker_count = worker_count
        self.poll_interval_s = float(poll_interval_s)
        self.max_callbacks_per_poll = max_callbacks_per_poll
        self._state_lock = threading.Lock()
        self._pending: dict[int, _PendingDelivery] = {}
        self._stop = threading.Event()
        self._started = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        """Start a small, fixed worker pool; call outside any transport lock."""
        with self._state_lock:
            if self._started or self._stop.is_set():
                raise RuntimeError("dispatcher already started or stopped")
            self._started = True
        for index in range(self.worker_count):
            thread = threading.Thread(
                target=self._run_worker,
                args=(index,),
                name=f"reliable-delivery-{index}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def stop(self, *, join_timeout_s: float = 2.0) -> None:
        """Signal shutdown and drop pending delivery state; idempotent."""
        self._stop.set()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=join_timeout_s)
        with self._state_lock:
            self._pending.clear()

    def pending_status(self, conn_id: int) -> str | None:
        """Inspection for coordinator/tests; no Registry or transport access."""
        with self._state_lock:
            pending = self._pending.get(conn_id)
            return pending.status if pending is not None else None

    def _notify(self, conn_id: int, delivery: StreamDelivery, code: str) -> None:
        """Notify A with the *original* delivery coordinates, outside all locks.

        Errors in A's notification hook cannot turn a failed application
        callback into an automatic retry. Log them for observability.
        """
        if self.on_reliable_delivery_failed is None:
            logging.getLogger(__name__).error(
                "Reliable delivery failed without a coordinator hook: "
                "conn_id=%016x stream_id=%d offset=%d code=%s",
                conn_id,
                delivery.stream_id,
                delivery.offset,
                code,
            )
            return
        try:
            self.on_reliable_delivery_failed(
                conn_id,
                delivery.stream_id,
                delivery.offset,
                code,
            )
        except Exception:
            logging.getLogger(__name__).exception(
                "A delivery-failure hook raised: conn_id=%016x stream_id=%d offset=%d code=%s",
                conn_id,
                delivery.stream_id,
                delivery.offset,
                code,
            )

    def _mark_failed(self, conn_id: int, code: str, status: str) -> None:
        with self._state_lock:
            pending = self._pending.get(conn_id)
            if pending is None or pending.status != "active":
                return
            pending.status = status
            delivery = pending.delivery
        # This must stay outside _state_lock, transport and Registry locks.
        self._notify(conn_id, delivery, code)

    def _drop(self, conn_id: int) -> None:
        with self._state_lock:
            self._pending.pop(conn_id, None)

    def _drive_one(self, conn_id: int) -> bool:
        """Process at most one delivery, synchronously on its assigned worker.

        Returns True when an active delivery was attempted (for work budgeting).
        Never invokes application code while holding _state_lock or a UDP lock.
        """
        if self._stop.is_set() or not self.udp_service.is_delivery_connection_active(
            conn_id
        ):
            self._drop(conn_id)
            return False
        with self._state_lock:
            pending = self._pending.get(conn_id)
            if pending is not None and pending.status != "active":
                return False
        if pending is None:
            delivery = self.udp_service.pop_reliable_delivery(conn_id)
            if delivery is None:
                return False
            with self._state_lock:
                pending = _PendingDelivery(delivery)
                self._pending[conn_id] = pending

        if self._stop.is_set() or not self.udp_service.is_delivery_connection_active(
            conn_id
        ):
            self._drop(conn_id)
            return False
        delivery = pending.delivery
        try:
            accepted = self.on_data(
                conn_id,
                delivery.stream_id,
                delivery.offset,
                delivery.data,
                delivery.fin,
            )
        except Exception:
            # No automatic retry: AUTH/Chat may have modified app state or
            # enqueued a reply BEFORE the exception was raised.
            logging.getLogger(__name__).exception(
                "Application callback raised conn_id=%016x stream_id=%d offset=%d",
                conn_id,
                delivery.stream_id,
                delivery.offset,
            )
            self._mark_failed(conn_id, APPLICATION_EXCEPTION, "failed")
            return True

        if accepted is not True:
            self._mark_failed(conn_id, APPLICATION_REJECTED, "rejected")
            return True

        # Both checks are needed: A may close a session INSIDE its callback.
        if self._stop.is_set() or not self.udp_service.is_delivery_connection_active(
            conn_id
        ):
            self._drop(conn_id)
            return True
        try:
            self.udp_service.confirm_consumed(
                conn_id,
                delivery.stream_id,
                delivery.offset + len(delivery.data),
            )
        except RuntimeError:
            # Usually a close race. If still live, this is a real mismatch.
            if (
                self._stop.is_set()
                or not self.udp_service.is_delivery_connection_active(conn_id)
            ):
                self._drop(conn_id)
            else:
                self._mark_failed(conn_id, CONSUMPTION_CONFIRM_FAILED, "failed")
            return True
        except Exception:
            self._mark_failed(conn_id, CONSUMPTION_CONFIRM_FAILED, "failed")
            return True
        self._drop(conn_id)
        return True

    def _run_worker(self, index: int) -> None:
        while not self._stop.is_set():
            try:
                ids = sorted(
                    conn_id
                    for conn_id in self.udp_service.connection_ids()
                    if conn_id % self.worker_count == index
                )
                # Coordinator has removed these ConnIDs; no need to retain
                # failed deliveries after B's transport state is gone.
                if index == 0:
                    live = self.udp_service.connection_ids()
                    with self._state_lock:
                        for closed_id in list(self._pending):
                            if closed_id not in live:
                                self._pending.pop(closed_id, None)
                attempted = 0
                while (
                    ids
                    and attempted < self.max_callbacks_per_poll
                    and not self._stop.is_set()
                ):
                    progressed = False
                    for conn_id in ids:
                        if (
                            attempted >= self.max_callbacks_per_poll
                            or self._stop.is_set()
                        ):
                            break
                        if self._drive_one(conn_id):
                            attempted += 1
                            progressed = True
                    if not progressed:
                        break
            except Exception:
                # Only unexpected dispatcher/runtime errors arrive here.
                # This worker remains alive; failure is observable through the
                # 4-argument hook when a pending ConnID exists in the affected shard.
                with self._state_lock:
                    affected = [
                        cid for cid in self._pending if cid % self.worker_count == index
                    ]
                for conn_id in affected:
                    self._mark_failed(conn_id, DISPATCHER_EXCEPTION, "failed")
            self._stop.wait(self.poll_interval_s)


def bind_application_bridge(
    server: CollaborationServer,
    *,
    on_reliable_delivery_failed: FailureCallback | None = None,
    worker_count: int = 4,
) -> ReliableDeliveryDispatcher:
    """Connect A's stream-0/1 sender hooks to B's reliable *enqueue* APIs.

    Call after CollaborationServer has created its UDPTransportService.
    Never use raw socket.sendto() or a TLS socket for AUTH/chat frames.
    Existing A-provided hooks are preserved instead of attached twice.
    """
    if server.auth_service is None:
        server.attach_reliable_control(
            lambda conn_id, frame: server.udp_service.queue_reliable_bytes(
                conn_id, 0, frame
            )
        )
    if server.chat_service is None:
        server.attach_reliable_chat(
            lambda conn_id, frame: server.udp_service.queue_reliable_bytes(
                conn_id, 1, frame
            )
        )
    return ReliableDeliveryDispatcher(
        server.udp_service,
        server.on_reliable_stream_data,
        on_reliable_delivery_failed=on_reliable_delivery_failed,
        worker_count=worker_count,
    )
