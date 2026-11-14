"""B3.3.2: bounded send scheduling and backpressure for ONE UDP ConnID.

No socket I/O, timers, Registry, callbacks, or CUBIC implementation.
The caller supplies the current connection-wide cwnd_bytes from A's CUBIC
(and must serialize ALL calls with StreamManager/SentPacketTracker/flows).

Commit a prepared datagram only AFTER sendto() accepts the entire datagram;
abort on a definite send failure. A burned packet number is NEVER reused.
This module is an internal B API pending A/B integration-contract approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from common.constants import (
    AES_256_KEY_SIZE,
    DATA,
    GCM_TAG_SIZE,
    HEADER_SIZE,
    MAX_DATA_PER_PACKET,
    WINDOW_UPDATE,
)
from common.streams import StreamManager, StreamSendFrame
from common.transport import (
    DataRetransmissionQueue,
    PreparedRetransmission,
    SentPacketTracker,
    _clock_ms,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import DATA_DATAGRAM_OVERHEAD, encode_data_body, encode_packet
from common.window_update_flow import PreparedWindowUpdate, WindowUpdateFlow

_DATA_OVERHEAD = DATA_DATAGRAM_OVERHEAD  # 51 B; common wire-size accounting
_WU_SIZE = HEADER_SIZE + GCM_TAG_SIZE + 12  # 48 B


@dataclass(frozen=True, slots=True)
class PreparedScheduledSend:
    """One reserved encrypted datagram; socket work belongs to the caller."""

    kind: Literal["new_data", "data_retry", "window_update"]
    packet_num: int
    datagram: bytes
    stream_id: int
    frame: StreamSendFrame | None = None
    delegate: PreparedRetransmission | PreparedWindowUpdate | None = None
    from_staged: bool = False


class ConnectionSendScheduler:
    """Safe handoff from B2 streams to B3 in-flight state, with bounded staging.

    Select WU first, then round-robin control/chat/retry/file slots.
    A blocked stream never consumes its queued DATA and does not block
    unrelated streams. ONE prepared datagram at a time maintains PN order.

    max_staged_frames/bytes cover DATA returned to the scheduler after a
    definite send failure. Their cap is separate from B2 buffers and B3
    in-flight tracking. Changes to cwnd are passed per prepare_next() call.
    """

    def __init__(
        self,
        streams: StreamManager,
        connection: TransportConnectionState,
        sent: SentPacketTracker,
        retries: DataRetransmissionQueue,
        flow: WindowUpdateFlow,
        *,
        max_staged_frames: int = 32,
        max_staged_bytes: int = 32 * 1024,
    ) -> None:
        if not isinstance(streams, StreamManager):
            raise TypeError("streams must be StreamManager")
        if not isinstance(connection, TransportConnectionState):
            raise TypeError("connection must be TransportConnectionState")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        if not isinstance(retries, DataRetransmissionQueue):
            raise TypeError("retries must be DataRetransmissionQueue")
        if not isinstance(flow, WindowUpdateFlow):
            raise TypeError("flow must be WindowUpdateFlow")
        if not (
            streams.conn_id == connection.conn_id == retries.conn_id == flow.conn_id
        ):
            raise ValueError("all components must refer to the same ConnID")
        if flow.streams is not streams:
            raise ValueError("WindowUpdateFlow must use the same StreamManager")
        if type(max_staged_frames) is not int or max_staged_frames < 1:
            raise ValueError("max_staged_frames must be positive int")
        if type(max_staged_bytes) is not int or max_staged_bytes < MAX_DATA_PER_PACKET:
            raise ValueError("max_staged_bytes must be at least one DATA chunk")
        self.streams = streams
        self.connection = connection
        self.sent = sent
        self.retries = retries
        self.flow = flow
        self.max_staged_frames = max_staged_frames
        self.max_staged_bytes = max_staged_bytes
        self._staged: dict[int, StreamSendFrame] = {}
        self._prepared: PreparedScheduledSend | None = None
        self._slot_cursor = 0
        self._file_cursor = 0

    @property
    def staged_bytes(self) -> int:
        return sum(len(frame.data) for frame in self._staged.values())

    @property
    def staged_count(self) -> int:
        return len(self._staged)

    @property
    def prepared(self) -> PreparedScheduledSend | None:
        return self._prepared

    @property
    def queued_total_bytes(self) -> int:
        """Known unsent/queued DATA in B2, failed-send staging, and retries.

        IN-FLIGHT datagrams are accounted separately as sent.bytes_in_flight;
        overlapping B3 retry metadata can reference the same DATA twice.
        This is diagnostic, not a single exact RAM-usage measurement.
        """
        return (
            self.streams.queued_send_bytes
            + self.staged_bytes
            + self.retries.queued_bytes
        )

    def _candidate_new(
        self, stream_id: int, allowance: int
    ) -> tuple[StreamSendFrame, int, bool] | None:
        """Preview one frame within cwnd, tracker and staging budgets."""
        if stream_id in self._staged:
            frame = self._staged[stream_id]
            if _DATA_OVERHEAD + len(frame.data) <= allowance:
                return frame, max(1, len(frame.data)), True
            return None

        if len(self._staged) >= self.max_staged_frames:
            return None
        free_staging = self.max_staged_bytes - self.staged_bytes
        if free_staging < 1:
            return None
        if allowance < _DATA_OVERHEAD:
            return None
        max_payload = max(
            1, min(MAX_DATA_PER_PACKET, free_staging, allowance - _DATA_OVERHEAD)
        )
        frame = self.streams.peek_send_frame(stream_id, max_payload=max_payload)
        if frame is None or _DATA_OVERHEAD + len(frame.data) > allowance:
            return None
        return frame, max_payload, False

    def _try_new(
        self, stream_id: int, key: bytes, now: float, headroom: int
    ) -> PreparedScheduledSend | None:
        tracker_room = self.sent.max_pending_bytes - self.sent.bytes_in_flight
        allowance = min(headroom, tracker_room)
        candidate = self._candidate_new(stream_id, allowance)
        if candidate is None:
            return None
        frame, max_payload, from_staged = candidate
        size = _DATA_OVERHEAD + len(frame.data)
        if not self.sent.can_track(size):
            return None

        body = encode_data_body(frame.stream_id, frame.offset, frame.flags, frame.data)
        pn = self.connection.allocate_packet_number()  # burn even on later failure
        datagram = encode_packet(key, DATA, self.connection.conn_id, pn, body)
        if len(datagram) != size:
            raise RuntimeError("unexpected DATA datagram size")
        self.sent.track_sent(pn, DATA, size, now, frame=frame)
        if not from_staged:
            try:
                popped = self.streams.next_send_frame(
                    stream_id, max_payload=max_payload
                )
                if popped != frame:
                    raise RuntimeError("send state changed between peek and pop")
            except Exception:
                self.sent.cancel_sent(pn)
                raise
        plan = PreparedScheduledSend(
            "new_data", pn, datagram, frame.stream_id, frame, None, from_staged
        )
        self._prepared = plan
        return plan

    def _try_retry(
        self, key: bytes, now: float, headroom: int
    ) -> PreparedScheduledSend | None:
        frame = self.retries.peek_queued_frame()
        if frame is None:
            return None
        size = _DATA_OVERHEAD + len(frame.data)
        if size > headroom or not self.sent.can_track(size):
            return None
        delegate = self.retries.prepare_next(self.connection, self.sent, key, now)
        if delegate is None:
            return None
        plan = PreparedScheduledSend(
            "data_retry",
            delegate.packet_num,
            delegate.datagram,
            delegate.frame.stream_id,
            delegate.frame,
            delegate,
        )
        self._prepared = plan
        return plan

    def _try_window(
        self, key: bytes, now: float, headroom: int
    ) -> PreparedScheduledSend | None:
        if headroom < _WU_SIZE or not self.sent.can_track(_WU_SIZE):
            return None
        delegate = self.flow.prepare_send(self.connection, self.sent, key, now)
        if delegate is None:
            return None
        plan = PreparedScheduledSend(
            "window_update",
            delegate.packet_num,
            delegate.datagram,
            delegate.stream_id,
            None,
            delegate,
        )
        self._prepared = plan
        return plan

    def prepare_next(
        self, key: bytes, *, now_ms: float | int, cwnd_bytes: int
    ) -> PreparedScheduledSend | None:
        """Reserve one send; cwnd comes from A and is NEVER assumed unlimited.

        Returns None when backpressured or idle. The stream is not popped
        until successful preflight + encryption + bounded sent tracking.
        Prepared send occupies bytes_in_flight until ACK or abort.
        """
        if not isinstance(key, bytes) or len(key) != AES_256_KEY_SIZE:
            raise ValueError("outbound AES-256 key must contain 32 bytes")
        now = _clock_ms(now_ms)
        if type(cwnd_bytes) is not int or cwnd_bytes < 0:
            raise ValueError(
                "cwnd_bytes must be a nonnegative integer from congestion control"
            )
        if self._prepared is not None:
            raise RuntimeError("previous send must be committed or aborted first")
        headroom = cwnd_bytes - self.sent.bytes_in_flight
        if headroom < min(_WU_SIZE, _DATA_OVERHEAD):
            return None

        # WINDOW_UPDATE is urgent control traffic, but cannot exceed cwnd.
        plan = self._try_window(key, now, headroom)
        if plan is not None:
            return plan

        # Four fair slots: control / chat / DATA retry / file. Skip blocked
        # slots instead of freezing all streams behind a large file packet.
        slots = ("control", "chat", "retry", "file")
        for step in range(len(slots)):
            idx = (self._slot_cursor + step) % len(slots)
            slot = slots[idx]
            if slot == "retry":
                plan = self._try_retry(key, now, headroom)
            elif slot == "control":
                plan = self._try_new(0, key, now, headroom)
            elif slot == "chat":
                plan = self._try_new(1, key, now, headroom)
            else:
                plan = None
                files = [sid for sid in self.streams.stream_ids if sid >= 2]
                if files:
                    for offset in range(len(files)):
                        candidate_index = (self._file_cursor + offset) % len(files)
                        plan = self._try_new(files[candidate_index], key, now, headroom)
                        if plan is not None:
                            self._file_cursor = (candidate_index + 1) % len(files)
                            break
            if plan is not None:
                self._slot_cursor = (idx + 1) % len(slots)
                return plan
        return None

    def commit_sent(self, plan: PreparedScheduledSend) -> None:
        """Commit only after the entire UDP datagram was accepted by socket."""
        if plan is not self._prepared:
            raise ValueError("plan is not the active prepared datagram")
        if plan.kind == "data_retry":
            assert isinstance(plan.delegate, PreparedRetransmission)
            self.retries.commit_sent(plan.delegate)
        elif plan.kind == "window_update":
            assert isinstance(plan.delegate, PreparedWindowUpdate)
            self.flow.commit_sent(plan.delegate)
        elif plan.kind == "new_data" and plan.from_staged:
            self._staged.pop(plan.stream_id)
        self._prepared = None

    def abort_send(self, plan: PreparedScheduledSend) -> None:
        """Definite socket send failure; keep DATA, burn allocated nonce."""
        if plan is not self._prepared:
            raise ValueError("plan is not the active prepared datagram")
        if plan.kind == "data_retry":
            assert isinstance(plan.delegate, PreparedRetransmission)
            self.retries.abort_send(plan.delegate, self.sent)
        elif plan.kind == "window_update":
            assert isinstance(plan.delegate, PreparedWindowUpdate)
            self.flow.abort_send(plan.delegate, self.sent)
        else:
            removed = self.sent.cancel_sent(plan.packet_num)
            if removed is None or removed.frame != plan.frame:
                raise RuntimeError("prepared DATA is missing from SentPacketTracker")
            if not plan.from_staged:
                assert plan.frame is not None
                self._staged[plan.stream_id] = plan.frame
        self._prepared = None
