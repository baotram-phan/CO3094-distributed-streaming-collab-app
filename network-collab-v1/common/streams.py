"""B2.1: bounded, independent receive-side reassembly for a logical stream.

Protocol §5–§6, version v1.0-proposed. This module does not send ACKs,
manage socket state, parse JSON messages, or advance credit automatically.

The B2.1 API is an internal proposal until A–B approve the transport ABI.
"""

from __future__ import annotations

from dataclasses import dataclass

from common.constants import (
    CONTROL_CHAT_INITIAL_WINDOW,
    FILE_INITIAL_WINDOW,
    FILE_STREAM_MIN_ID,
    MAX_DATA_PER_PACKET,
)

_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class StreamDelivery:
    """One newly deliverable contiguous run; FIN is reported exactly once."""

    stream_id: int
    offset: int
    data: bytes
    fin: bool = False


class StreamReceiveState:
    """Receive DATA frames for ONE stream and ONE direction.

    `receive()` returns a StreamDelivery only when a new contiguous run is
    available (or the final offset becomes contiguous). For the same conn_id,
    instantiate separate objects for each (stream_id, direction).

    `advertised_max_offset` is absolute and NEVER increased automatically.
    Call `grant_credit()` only AFTER the application consumes / durably stores
    delivered bytes. A file stream starts with zero credit until FILE_START.

    This class is not thread-safe. The transport serializes events per stream.
    """

    def __init__(
        self,
        stream_id: int,
        *,
        buffer_limit_bytes: int | None = None,
        initial_max_offset: int | None = None,
    ) -> None:
        if type(stream_id) is not int or not 0 <= stream_id <= _UINT32_MAX:
            raise ValueError("stream_id must be uint32")
        is_file = stream_id >= FILE_STREAM_MIN_ID

        if buffer_limit_bytes is None:
            buffer_limit_bytes = (
                FILE_INITIAL_WINDOW if is_file else CONTROL_CHAT_INITIAL_WINDOW
            )
        if type(buffer_limit_bytes) is not int or not 1 <= buffer_limit_bytes <= _UINT64_MAX:
            raise ValueError("buffer_limit_bytes must be a positive uint64")

        if initial_max_offset is None:
            initial_max_offset = 0 if is_file else min(buffer_limit_bytes, CONTROL_CHAT_INITIAL_WINDOW)
        self._check_u64(initial_max_offset, "initial_max_offset")
        if initial_max_offset > buffer_limit_bytes:
            raise ValueError("initial credit exceeds receive buffer limit")

        self.stream_id = stream_id
        self.buffer_limit_bytes = buffer_limit_bytes
        self.advertised_max_offset = initial_max_offset
        self.delivered_offset = 0
        self.final_offset: int | None = None
        self._fin_delivered = False
        # Sorted disjoint, non-adjacent chunks (offset, data); all offsets >= delivered_offset.
        self._pending: list[tuple[int, bytes]] = []

    @staticmethod
    def _check_u64(value: int, field: str) -> None:
        if type(value) is not int or not 0 <= value <= _UINT64_MAX:
            raise ValueError(f"{field} must be uint64")

    @property
    def buffered_bytes(self) -> int:
        return sum(len(chunk) for _, chunk in self._pending)

    @property
    def finished(self) -> bool:
        return self._fin_delivered

    def grant_credit(self, new_max_offset: int) -> bool:
        """Raise the absolute receive limit after downstream consumption.

        Returns True if the limit advanced, False for a duplicate update.
        The caller is responsible for sending the WINDOW_UPDATE packet later.
        """
        self._check_u64(new_max_offset, "new_max_offset")
        if new_max_offset < self.advertised_max_offset:
            raise ValueError("receive credit must never decrease")
        if new_max_offset > self.delivered_offset + self.buffer_limit_bytes:
            raise ValueError("credit exceeds bounded receive capacity")
        changed = new_max_offset > self.advertised_max_offset
        self.advertised_max_offset = new_max_offset
        return changed

    @staticmethod
    def _merge_chunks(chunks: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
        """Coalesce adjacent/overlapping chunks; reject conflicting overlap."""
        merged: list[tuple[int, bytes]] = []
        for start, chunk in sorted(chunks, key=lambda item: item[0]):
            if not chunk:
                continue
            if not merged:
                merged.append((start, chunk))
                continue
            prev_start, prev = merged[-1]
            prev_end = prev_start + len(prev)
            if start > prev_end:
                merged.append((start, chunk))
                continue

            overlap = prev_end - start
            if overlap >= len(chunk):
                existing = prev[start - prev_start : start - prev_start + len(chunk)]
                if existing != chunk:
                    raise ValueError("overlapping DATA contains conflicting bytes")
                continue
            if overlap and prev[-overlap:] != chunk[:overlap]:
                raise ValueError("overlapping DATA contains conflicting bytes")
            merged[-1] = (prev_start, prev + chunk[overlap:])
        return merged

    def receive(self, offset: int, data: bytes, fin: bool = False) -> StreamDelivery | None:
        """Validate and reassemble one decoded DATA frame.

        The frame is ALREADY authenticated/decrypted and decoded by udp_packet.
        Any ValueError/TypeError leaves receive state unchanged.
        """
        self._check_u64(offset, "offset")
        if not isinstance(data, bytes):
            raise TypeError("DATA payload must be bytes")
        if len(data) > MAX_DATA_PER_PACKET:
            raise ValueError("DATA payload exceeds MAX_DATA_PER_PACKET")
        if type(fin) is not bool:
            raise ValueError("fin must be bool")
        end = offset + len(data)
        if end > _UINT64_MAX:
            raise ValueError("DATA end offset overflows uint64")
        if end > self.advertised_max_offset:
            raise ValueError("DATA exceeds advertised per-stream receive credit")
        if self.final_offset is not None:
            if end > self.final_offset:
                raise ValueError("DATA extends beyond known FIN offset")
            if fin and end != self.final_offset:
                raise ValueError("conflicting FIN final offset")

        # Check any NEW FIN against all existing state BEFORE committing it.
        if fin and self.final_offset is None:
            if end < self.delivered_offset:
                raise ValueError("FIN is before already delivered DATA")
            if any(start + len(chunk) > end for start, chunk in self._pending):
                raise ValueError("FIN is before buffered DATA")

        # DATA below delivered_offset has already been handed off exactly once.
        if end <= self.delivered_offset:
            fresh_start, fresh_data = self.delivered_offset, b""
        else:
            fresh_start = max(offset, self.delivered_offset)
            fresh_data = data[fresh_start - offset:]

        # Form proposed buffer first: error paths do not alter current state.
        chunks = list(self._pending)
        if fresh_data:
            chunks.append((fresh_start, fresh_data))
        merged = self._merge_chunks(chunks)
        if sum(len(chunk) for _, chunk in merged) > self.buffer_limit_bytes:
            raise ValueError("out-of-order buffer capacity exceeded")

        new_final = end if fin and self.final_offset is None else self.final_offset
        old_delivered = self.delivered_offset
        delivered_parts: list[bytes] = []
        while merged and merged[0][0] == self.delivered_offset:
            start, chunk = merged.pop(0)
            delivered_parts.append(chunk)
            self.delivered_offset = start + len(chunk)

        fin_now = bool(new_final is not None and self.delivered_offset == new_final and not self._fin_delivered)
        self._pending = merged
        self.final_offset = new_final
        if fin_now:
            self._fin_delivered = True
        if delivered_parts or fin_now:
            return StreamDelivery(self.stream_id, old_delivered, b"".join(delivered_parts), fin_now)
        return None


@dataclass(frozen=True, slots=True)
class StreamSendFrame:
    """One new DATA frame to be encoded; packet number is assigned by transport.

    Once emitted, B3 owns ACK/retransmission tracking. A retransmission MUST
    reuse (stream_id, offset, data, fin) with a NEW UDP packet number.
    """

    stream_id: int
    offset: int
    data: bytes
    fin: bool = False

    @property
    def flags(self) -> int:
        return 1 if self.fin else 0


class StreamSendState:
    """Bounded, one-direction DATA producer for one logical stream.

    `queue()` buffers not-yet-emitted bytes, without creating UDP packets.
    `next_frame()` removes up to 1024 bytes subject to the peer's absolute
    per-stream credit, advancing the unique stream offset exactly once.

    IMPORTANT: emitted frames are NOT necessarily received or ACKed. They must
    be retained by the reliable transport's in-flight tracking until ACKed.
    This class does not track cwnd, bytes_in_flight, packet numbers, sockets,
    or retransmissions. The API remains internal until A/B sign-off.

    This class is not thread-safe; serialize access per logical stream.
    """

    def __init__(
        self,
        stream_id: int,
        *,
        buffer_limit_bytes: int | None = None,
        initial_max_offset: int | None = None,
    ) -> None:
        if type(stream_id) is not int or not 0 <= stream_id <= _UINT32_MAX:
            raise ValueError("stream_id must be uint32")
        is_file = stream_id >= FILE_STREAM_MIN_ID
        if buffer_limit_bytes is None:
            buffer_limit_bytes = FILE_INITIAL_WINDOW if is_file else CONTROL_CHAT_INITIAL_WINDOW
        if type(buffer_limit_bytes) is not int or not 1 <= buffer_limit_bytes <= _UINT64_MAX:
            raise ValueError("buffer_limit_bytes must be positive uint64")
        if initial_max_offset is None:
            initial_max_offset = 0 if is_file else CONTROL_CHAT_INITIAL_WINDOW
        StreamReceiveState._check_u64(initial_max_offset, "initial_max_offset")

        self.stream_id = stream_id
        self.buffer_limit_bytes = buffer_limit_bytes
        self.advertised_max_offset = initial_max_offset
        self.next_offset = 0
        self._pending = bytearray()
        self._fin_queued = False
        self._fin_emitted = False

    @property
    def queued_bytes(self) -> int:
        """Only unsent bytes; sent/unACKed bytes belong to B3 tracking."""
        return len(self._pending)

    @property
    def fin_queued(self) -> bool:
        return self._fin_queued

    @property
    def finished_sending(self) -> bool:
        """FIN emitted, NOT yet confirmed by the remote peer."""
        return self._fin_emitted

    def queue(self, data: bytes, *, fin: bool = False) -> None:
        """Queue bytes; setting fin declares no further bytes may be queued.

        Validates fully before committing. Empty `data` with fin=True emits a
        FIN-only frame once previous queued data has drained.
        """
        if not isinstance(data, bytes):
            raise TypeError("stream send payload must be bytes")
        if type(fin) is not bool:
            raise ValueError("fin must be bool")
        if self._fin_queued:
            raise ValueError("cannot queue data after FIN")
        if len(self._pending) + len(data) > self.buffer_limit_bytes:
            raise ValueError("stream send queue capacity exceeded")
        if self.next_offset + len(self._pending) + len(data) > _UINT64_MAX:
            raise ValueError("stream offset overflows uint64")
        self._pending.extend(data)
        if fin:
            self._fin_queued = True

    def update_credit(self, new_max_offset: int) -> bool:
        """Accept peer WINDOW_UPDATE absolute max_offset (monotonic).

        A repeated value is harmless. A value below the current credit is
        rejected even when more bytes have not been emitted yet.
        """
        StreamReceiveState._check_u64(new_max_offset, "new_max_offset")
        if new_max_offset < self.advertised_max_offset:
            raise ValueError("remote stream credit must not decrease")
        changed = new_max_offset > self.advertised_max_offset
        self.advertised_max_offset = new_max_offset
        return changed

    def next_frame(self, *, max_payload: int = MAX_DATA_PER_PACKET) -> StreamSendFrame | None:
        """Produce one NEW DATA frame within credit; never creates UDP packet.

        Returns None when queue empty, credit exhausted, or FIN already sent.
        No portion is emitted twice. B3 must handle retransmits independently.
        """
        if type(max_payload) is not int or not 1 <= max_payload <= MAX_DATA_PER_PACKET:
            raise ValueError("max_payload must be in 1..MAX_DATA_PER_PACKET")
        if self._fin_emitted:
            return None

        available_credit = max(0, self.advertised_max_offset - self.next_offset)
        size = min(len(self._pending), max_payload, available_credit)
        if size:
            offset = self.next_offset
            data = bytes(self._pending[:size])
            fin_now = self._fin_queued and size == len(self._pending)
            del self._pending[:size]
            self.next_offset += size
            if fin_now:
                self._fin_emitted = True
            return StreamSendFrame(self.stream_id, offset, data, fin_now)

        # FIN-only frame needs no new byte credit, but cannot exceed the peer's
        # absolute credit and cannot skip any data still in the queue.
        if self._fin_queued and not self._pending and self.next_offset <= self.advertised_max_offset:
            self._fin_emitted = True
            return StreamSendFrame(self.stream_id, self.next_offset, b"", True)
        return None


class StreamManager:
    """Bounded, per-connection collection of independent logical streams.

    This is an INTERNAL B2.3 interface, not yet the agreed A/B transport ABI.
    One instance belongs to exactly one UDP connection (ConnID); B3 must
    serialize access to it. Control (0) and chat (1) exist at creation; file
    streams (>=2) are opened explicitly by the FILE_START integration path.

    Each stream has separate send and receive offset spaces. No UDP packet
    numbers, ACK/retransmit tracker, registry access, callbacks, I/O, socket,
    or CUBIC logic lives here. Returning a StreamDelivery does NOT mean that
    the application worker accepted it. B3 must retain/hand off deliveries
    safely and call A's callbacks outside transport locks.

    Limits below are provisional *local resource policy*, NOT negotiated or
    defined as wire-format values in the proposed protocol. In-flight DATA
    metadata and outstanding app callbacks must be bounded separately by B3.
    """

    def __init__(
        self,
        conn_id: int,
        *,
        max_file_streams: int = 16,
        max_buffered_bytes: int = 2 * 1024 * 1024,
        max_file_stream_ids_total: int = 1024,
    ) -> None:
        StreamReceiveState._check_u64(conn_id, "conn_id")
        if type(max_file_streams) is not int or not 0 <= max_file_streams <= _UINT32_MAX - 1:
            raise ValueError("max_file_streams must be nonnegative uint32")
        if type(max_buffered_bytes) is not int or not 1 <= max_buffered_bytes <= _UINT64_MAX:
            raise ValueError("max_buffered_bytes must be positive uint64")
        if type(max_file_stream_ids_total) is not int or not 1 <= max_file_stream_ids_total <= _UINT32_MAX - 1:
            raise ValueError("max_file_stream_ids_total must be positive uint32")

        self.conn_id = conn_id
        self.max_file_streams = max_file_streams
        self.max_buffered_bytes = max_buffered_bytes
        self.max_file_stream_ids_total = max_file_stream_ids_total
        # Tombstone stream IDs for this ConnID: delayed authenticated DATA from
        # a cancelled transfer must NEVER be accepted as a new transfer.
        # The total tombstone set is bounded by max_file_stream_ids_total.
        self._used_file_stream_ids: set[int] = set()
        self._send: dict[int, StreamSendState] = {
            0: StreamSendState(0),
            1: StreamSendState(1),
        }
        self._receive: dict[int, StreamReceiveState] = {
            0: StreamReceiveState(0),
            1: StreamReceiveState(1),
        }

    @staticmethod
    def _check_stream_id(stream_id: int) -> None:
        if type(stream_id) is not int or not 0 <= stream_id <= _UINT32_MAX:
            raise ValueError("stream_id must be uint32")

    @property
    def stream_ids(self) -> tuple[int, ...]:
        """Stable ascending snapshot of streams open within this connection."""
        return tuple(sorted(self._send))

    @property
    def file_stream_count(self) -> int:
        return len(self._send) - 2

    @property
    def queued_send_bytes(self) -> int:
        """Only DATA not yet emitted; unACKed frames are B3's responsibility."""
        return sum(state.queued_bytes for state in self._send.values())

    @property
    def buffered_receive_bytes(self) -> int:
        """Only out-of-order buffered DATA; delivered bytes belong to B3/A."""
        return sum(state.buffered_bytes for state in self._receive.values())

    @property
    def buffered_bytes(self) -> int:
        """Combined, currently retained DATA bytes in B2 only."""
        return self.queued_send_bytes + self.buffered_receive_bytes

    def _send_state(self, stream_id: int) -> StreamSendState:
        self._check_stream_id(stream_id)
        try:
            return self._send[stream_id]
        except KeyError as exc:
            raise ValueError("stream is not open; FILE_START required for file streams") from exc

    def _receive_state(self, stream_id: int) -> StreamReceiveState:
        self._check_stream_id(stream_id)
        try:
            return self._receive[stream_id]
        except KeyError as exc:
            raise ValueError("stream is not open; FILE_START required for file streams") from exc

    def open_file_stream(self, stream_id: int) -> bool:
        """Register one file stream, still with ZERO initial file credit.

        Call only after application authorizes FILE_START. Credit must then be
        granted explicitly, and B3 emits WINDOW_UPDATE on the wire.
        Returns False for an already-open file stream without resetting state.
        """
        self._check_stream_id(stream_id)
        if stream_id < FILE_STREAM_MIN_ID:
            raise ValueError("file stream_id must be >= FILE_STREAM_MIN_ID")
        if stream_id in self._send:
            return False
        if stream_id in self._used_file_stream_ids:
            raise ValueError("file stream_id cannot be reused within a ConnID")
        if self.file_stream_count >= self.max_file_streams:
            raise ValueError("too many open file streams for this connection")
        if len(self._used_file_stream_ids) >= self.max_file_stream_ids_total:
            raise ValueError("total file stream ID limit reached for this connection")
        self._send[stream_id] = StreamSendState(stream_id)
        self._receive[stream_id] = StreamReceiveState(stream_id)
        self._used_file_stream_ids.add(stream_id)
        return True

    def discard_file_stream(self, stream_id: int) -> bool:
        """Destructively drop file stream state after cancellation/cleanup.

        B3 must first coordinate unACKed frames, the application callback
        queue, and file lifecycle. Never call this on control/chat streams.
        The ID stays tombstoned until the ConnID is disposed; it cannot be
        reused by a new transfer, even though the active slot is released.
        Does not touch the SessionRegistry or transport keys.
        """
        self._check_stream_id(stream_id)
        if stream_id < FILE_STREAM_MIN_ID:
            raise ValueError("cannot discard control or chat stream")
        if stream_id not in self._send:
            return False
        del self._send[stream_id]
        del self._receive[stream_id]
        return True

    def queue_bytes(self, stream_id: int, data: bytes, *, fin: bool = False) -> None:
        """Enqueue raw stream bytes, no JSON framing or UDP I/O.

        A's already-framed stream-0 AUTH/control bytes pass through unchanged.
        On overflow, no part of the new DATA or FIN is committed.
        """
        state = self._send_state(stream_id)
        if not isinstance(data, bytes):
            raise TypeError("stream send payload must be bytes")
        if self.buffered_bytes + len(data) > self.max_buffered_bytes:
            raise ValueError("connection-wide stream buffer capacity exceeded")
        state.queue(data, fin=fin)

    def next_send_frame(
        self,
        stream_id: int,
        *,
        max_payload: int = MAX_DATA_PER_PACKET,
    ) -> StreamSendFrame | None:
        """Pop one fresh DATA frame from a chosen stream; B3 retains it.

        The B3 scheduler chooses the stream, enforces congestion/window and
        retains the frame BEFORE any operation that could lose it.
        """
        return self._send_state(stream_id).next_frame(max_payload=max_payload)

    def update_send_credit(self, stream_id: int, new_max_offset: int) -> bool:
        """Apply a received WINDOW_UPDATE to the send-side stream credit."""
        return self._send_state(stream_id).update_credit(new_max_offset)

    def grant_receive_credit(self, stream_id: int, new_max_offset: int) -> bool:
        """Record higher credit after downstream progress (NO UDP packet sent).

        B3 must decide when to advertise this limit, including relay
        backpressure, and avoid granting credit before app consumption.
        """
        return self._receive_state(stream_id).grant_credit(new_max_offset)

    def receive_frame(
        self,
        stream_id: int,
        offset: int,
        data: bytes,
        *,
        fin: bool = False,
    ) -> StreamDelivery | None:
        """Reassemble one authenticated, decoded DATA frame, atomically.

        Invalid/overflow DATA is not committed. This method does not decrypt,
        check replay/endpoint, ACK packets or invoke A's callbacks.
        """
        state = self._receive_state(stream_id)
        # B2.1 receive() commits its own state on success. Save a cheap
        # snapshot so connection-wide capacity rejection is also atomic.
        prior_pending = state._pending.copy()
        prior_offset = state.delivered_offset
        prior_final_offset = state.final_offset
        prior_fin_delivered = state._fin_delivered
        delivery = state.receive(offset, data, fin=fin)
        if self.buffered_bytes > self.max_buffered_bytes:
            state._pending = prior_pending
            state.delivered_offset = prior_offset
            state.final_offset = prior_final_offset
            state._fin_delivered = prior_fin_delivered
            raise ValueError("connection-wide stream buffer capacity exceeded")
        return delivery