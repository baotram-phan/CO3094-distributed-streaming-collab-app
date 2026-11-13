"""B3.3.1: WINDOW_UPDATE flow-credit orchestration, no sockets/callbacks.

Per-ConnID, single-threaded controller. The caller serializes its operations
with StreamManager/SentPacketTracker and invokes application callbacks only
outside transport locks. The packet-number allocator is the A1.5 state.

Wire format remains WINDOW_UPDATE: stream_id:u32 | max_offset:u64 (12 B).
This module does not implement application consumption, CUBIC or UDP I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from common.constants import (
    AES_256_KEY_SIZE, FILE_STREAM_MIN_ID, GCM_TAG_SIZE,
    HEADER_SIZE, WINDOW_UPDATE,
)
from common.streams import StreamManager
from common.transport import AckReceipt, LostPacket, SentPacketTracker, _clock_ms
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    WINDOW_UPDATE_STRUCT, decode_window_update_body,
    encode_packet, encode_window_update_body,
)

_UINT64_MAX = (1 << 64) - 1
_DATAGRAM_SIZE = HEADER_SIZE + GCM_TAG_SIZE + WINDOW_UPDATE_STRUCT.size


@dataclass(frozen=True, slots=True)
class PreparedWindowUpdate:
    """One allocated/encrypted WU datagram: commit only on successful sendto."""

    packet_num: int
    stream_id: int
    max_offset: int
    datagram: bytes
    attempt_number: int


@dataclass(slots=True)
class _WindowAttempt:
    stream_id: int
    max_offset: int
    status: str  # "prepared", "sent", "lost"


class WindowUpdateFlow:
    """Track peer credit, downstream consumption and reliable WU advertisements.

    `streams` is one StreamManager (one ConnID). The initial 64KiB credit for
    stream 0 and 1 is a protocol assumption, not an on-wire WINDOW_UPDATE.
    File stream (>=2) starts with credit=0; call authorize_file_receive() ONLY
    after the application accepted FILE_START and opened the stream in B2.

    Credit increases only after downstream confirms contiguous consumption via
    note_consumed(); a StreamDelivery being returned does NOT automatically
    grant credit. A's worker/callback acceptance semantics must be agreed on.

    ACK/loss calls require authenticated, endpoint-bound, replay-checked ACK.
    No socket, Registry, worker callbacks, CUBIC or timeout loop is here.
    All methods must be serialized per ConnID, including prepare/commit/abort.
    """

    def __init__(
        self, streams: StreamManager, *, max_attempt_history: int = 256,
        max_retransmissions: int = 8,
    ) -> None:
        if not isinstance(streams, StreamManager):
            raise TypeError("streams must be StreamManager")
        if type(max_attempt_history) is not int or max_attempt_history < 1:
            raise ValueError("max_attempt_history must be positive int")
        if type(max_retransmissions) is not int or max_retransmissions < 1:
            raise ValueError("max_retransmissions must be positive int")
        self.streams = streams
        self.conn_id = streams.conn_id
        self.max_attempt_history = max_attempt_history
        self.max_retransmissions = max_retransmissions
        self._desired: dict[int, int] = {}
        self._acked: dict[int, int] = {}
        self._consumed: dict[int, int] = {}
        self._attempts: dict[int, _WindowAttempt] = {}
        self._prepared: PreparedWindowUpdate | None = None

    @property
    def tracked_attempts(self) -> int:
        return len(self._attempts)

    @property
    def prepared(self) -> PreparedWindowUpdate | None:
        return self._prepared

    @property
    def pending_stream_ids(self) -> tuple[int, ...]:
        """Streams whose newest credit is not yet ACKed (maybe in flight)."""
        return tuple(sorted(
            sid for sid, desired in self._desired.items()
            if desired > self._acked.get(sid, 0)
        ))

    def receive_peer_update(self, body: bytes) -> bool:
        """Decode valid WU; accept increasing credit, ignore stale/duplicate.

        Known stream is required; file stream must have passed FILE_START.
        Does not ACK the UDP packet (ACK tracker does that after acceptance).
        """
        stream_id, max_offset = decode_window_update_body(body)
        state = self.streams._send_state(stream_id)  # internal B2 interface
        if max_offset <= state.advertised_max_offset:
            return False
        return state.update_credit(max_offset)

    def authorize_file_receive(self, stream_id: int) -> bool:
        """Application-approved FILE_START: advertise initial file capacity.

        Caller must first call StreamManager.open_file_stream(stream_id) after
        authorization. Never call speculatively for unknown file stream IDs.
        """
        if type(stream_id) is not int or stream_id < FILE_STREAM_MIN_ID:
            raise ValueError("initial file credit requires stream_id >= 2")
        state = self.streams._receive_state(stream_id)
        credit = state.buffer_limit_bytes
        changed = self.streams.grant_receive_credit(stream_id, credit)
        if changed:
            self._record_desired(stream_id, credit)
        return changed

    def note_consumed(self, stream_id: int, consumed_offset: int) -> bool:
        """Advance credit ONLY after downstream consumed/stored bytes through offset.

        The caller must not call this on worker enqueue alone if that enqueue
        does not transfer ownership of the delivered bytes. `consumed_offset`
        is the contiguous exclusive end actually processed by downstream.
        """
        state = self.streams._receive_state(stream_id)
        if type(consumed_offset) is not int or not 0 <= consumed_offset <= _UINT64_MAX:
            raise ValueError("consumed_offset must be uint64")
        prior = self._consumed.get(stream_id, 0)
        if consumed_offset < prior:
            raise ValueError("downstream consumption cannot move backwards")
        if consumed_offset > state.delivered_offset:
            raise ValueError("cannot grant credit for bytes not delivered by B2")
        if consumed_offset == prior:
            return False
        # File credit is never implicitly unlocked before application-accepted
        # FILE_START; initial credit must be authorized explicitly.
        if stream_id >= FILE_STREAM_MIN_ID and state.advertised_max_offset == 0:
            raise ValueError("file receive credit not authorized by FILE_START")
        target = min(_UINT64_MAX, consumed_offset + state.buffer_limit_bytes)
        changed = self.streams.grant_receive_credit(stream_id, target)
        self._consumed[stream_id] = consumed_offset
        if changed:
            self._record_desired(stream_id, target)
        return changed

    def _record_desired(self, stream_id: int, max_offset: int) -> None:
        old = self._desired.get(stream_id, 0)
        if max_offset > old:
            self._desired[stream_id] = max_offset

    def _sendable(self) -> tuple[int, int] | None:
        for stream_id in self.pending_stream_ids:
            target = self._desired[stream_id]
            # A sent attempt for the same current target is still outstanding.
            if any(
                a.stream_id == stream_id and a.max_offset == target
                and a.status in ("prepared", "sent")
                for a in self._attempts.values()
            ):
                continue
            return stream_id, target
        return None

    def prepare_send(
        self, connection: TransportConnectionState,
        sent: SentPacketTracker, key: bytes, now_ms: float | int,
    ) -> PreparedWindowUpdate | None:
        """Reserve a fresh PN and track WU before handing ciphertext to socket.

        None when no update is sendable or tracking/history is at capacity.
        Never pop a credit advertisement on merely preparing a UDP datagram.
        """
        if not isinstance(connection, TransportConnectionState) or connection.conn_id != self.conn_id:
            raise ValueError("connection state does not match ConnID")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        if not isinstance(key, bytes) or len(key) != AES_256_KEY_SIZE:
            raise ValueError("outbound AES-256 key must contain 32 bytes")
        now = _clock_ms(now_ms)
        if self._prepared is not None:
            raise RuntimeError("previous WINDOW_UPDATE send is not committed/aborted")
        next_update = self._sendable()
        if next_update is None:
            return None
        if len(self._attempts) >= self.max_attempt_history:
            return None  # bounded history; do not lose desired credit
        if not sent.can_track(_DATAGRAM_SIZE):
            return None
        stream_id, max_offset = next_update
        prior_attempts = sum(
            a.stream_id == stream_id and a.max_offset == max_offset
            and a.status in ("sent", "lost")
            for a in self._attempts.values()
        )
        if prior_attempts > self.max_retransmissions:
            raise TimeoutError("WINDOW_UPDATE retry limit exceeded")
        body = encode_window_update_body(stream_id, max_offset)
        pkt_num = connection.allocate_packet_number()  # NEVER reused
        datagram = encode_packet(key, WINDOW_UPDATE, self.conn_id, pkt_num, body)
        sent.track_sent(pkt_num, WINDOW_UPDATE, len(datagram), now)
        plan = PreparedWindowUpdate(pkt_num, stream_id, max_offset, datagram, prior_attempts + 1)
        self._attempts[pkt_num] = _WindowAttempt(stream_id, max_offset, "prepared")
        self._prepared = plan
        return plan

    def commit_sent(self, plan: PreparedWindowUpdate) -> None:
        """Call after socket.sendto accepted the entire datagram."""
        if plan is not self._prepared:
            raise ValueError("plan is not the current prepared WINDOW_UPDATE")
        self._attempts[plan.packet_num].status = "sent"
        self._prepared = None

    def abort_send(self, plan: PreparedWindowUpdate, sent: SentPacketTracker) -> None:
        """Definite send failure: keep credit pending; burn allocated packet PN."""
        if plan is not self._prepared:
            raise ValueError("plan is not the current prepared WINDOW_UPDATE")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        sent.cancel_sent(plan.packet_num)
        del self._attempts[plan.packet_num]
        self._prepared = None

    def note_loss(self, lost: LostPacket, sent: SentPacketTracker) -> bool:
        """After packet loss detection, schedule latest credit with new PN.

        Keep the old committed packet-number history: an ACK for that old WU
        may still arrive and cancel a needless retry.
        """
        if not isinstance(lost, LostPacket):
            raise TypeError("lost must be LostPacket")
        if lost.packet.packet_type != WINDOW_UPDATE:
            return False  # DATA is DataRetransmissionQueue's responsibility
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        attempt = self._attempts.get(lost.packet.packet_num)
        if attempt is None or attempt.status != "sent":
            return False
        tracked = sent.get(lost.packet.packet_num)
        if tracked is None:
            return False
        if tracked != lost.packet:
            raise ValueError("loss report does not match tracked WINDOW_UPDATE")
        # No enqueue can fail: latest desired credit already lives in _desired.
        sent.cancel_sent(lost.packet.packet_num)
        attempt.status = "lost"
        return True

    def on_ack(self, receipt: AckReceipt, sent: SentPacketTracker) -> tuple[tuple[int, int], ...]:
        """Settle WU if ANY committed attempt (including retired loss) got ACK.

        Caller first performs sent.process_ack(ack_body) on an authenticated
        ACK. Duplicates, old smaller credits, and late ACKs are idempotent.
        Returns newly ACKed (stream_id, max_offset) progress.
        """
        if not isinstance(receipt, AckReceipt):
            raise TypeError("receipt must be AckReceipt")
        if not isinstance(sent, SentPacketTracker):
            raise TypeError("sent must be SentPacketTracker")
        newly: dict[int, int] = {}
        for pn, attempt in self._attempts.items():
            if attempt.status not in ("sent", "lost"):
                continue
            if any(lo <= pn <= hi for lo, hi in receipt.ranges):
                newly[attempt.stream_id] = max(
                    newly.get(attempt.stream_id, 0), attempt.max_offset
                )
        progress: list[tuple[int, int]] = []
        for sid, credit in newly.items():
            previous = self._acked.get(sid, 0)
            if credit > previous:
                self._acked[sid] = credit
                progress.append((sid, credit))
            # ACK newer credit subsumes all older WU for the same stream.
            for pn, attempt in list(self._attempts.items()):
                if attempt.stream_id == sid and attempt.max_offset <= self._acked.get(sid, 0):
                    if attempt.status == "sent":
                        sent.cancel_sent(pn)
                    del self._attempts[pn]
        return tuple(sorted(progress))