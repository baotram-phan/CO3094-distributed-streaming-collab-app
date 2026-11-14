"""B5.1b: encrypted Reliable UDP reorder / duplicate / cross-stream HoL.

TEST ONLY. Do not change production code to make these tests pass.
Tests run without AUTH/UI or test users; deterministic by explicit packet order.
One case uses actual localhost UDP sockets; the others isolate transport state.
"""

from __future__ import annotations

import socket
import unittest
from typing import TypeVar

from common.constants import ACK, DATA, MAX_DATA_PER_PACKET, WINDOW_UPDATE
from common.reliable_receive import ReliableReceiveState, ReceiveResult
from common.send_scheduler import PreparedScheduledSend
from common.streams import StreamDelivery, StreamSendFrame
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    decode_data_body,
    decode_packet,
    encode_ack_body,
    encode_data_body,
    encode_packet,
    encode_window_update_body,
)

CONN_ID = 515101
DATA_KEY = bytes(range(32))
REVERSE_KEY = bytes(range(32, 64))
PEER = ("127.0.0.1", 45051)

_T = TypeVar("_T")


def require_not_none(value: _T | None) -> _T:
    """Fail the test if a transport API returned None; also narrow its type.

    unittest.TestCase.assertIsNotNone alone is not recognized as a type guard
    by Pylance, so accessing the returned object's fields generates warnings.
    """
    if value is None:
        raise AssertionError("Expected a non-None transport result")
    return value


def require_data_frame(plan: PreparedScheduledSend) -> StreamSendFrame:
    """A DATA send plan must contain its underlying stream frame."""
    return require_not_none(plan.frame)


class B51bReliableTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receiver = ReliableReceiveState(TransportConnectionState(CONN_ID))
        self.now_ms = 1000.0

    def data_packet(
        self, pn: int, sid: int, offset: int, payload: bytes, *, fin: bool = False
    ) -> bytes:
        return encode_packet(
            DATA_KEY,
            DATA,
            CONN_ID,
            pn,
            encode_data_body(sid, offset, int(fin), payload),
        )

    def accept(self, packet: bytes) -> ReceiveResult:
        self.now_ms += 1.0
        return require_not_none(
            self.receiver.accept(
                packet,
                key=DATA_KEY,
                endpoint=PEER,
                bound_endpoint=PEER,
                now_ms=self.now_ms,
            )
        )

    def take_all(self) -> list[StreamDelivery]:
        out: list[StreamDelivery] = []
        while (item := self.receiver.pop_delivery()) is not None:
            out.append(item)
        return out

    def test_01_reordered_three_chunks_with_fin_delivered_in_order_once(self) -> None:
        # Simulate UDP reordering: tail and middle arrive before stream offset 0.
        head = b"H" * 1024
        middle = b"M" * 1024
        tail = b"T" * 127
        a = self.accept(self.data_packet(7, 1, 2048, tail, fin=True))
        b = self.accept(self.data_packet(8, 1, 1024, middle))
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertEqual(self.take_all(), [])
        self.assertEqual(self.receiver.streams._receive_state(1).buffered_bytes, 1151)
        c = self.accept(self.data_packet(9, 1, 0, head))
        self.assertTrue(c.delivery_enqueued)
        delivered = self.take_all()
        self.assertEqual(len(delivered), 1)
        self.assertEqual((delivered[0].stream_id, delivered[0].offset), (1, 0))
        self.assertEqual(delivered[0].data, head + middle + tail)
        self.assertTrue(delivered[0].fin)
        self.assertEqual(self.receiver.streams._receive_state(1).buffered_bytes, 0)
        self.assertEqual(self.take_all(), [])

    def test_02_exact_replay_requests_ack_but_never_redelivers_or_recredits(
        self,
    ) -> None:
        packet = self.data_packet(20, 1, 0, b"chat-msg")
        first = self.accept(packet)
        self.assertTrue(first.delivery_enqueued)
        delivery = require_not_none(self.receiver.pop_delivery())
        self.assertIsNotNone(delivery)
        self.assertEqual(delivery.data, b"chat-msg")
        self.assertTrue(self.receiver.confirm_consumed(1, 8))
        self.assertEqual(self.receiver.flow._consumed[1], 8)
        snapshot = require_not_none(self.receiver.received.build_ack(self.now_ms + 10))
        self.assertIsNotNone(snapshot)
        self.receiver.received.mark_ack_sent(snapshot)
        self.assertFalse(self.receiver.received.ack_pending)
        again = self.accept(packet)
        self.assertTrue(again.duplicate)
        self.assertFalse(again.delivery_enqueued)
        self.assertTrue(self.receiver.received.ack_pending)
        self.assertEqual(self.take_all(), [])
        self.assertEqual(self.receiver.flow._consumed[1], 8)
        self.assertFalse(self.receiver.confirm_consumed(1, 8))

    def test_03_retransmission_new_packet_number_same_offset_delivered_once(
        self,
    ) -> None:
        original = self.data_packet(30, 1, 0, b"payload")
        retry = self.data_packet(31, 1, 0, b"payload")
        one = self.accept(original)
        two = self.accept(retry)
        self.assertTrue(one.delivery_enqueued)
        # New PN passes packet replay check, but not stream duplicate suppression.
        self.assertFalse(two.duplicate)
        self.assertFalse(two.delivery_enqueued)
        delivered = self.take_all()
        self.assertEqual([d.data for d in delivered], [b"payload"])
        self.assertEqual(self.receiver.streams._receive_state(1).delivered_offset, 7)
        self.assertEqual(self.take_all(), [])
        # Both authenticated packet numbers are ACK-able, not two app deliveries.
        self.assertTrue(self.receiver.received.ack_pending)
        ack = require_not_none(self.receiver.received.build_ack(self.now_ms + 5))
        self.assertIsNotNone(ack)
        self.assertTrue(any(start <= 30 <= end for start, end in ack.ranges))
        self.assertTrue(any(start <= 31 <= end for start, end in ack.ranges))

    def test_04_partial_overlap_reorder_deduplicates_matching_bytes(self) -> None:
        self.assertIsNotNone(self.accept(self.data_packet(40, 1, 4, b"EFGH")))
        self.assertEqual(self.take_all(), [])
        merged = self.accept(self.data_packet(41, 1, 0, b"ABCDEF"))
        self.assertTrue(merged.delivery_enqueued)
        first = self.take_all()
        self.assertEqual([(x.offset, x.data) for x in first], [(0, b"ABCDEFGH")])
        finish = self.accept(self.data_packet(42, 1, 8, b"IJ", fin=True))
        self.assertTrue(finish.delivery_enqueued)
        last = self.take_all()
        self.assertEqual([(x.offset, x.data, x.fin) for x in last], [(8, b"IJ", True)])
        # The retransmission of already delivered bytes must not create an event.
        self.assertFalse(
            self.accept(self.data_packet(43, 1, 4, b"EFGH")).delivery_enqueued
        )
        self.assertEqual(self.take_all(), [])

    def test_05_file_receive_gap_does_not_block_chat_stream(self) -> None:
        self.receiver.streams.open_file_stream(2)
        self.receiver.flow.authorize_file_receive(2)
        head = b"F" * 1024
        tail = b"Z" * 200
        # File stream has a gap: receiver buffers its tail and FIN.
        file_tail = self.accept(self.data_packet(50, 2, 1024, tail, fin=True))
        self.assertFalse(file_tail.delivery_enqueued)
        self.assertEqual(self.take_all(), [])
        # Chat stream 1 has its own offset: it must deliver despite file gap.
        chat = self.accept(self.data_packet(51, 1, 0, b"hello-chat"))
        self.assertTrue(chat.delivery_enqueued)
        delivered_chat = self.take_all()
        self.assertEqual(
            [(d.stream_id, d.offset, d.data) for d in delivered_chat],
            [(1, 0, b"hello-chat")],
        )
        self.assertFalse(delivered_chat[0].fin)
        # Recovery of file head releases buffered tail and FIN only for stream 2.
        file_head = self.accept(self.data_packet(52, 2, 0, head))
        self.assertTrue(file_head.delivery_enqueued)
        file_data = self.take_all()
        self.assertEqual(
            [(d.stream_id, d.offset, d.data, d.fin) for d in file_data],
            [(2, 0, head + tail, True)],
        )
        self.assertTrue(
            self.accept(self.data_packet(53, 1, 10, b"!")).delivery_enqueued
        )
        self.assertEqual(
            [(d.stream_id, d.offset, d.data) for d in self.take_all()], [(1, 10, b"!")]
        )

    def test_06_sender_blocked_file_credit_does_not_stop_chat(self) -> None:
        sender = ReliableReceiveState(TransportConnectionState(CONN_ID))
        sender.streams.open_file_stream(2)
        sender.streams.queue_bytes(2, b"F" * MAX_DATA_PER_PACKET)
        sender.streams.queue_bytes(1, b"chat")
        # File has zero initial receive credit. Scheduler must skip it.
        first = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1000))
        self.assertIsNotNone(first)
        self.assertEqual(
            (first.kind, first.stream_id, require_data_frame(first).data),
            ("new_data", 1, b"chat"),
        )
        sender.commit_send(first)
        self.assertEqual(sender.streams._send_state(2).next_offset, 0)
        self.assertEqual(sender.streams._send_state(2).queued_bytes, 1024)
        self.assertIsNone(sender.prepare_send(DATA_KEY, now_ms=1001))
        # Once the peer authorizes FILE_START and advertises credit, file moves.
        credit = encode_packet(
            REVERSE_KEY, WINDOW_UPDATE, CONN_ID, 500, encode_window_update_body(2, 2048)
        )
        accepted = require_not_none(
            sender.accept(
                credit,
                key=REVERSE_KEY,
                endpoint=PEER,
                bound_endpoint=PEER,
                now_ms=1100,
            )
        )
        self.assertTrue(accepted.credit_advanced)
        next_plan = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1101))
        self.assertIsNotNone(next_plan)
        self.assertEqual(
            (
                next_plan.kind,
                next_plan.stream_id,
                len(require_data_frame(next_plan).data),
            ),
            ("new_data", 2, 1024),
        )
        sender.commit_send(next_plan)
        self.assertLessEqual(sender.sent.bytes_in_flight, sender.cubic.cwnd_bytes)

    def test_07_real_udp_loopback_dropped_file_head_chat_then_recovery(self) -> None:
        # Actual localhost UDP datagrams. Initial file head is deliberately
        # not emitted (a controlled network drop); its retry has a NEW PN.
        self.receiver.streams.open_file_stream(2)
        self.receiver.flow.authorize_file_receive(2)
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx,
        ):
            rx.bind(("127.0.0.1", 0))
            rx.settimeout(2.0)
            tx.bind(("127.0.0.1", 0))
            endpoint = tx.getsockname()
            destination = rx.getsockname()
            head = b"H" * 1024
            tail = b"T" * 15
            dropped_original = self.data_packet(60, 2, 0, head)
            self.assertEqual(len(dropped_original), 1075)
            # 'drop': do not call tx.sendto(dropped_original, ...)
            plans = (
                (self.data_packet(61, 2, 1024, tail, fin=True), False, None),
                (self.data_packet(62, 1, 0, b"chat-first"), True, 1),
                (self.data_packet(63, 2, 0, head), True, 2),
                (self.data_packet(64, 2, 0, head), False, None),
            )
            for packet, expected_delivery, expected_stream in plans:
                self.assertEqual(tx.sendto(packet, destination), len(packet))
                actual, source = rx.recvfrom(1200)
                self.assertEqual(source, endpoint)
                self.now_ms += 1
                result = require_not_none(
                    self.receiver.accept(
                        actual,
                        key=DATA_KEY,
                        endpoint=source,
                        bound_endpoint=endpoint,
                        now_ms=self.now_ms,
                    )
                )
                self.assertIsNotNone(result)
                self.assertEqual(result.delivery_enqueued, expected_delivery)
                events = self.take_all()
                if expected_stream is None:
                    self.assertEqual(events, [])
                elif expected_stream == 1:
                    self.assertEqual(
                        [(d.stream_id, d.data) for d in events], [(1, b"chat-first")]
                    )
                else:
                    self.assertEqual(
                        [(d.stream_id, d.data, d.fin) for d in events],
                        [(2, head + tail, True)],
                    )
        self.assertEqual(self.receiver.streams._receive_state(2).delivered_offset, 1039)
        self.assertEqual(self.receiver.streams._receive_state(1).delivered_offset, 10)

    def test_08_real_sender_rto_file_loss_does_not_block_chat(self) -> None:
        """Actual sender scheduler + loss detector + encrypted UDP sockets.

        One DATA is swallowed *after* the send adapter reports success,
        emulating network loss (not a local socket failure). The receiver
        ACKs the tail and chat; sender RTO retries the missing file head.
        """
        sender = ReliableReceiveState(TransportConnectionState(CONN_ID))
        sender.streams.open_file_stream(2)
        sender.streams.update_send_credit(2, 2048)  # FILE_START/WU fixture
        self.receiver.streams.open_file_stream(2)
        self.receiver.flow.authorize_file_receive(2)
        sender.streams.queue_bytes(2, b"F" * 1024 + b"T" * 15, fin=True)
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx,
        ):
            rx.bind(("127.0.0.1", 0))
            tx.bind(("127.0.0.1", 0))
            rx.settimeout(2.0)
            tx.settimeout(2.0)
            rx_endpoint = rx.getsockname()
            tx_endpoint = tx.getsockname()

            def receive_data(
                plan: PreparedScheduledSend, now_ms: float
            ) -> ReceiveResult:
                self.assertEqual(
                    tx.sendto(plan.datagram, rx_endpoint), len(plan.datagram)
                )
                packet, address = rx.recvfrom(1200)
                self.assertEqual(address, tx_endpoint)
                return require_not_none(
                    self.receiver.accept(
                        packet,
                        key=DATA_KEY,
                        endpoint=address,
                        bound_endpoint=tx_endpoint,
                        now_ms=now_ms,
                    )
                )

            # This send is accepted by the network simulator, but packet is
            # swallowed in transit; the sender still tracks it as in-flight.
            head = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1000))
            self.assertIsNotNone(head)
            self.assertEqual(
                (head.stream_id, len(require_data_frame(head).data)), (2, 1024)
            )
            sender.commit_send(head)
            self.assertEqual(sender.sent.outstanding_count, 1)
            # Intentional network loss: do not forward head.datagram to rx.

            tail = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1001))
            self.assertIsNotNone(tail)
            tail_frame = require_data_frame(tail)
            self.assertEqual(
                (tail.stream_id, tail_frame.offset, tail_frame.fin), (2, 1024, True)
            )
            sender.commit_send(tail)
            self.assertFalse(receive_data(tail, 1050).delivery_enqueued)
            self.assertEqual(self.take_all(), [])

            sender.streams.queue_bytes(1, b"chat")
            chat = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1002))
            self.assertIsNotNone(chat)
            self.assertEqual(chat.stream_id, 1)
            sender.commit_send(chat)
            self.assertTrue(receive_data(chat, 1060).delivery_enqueued)
            delivered = self.take_all()
            self.assertEqual([(d.stream_id, d.data) for d in delivered], [(1, b"chat")])
            # Real encrypted ACK datagram goes back through UDP sockets.
            ack = encode_packet(
                REVERSE_KEY,
                ACK,
                CONN_ID,
                800,
                encode_ack_body(
                    0,
                    (
                        (chat.packet_num, chat.packet_num),
                        (tail.packet_num, tail.packet_num),
                    ),
                ),
            )
            self.assertEqual(rx.sendto(ack, tx_endpoint), len(ack))
            ack_bytes, ack_source = tx.recvfrom(1200)
            self.assertEqual(ack_source, rx_endpoint)
            self.assertIsNotNone(
                sender.accept(
                    ack_bytes,
                    key=REVERSE_KEY,
                    endpoint=ack_source,
                    bound_endpoint=rx_endpoint,
                    now_ms=1100,
                )
            )
            self.assertEqual(sender.sent.outstanding_count, 1)
            tracked_head = require_not_none(sender.sent.get(head.packet_num))
            self.assertEqual(require_not_none(tracked_head.frame).offset, 0)

            # Real timeout must queue the missing DATA; with MSS 1075 the
            # retry is sendable without weakening congestion headroom.
            losses = sender.check_rto(now_ms=1800)
            self.assertEqual([x.packet.packet_num for x in losses], [head.packet_num])
            self.assertEqual(sender.sent.bytes_in_flight, 0)
            retry = require_not_none(sender.prepare_send(DATA_KEY, now_ms=1810))
            self.assertIsNotNone(retry)
            self.assertEqual(
                (retry.kind, retry.stream_id, require_data_frame(retry).offset),
                ("data_retry", 2, 0),
            )
            self.assertGreater(retry.packet_num, head.packet_num)
            sender.commit_send(retry)
            self.assertTrue(receive_data(retry, 1850).delivery_enqueued)
            received = self.take_all()
            self.assertEqual(
                [(d.stream_id, d.offset, d.data, d.fin) for d in received],
                [(2, 0, b"F" * 1024 + b"T" * 15, True)],
            )
            self.assertEqual(
                self.receiver.streams._receive_state(2).delivered_offset, 1039
            )


if __name__ == "__main__":
    unittest.main()
