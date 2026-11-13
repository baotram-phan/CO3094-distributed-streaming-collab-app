"""B3.3.1 WINDOW_UPDATE orchestration tests; deterministic, no real UDP."""

import unittest
from dataclasses import replace
from typing import cast

from common.constants import DATA, WINDOW_UPDATE
from common.streams import StreamManager, StreamSendFrame
from common.transport import (
    AckReceipt, LostPacket, PacketLossDetector, RttEstimator,
    SentPacketTracker,
)
from common.transport_state import TransportConnectionState
from common.udp_packet import (
    decode_packet, decode_window_update_body, encode_ack_body,
    encode_window_update_body,
)
from common.window_update_flow import WindowUpdateFlow

KEY = bytes(range(32))
CONN = 921


def tracked_packet(sent: SentPacketTracker, pn: int):
    packet = sent.get(pn)
    assert packet is not None
    return packet


def setup(**kwargs):
    streams = StreamManager(CONN)
    ctrl = WindowUpdateFlow(streams, **kwargs)
    connection = TransportConnectionState(CONN)
    sent = SentPacketTracker()
    return streams, ctrl, connection, sent


def emit(ctrl, connection, sent, now=0):
    plan = ctrl.prepare_send(connection, sent, KEY, now)
    assert plan is not None
    ctrl.commit_sent(plan)
    return plan


def ack(ctrl, sent, *pns):
    receipt = sent.process_ack(encode_ack_body(0, [(pn, pn) for pn in sorted(pns, reverse=True)]))
    return ctrl.on_ack(receipt, sent)


class TestIncomingCredit(unittest.TestCase):
    def test_12_byte_codec_roundtrip_and_increasing_credit(self):
        streams, flow, _, _ = setup()
        body = encode_window_update_body(1, 65538)
        self.assertEqual(len(body), 12)
        self.assertTrue(flow.receive_peer_update(body))
        self.assertEqual(streams._send_state(1).advertised_max_offset, 65538)

    def test_duplicate_and_stale_are_ignored_without_mutation(self):
        streams, flow, _, _ = setup()
        self.assertTrue(flow.receive_peer_update(encode_window_update_body(1, 66000)))
        self.assertFalse(flow.receive_peer_update(encode_window_update_body(1, 66000)))
        self.assertFalse(flow.receive_peer_update(encode_window_update_body(1, 65536)))
        self.assertEqual(streams._send_state(1).advertised_max_offset, 66000)

    def test_stale_one_stream_does_not_affect_another(self):
        streams, flow, _, _ = setup()
        self.assertTrue(flow.receive_peer_update(encode_window_update_body(0, 70000)))
        self.assertFalse(flow.receive_peer_update(encode_window_update_body(0, 50000)))
        self.assertTrue(flow.receive_peer_update(encode_window_update_body(1, 70001)))
        self.assertEqual(streams._send_state(1).advertised_max_offset, 70001)

    def test_unopened_file_stream_is_rejected(self):
        _, flow, _, _ = setup()
        with self.assertRaises(ValueError):
            flow.receive_peer_update(encode_window_update_body(2, 512*1024))

    def test_file_stream_zero_credit_until_authorized(self):
        streams, flow, _, _ = setup()
        streams.open_file_stream(2)
        streams.queue_bytes(2, b"abc")
        self.assertIsNone(streams.next_send_frame(2))
        self.assertTrue(flow.receive_peer_update(encode_window_update_body(2, 3)))
        frame = streams.next_send_frame(2)
        assert frame is not None
        self.assertEqual((frame.offset, frame.data), (0, b"abc"))

    def test_wrong_length_or_type_does_not_mutate_credit(self):
        streams, flow, _, _ = setup()
        for body in (b"", b"\x00" * 11, b"\x00" * 13, b"oops"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                flow.receive_peer_update(body)
        self.assertEqual(streams._send_state(1).advertised_max_offset, 65536)

    def test_invalid_type_raises(self):
        _, flow, _, _ = setup()
        with self.assertRaises(TypeError):
            flow.receive_peer_update(cast(bytes, None))

    def test_unknown_stream_mutation_prevented(self):
        _, flow, _, _ = setup()
        with self.assertRaises(ValueError):
            flow.receive_peer_update(encode_window_update_body(123, 2))


class TestCreditLifecycle(unittest.TestCase):
    def test_no_automatic_credit_on_receive(self):
        streams, flow, _, _ = setup()
        delivery = streams.receive_frame(1, 0, b"abc")
        assert delivery is not None
        self.assertEqual(delivery.data, b"abc")
        self.assertEqual(streams._receive_state(1).advertised_max_offset, 65536)
        self.assertEqual(flow.pending_stream_ids, ())

    def test_downstream_consumed_grants_credit(self):
        streams, flow, _, _ = setup()
        streams.receive_frame(1, 0, b"hello")
        self.assertTrue(flow.note_consumed(1, 5))
        self.assertEqual(streams._receive_state(1).advertised_max_offset, 65536 + 5)
        self.assertEqual(flow.pending_stream_ids, (1,))

    def test_consumed_can_advance_in_steps(self):
        streams, flow, _, _ = setup()
        streams.receive_frame(1, 0, b"abcde")
        self.assertTrue(flow.note_consumed(1, 2))
        self.assertTrue(flow.note_consumed(1, 5))
        self.assertFalse(flow.note_consumed(1, 5))
        self.assertEqual(streams._receive_state(1).advertised_max_offset, 65541)

    def test_cannot_consume_undelivered_bytes(self):
        streams, flow, _, _ = setup()
        streams.receive_frame(1, 10, b"missing-front")
        with self.assertRaises(ValueError):
            flow.note_consumed(1, 1)
        self.assertEqual(flow.pending_stream_ids, ())

    def test_cannot_consume_in_reverse(self):
        streams, flow, _, _ = setup()
        streams.receive_frame(1, 0, b"abc")
        flow.note_consumed(1, 2)
        with self.assertRaises(ValueError):
            flow.note_consumed(1, 1)

    def test_invalid_consumed_type(self):
        _, flow, _, _ = setup()
        for value in (-1, True, 1.5, 1 << 64, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                flow.note_consumed(1, cast(int, value))

    def test_file_credit_requires_explicit_authorization(self):
        streams, flow, _, _ = setup()
        streams.open_file_stream(2)
        self.assertEqual(streams._receive_state(2).advertised_max_offset, 0)
        self.assertTrue(flow.authorize_file_receive(2))
        self.assertEqual(streams._receive_state(2).advertised_max_offset, 512*1024)
        self.assertFalse(flow.authorize_file_receive(2))
        self.assertEqual(flow.pending_stream_ids, (2,))

    def test_file_authorize_unknown_rejected(self):
        _, flow, _, _ = setup()
        with self.assertRaises(ValueError):
            flow.authorize_file_receive(2)
        with self.assertRaises(ValueError):
            flow.authorize_file_receive(1)
        self.assertEqual(flow.pending_stream_ids, ())

    def test_file_flow_credit_after_consumption(self):
        streams, flow, _, _ = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        streams.receive_frame(2, 0, b"abcd")
        self.assertTrue(flow.note_consumed(2, 4))
        self.assertEqual(streams._receive_state(2).advertised_max_offset, 512*1024+4)

    def test_cross_stream_chat_progress_during_file_gap(self):
        streams, flow, _, _ = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        self.assertIsNone(streams.receive_frame(2, 5, b"world", fin=True))
        chat = streams.receive_frame(1, 0, b"hi")
        assert chat is not None
        self.assertEqual(chat.data, b"hi")
        self.assertTrue(flow.note_consumed(1, 2))
        self.assertIn(1, flow.pending_stream_ids)

    def test_receiver_rejects_more_than_granted(self):
        streams, flow, _, _ = setup()
        streams.open_file_stream(2)
        with self.assertRaises(ValueError):
            streams.receive_frame(2, 0, b"not authorized")
        flow.authorize_file_receive(2)
        with self.assertRaises(ValueError):
            streams.receive_frame(2, 512*1024, b"x")


class TestReliableWindowUpdate(unittest.TestCase):
    def test_build_encrypted_packet_with_correct_type_body(self):
        streams, flow, connection, sent = setup()
        streams.receive_frame(1, 0, b"abc")
        flow.note_consumed(1, 3)
        plan = flow.prepare_send(connection, sent, KEY, 100)
        assert plan is not None
        self.assertEqual(plan.attempt_number, 1)
        kind, cid, pn, body = decode_packet(KEY, plan.datagram)
        self.assertEqual((kind, cid, pn), (WINDOW_UPDATE, CONN, plan.packet_num))
        self.assertEqual(decode_window_update_body(body), (1, 65539))
        self.assertLessEqual(len(plan.datagram), 1200)
        self.assertIsNotNone(sent.get(pn))
        flow.commit_sent(plan)

    def test_first_commit_awaits_ack(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        plan = emit(flow, connection, sent)
        self.assertEqual(flow.pending_stream_ids, (2,))
        self.assertEqual(flow.tracked_attempts, 1)
        self.assertIsNone(flow.prepare_send(connection, sent, KEY, 1))
        self.assertEqual(ack(flow, sent, plan.packet_num), ((2, 512*1024),))
        self.assertEqual(flow.pending_stream_ids, ())
        self.assertEqual(flow.tracked_attempts, 0)

    def test_socket_failure_retains_credit_burns_nonce(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        plan = flow.prepare_send(connection, sent, KEY, 0)
        assert plan is not None
        flow.abort_send(plan, sent)
        self.assertIsNone(sent.get(plan.packet_num))
        self.assertEqual(flow.pending_stream_ids, (2,))
        again = emit(flow, connection, sent, 1)
        self.assertGreater(again.packet_num, plan.packet_num)
        self.assertEqual(again.max_offset, plan.max_offset)

    def test_rto_loss_retries_same_body_new_packet_num(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        first = emit(flow, connection, sent, 0)
        loss = PacketLossDetector()
        rtt = RttEstimator()
        lost = loss.check_timeouts(sent, rtt, now_ms=500)
        self.assertEqual(len(lost), 1)
        self.assertTrue(flow.note_loss(lost[0], sent))
        second = emit(flow, connection, sent, 501)
        self.assertGreater(second.packet_num, first.packet_num)
        self.assertEqual(decode_packet(KEY, first.datagram)[3], decode_packet(KEY, second.datagram)[3])
        self.assertEqual(second.attempt_number, 2)

    def test_late_ack_cancels_pending_retry(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        first = emit(flow, connection, sent)
        loss = LostPacket(tracked_packet(sent, first.packet_num), "rto", 500)
        self.assertTrue(flow.note_loss(loss, sent))
        self.assertEqual(ack(flow, sent, first.packet_num), ((2, 512*1024),))
        self.assertIsNone(flow.prepare_send(connection, sent, KEY, 700))

    def test_ack_of_retry_cancels_old_history(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        first = emit(flow, connection, sent, 0)
        self.assertTrue(flow.note_loss(LostPacket(tracked_packet(sent, first.packet_num), "rto", 500), sent))
        second = emit(flow, connection, sent, 501)
        self.assertEqual(ack(flow, sent, second.packet_num), ((2, 512*1024),))
        self.assertEqual(flow.tracked_attempts, 0)
        self.assertEqual(ack(flow, sent, first.packet_num), ())

    def test_newer_credit_supersedes_older_ack_but_not_other_way(self):
        streams, flow, connection, sent = setup()
        streams.receive_frame(1, 0, b"abcd")
        flow.note_consumed(1, 2)
        first = emit(flow, connection, sent)
        flow.note_consumed(1, 4)
        second = emit(flow, connection, sent, 1)
        self.assertEqual(first.max_offset, 65538)
        self.assertEqual(second.max_offset, 65540)
        self.assertEqual(ack(flow, sent, first.packet_num), ((1, 65538),))
        self.assertEqual(flow.pending_stream_ids, (1,))
        self.assertEqual(ack(flow, sent, second.packet_num), ((1, 65540),))
        self.assertEqual(flow.pending_stream_ids, ())

    def test_newer_ack_retires_old_outstanding_metadata(self):
        streams, flow, connection, sent = setup()
        streams.receive_frame(1, 0, b"abcde")
        flow.note_consumed(1, 1)
        old = emit(flow, connection, sent)
        flow.note_consumed(1, 5)
        newer = emit(flow, connection, sent, 10)
        self.assertEqual(ack(flow, sent, newer.packet_num), ((1, 65541),))
        self.assertIsNone(sent.get(old.packet_num))
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_invalid_connection_key_rejected_before_pn_alloc(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        for bad in (None, b"short", "wrong"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                flow.prepare_send(connection, sent, cast(bytes, bad), 0)
        self.assertEqual(connection._next_send_packet_num, 0)

    def test_wrong_connection_state_rejected(self):
        streams, flow, _, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        with self.assertRaises(ValueError):
            flow.prepare_send(TransportConnectionState(CONN+1), sent, KEY, 0)

    def test_duplicate_loss_report_is_idempotent(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        first = emit(flow, connection, sent)
        loss = LostPacket(tracked_packet(sent, first.packet_num), "rto", 500)
        self.assertTrue(flow.note_loss(loss, sent))
        self.assertFalse(flow.note_loss(loss, sent))
        self.assertEqual(sent.bytes_in_flight, 0)

    def test_non_window_loss_ignored(self):
        streams, flow, _, sent = setup()
        frame = StreamSendFrame(1, 0, b"hi")
        sent.track_sent(100, DATA, 50, 0, frame=frame)
        packet = sent.get(100)
        assert packet is not None
        self.assertFalse(flow.note_loss(LostPacket(packet, "rto", 500), sent))
        self.assertIsNotNone(sent.get(100))

    def test_failed_send_does_not_count_retry(self):
        streams, flow, connection, sent = setup(max_retransmissions=1)
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        plan = flow.prepare_send(connection, sent, KEY, 0)
        assert plan is not None
        flow.abort_send(plan, sent)
        plan2 = emit(flow, connection, sent)
        self.assertEqual(plan2.attempt_number, 1)

    def test_retry_limit_raises_after_one_retry(self):
        streams, flow, connection, sent = setup(max_retransmissions=1)
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        first = emit(flow, connection, sent, 0)
        flow.note_loss(LostPacket(tracked_packet(sent, first.packet_num), "rto", 500), sent)
        second = emit(flow, connection, sent, 600)
        flow.note_loss(LostPacket(tracked_packet(sent, second.packet_num), "rto", 1100), sent)
        with self.assertRaises(TimeoutError):
            flow.prepare_send(connection, sent, KEY, 1200)

    def test_history_limit_returns_none_without_losing_credit(self):
        streams, flow, connection, sent = setup(max_attempt_history=1)
        streams.receive_frame(1, 0, b"abcdef")
        flow.note_consumed(1, 1)
        old = emit(flow, connection, sent)
        flow.note_consumed(1, 6)
        self.assertIsNone(flow.prepare_send(connection, sent, KEY, 1))
        self.assertEqual(flow.pending_stream_ids, (1,))
        ack(flow, sent, old.packet_num)
        self.assertIsNotNone(flow.prepare_send(connection, sent, KEY, 2))

    def test_tracker_byte_limit_prevents_allocation(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        constrained = SentPacketTracker(max_pending_bytes=47)
        self.assertIsNone(flow.prepare_send(connection, constrained, KEY, 0))
        self.assertEqual(connection._next_send_packet_num, 0)

    def test_prepared_transaction_requires_commit_or_abort(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        plan = flow.prepare_send(connection, sent, KEY, 0)
        assert plan is not None
        with self.assertRaises(RuntimeError):
            flow.prepare_send(connection, sent, KEY, 1)
        with self.assertRaises(ValueError):
            flow.commit_sent(replace(plan, packet_num=plan.packet_num+1))
        flow.abort_send(plan, sent)

    def test_ack_only_has_no_reack(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        plan = emit(flow, connection, sent)
        self.assertEqual(ack(flow, sent, plan.packet_num), ((2, 512*1024),))
        # ACK for this WU is an ordinary ACK-only UDP packet; it is not ACKed again.
        self.assertEqual(flow.pending_stream_ids, ())

    def test_different_streams_are_independent(self):
        streams, flow, connection, sent = setup()
        streams.open_file_stream(2)
        flow.authorize_file_receive(2)
        streams.receive_frame(1, 0, b"ok")
        flow.note_consumed(1, 2)
        first = emit(flow, connection, sent)
        second = emit(flow, connection, sent, 1)
        self.assertEqual((first.stream_id, second.stream_id), (1, 2))
        ack(flow, sent, first.packet_num)
        self.assertEqual(flow.pending_stream_ids, (2,))


if __name__ == "__main__":
    unittest.main()