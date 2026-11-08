
import unittest

from common.transport_state import TransportConnectionState


class TestTransportConnectionState(unittest.TestCase):

    def test_packet_number_increment(self):
        state = TransportConnectionState(conn_id=101)

        self.assertEqual(state.allocate_packet_number(), 0)
        self.assertEqual(state.allocate_packet_number(), 1)
        self.assertEqual(state.allocate_packet_number(), 2)

    def test_independent_packet_numbers(self):
        state_a = TransportConnectionState(conn_id=101)
        state_b = TransportConnectionState(conn_id=202)

        self.assertEqual(state_a.allocate_packet_number(), 0)
        self.assertEqual(state_a.allocate_packet_number(), 1)

        self.assertEqual(state_b.allocate_packet_number(), 0)

    def test_independent_replay_windows(self):
        state_a = TransportConnectionState(conn_id=101)
        state_b = TransportConnectionState(conn_id=202)

        state_a.recv_replay.commit(5)

        self.assertFalse(state_a.recv_replay.can_accept(5))

        self.assertTrue(state_b.recv_replay.can_accept(5))
