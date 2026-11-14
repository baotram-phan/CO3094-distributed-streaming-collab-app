"""Regression tests for merging A1.5 official integration with B 2026-11-09 update."""

import unittest

from common.constants import AES_256_KEY_SIZE, REPLAY_WINDOW_SIZE, PROTOCOL_VERSION
from common.crypto import make_nonce
from common.transport_manager import TransportStateManager
from common.transport_state import TransportConnectionState
from common.udp_packet import encode_packet, decode_packet
from common.constants import REGISTER


class TestABMergeCompatibility(unittest.TestCase):
    def test_constants_support_both_sides(self):
        self.assertEqual(PROTOCOL_VERSION, 1)
        self.assertEqual(AES_256_KEY_SIZE, 32)
        self.assertEqual(REPLAY_WINDOW_SIZE, 4096)

    def test_max_uint64_packet_number_is_valid(self):
        pn = (1 << 64) - 1
        self.assertEqual(make_nonce(pn), b"\0" * 4 + b"\xff" * 8)
        packet = encode_packet(b"k" * 32, REGISTER, 42, pn)
        self.assertEqual(decode_packet(b"k" * 32, packet), (REGISTER, 42, pn, b""))

    def test_manager_cleanup_and_snapshot(self):
        manager = TransportStateManager()
        state = manager.add(42)
        self.assertIs(state, manager.add(42))
        self.assertEqual(manager.connection_ids(), {42})
        self.assertTrue(manager.remove(42))
        self.assertEqual(manager.connection_ids(), set())
        self.assertIsNone(manager.get(42))

    def test_packet_counter_exhaustion_does_not_wrap(self):
        state = TransportConnectionState(42)
        state._next_send_packet_num = (1 << 64) - 1
        self.assertEqual(state.allocate_packet_number(), (1 << 64) - 1)
        with self.assertRaises(OverflowError):
            state.allocate_packet_number()


if __name__ == "__main__":
    unittest.main()
