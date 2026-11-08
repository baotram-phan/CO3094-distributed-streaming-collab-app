
import unittest

from common.transport_manager import TransportStateManager


class TestTransportStateManager(unittest.TestCase):

    def test_add_and_get(self):
        manager = TransportStateManager()

        state = manager.add(101)

        self.assertIs(manager.get(101), state)

    def test_add_existing_keeps_state(self):
        manager = TransportStateManager()

        first = manager.add(101)
        self.assertEqual(first.allocate_packet_number(), 0)

        second = manager.add(101)

        self.assertIs(first, second)
        self.assertEqual(second.allocate_packet_number(), 1)

    def test_remove(self):
        manager = TransportStateManager()

        manager.add(101)

        self.assertTrue(manager.remove(101))
        self.assertIsNone(manager.get(101))
        self.assertFalse(manager.remove(101))

    def test_invalid_conn_id(self):
        manager = TransportStateManager()

        for invalid in (0, -1, True, 1 << 64):
            with self.assertRaises(ValueError):
                manager.add(invalid)
