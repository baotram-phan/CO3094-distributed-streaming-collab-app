
import unittest

from common.replay import ReplayWindow


class TestReplayWindow(unittest.TestCase):

    def test_first_packet(self):
        window = ReplayWindow()

        self.assertTrue(window.commit(0))
        self.assertEqual(window.highest, 0)

    def test_duplicate_packet(self):
        window = ReplayWindow()

        self.assertTrue(window.commit(5))
        self.assertFalse(window.commit(5))

    def test_out_of_order(self):
        window = ReplayWindow()

        self.assertTrue(window.commit(10))
        self.assertTrue(window.commit(12))
        self.assertTrue(window.commit(11))

        self.assertEqual(window.highest, 12)

    def test_packet_too_old(self):
        window = ReplayWindow(size=4)

        window.commit(10)
        window.commit(14)

        self.assertFalse(window.can_accept(10))

    def test_check_does_not_commit(self):
        window = ReplayWindow()

        self.assertTrue(window.can_accept(7))
        self.assertTrue(window.can_accept(7))

        self.assertTrue(window.commit(7))
        self.assertFalse(window.can_accept(7))


if __name__ == "__main__":
    unittest.main()
