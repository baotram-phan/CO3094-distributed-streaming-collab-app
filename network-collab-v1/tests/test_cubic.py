"""A's CUBIC controller contract / algorithm regression tests."""

import unittest

from common.cubic import CubicController


class CubicTests(unittest.TestCase):
    def test_initial_window(self):
        c = CubicController(mss_bytes=1024)
        self.assertEqual(c.cwnd_bytes, 10240)

    def test_initial_slow_start_ack_growth(self):
        c = CubicController()
        c.on_ack(1024, 1.0, 0.1)
        self.assertEqual(c.cwnd_bytes, 11264)

    def test_duplicate_ack_no_growth(self):
        c = CubicController()
        c.on_ack(0, 1.0, 0.1)
        self.assertEqual(c.cwnd_bytes, 10240)

    def test_loss_beta_and_ssthresh(self):
        c = CubicController()
        c.on_loss(1.0, 17)
        self.assertEqual(c.cwnd_bytes, 7168)
        self.assertEqual(c.ssthresh_bytes, 7168)

    def test_loss_duplicate_marker_is_idempotent(self):
        c = CubicController()
        c.on_loss(1.0, 17)
        original = c.cwnd_bytes
        c.on_loss(1.1, 17)
        c.on_loss(1.2, 16)
        self.assertEqual(c.cwnd_bytes, original)

    def test_new_recovery_marker_causes_new_decrease(self):
        c = CubicController()
        c.on_loss(1.0, 17)
        c.on_loss(2.0, 23)
        self.assertLess(c.cwnd_bytes, 7168)
        self.assertGreaterEqual(c.cwnd_bytes, 2048)

    def test_congestion_avoidance_grows(self):
        c = CubicController()
        c.on_loss(1.0, 20)
        start = c.cwnd_bytes
        for i in range(1, 31):
            c.on_ack(1024, 1.0 + i * 0.1, 0.1)
        self.assertGreater(c.cwnd_bytes, start)

    def test_timeout_resets_to_mss(self):
        c = CubicController()
        c.on_ack(2048, 1.0, 0.1)
        c.on_timeout(2.0)
        self.assertEqual(c.cwnd_bytes, 1024)
        self.assertGreaterEqual(c.ssthresh_bytes, 2048)

    def test_timeout_then_slow_start(self):
        c = CubicController()
        c.on_timeout(1.0)
        c.on_ack(1024, 1.1, 0.1)
        self.assertEqual(c.cwnd_bytes, 2048)

    def test_loss_after_timeout_never_increases_cwnd(self):
        c = CubicController()
        c.on_timeout(1.0)
        c.on_loss(1.1, 20)
        self.assertEqual(c.cwnd_bytes, 1024)

    def test_rejects_invalid_parameters(self):
        with self.assertRaises(ValueError):
            CubicController(0)
        with self.assertRaises(ValueError):
            CubicController(1.5)
        c = CubicController()
        with self.assertRaises(ValueError):
            c.on_ack(-1, 1, 0.1)
        with self.assertRaises(ValueError):
            c.on_ack(1, 1, 0)
        with self.assertRaises(ValueError):
            c.on_loss(1, -1)
        with self.assertRaises(ValueError):
            c.on_ack(1, float("nan"), 0.1)

    def test_requires_monotonic_clock(self):
        c = CubicController()
        c.on_ack(1024, 2.0, 0.1)
        with self.assertRaises(ValueError):
            c.on_loss(1.0, 2)


if __name__ == "__main__":
    unittest.main()
