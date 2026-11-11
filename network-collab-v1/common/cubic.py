"""[TODO - A] CUBIC Congestion Controller (RFC 9438).

B sở hữu UDP ACK/loss detection, bytes_in_flight; A sở hữu quyết định cwnd.
Đây là skeleton, các hàm cố ý raise để tránh giả vờ congestion control hoạt động.
"""

class CubicController:
    def __init__(self, mss_bytes: int = 1024):
        if mss_bytes <= 0:
            raise ValueError("mss_bytes must be positive")
        self.mss_bytes = mss_bytes
        self.cwnd_bytes = 10 * mss_bytes  # initial proposed window, NOT a CUBIC implementation
        raise NotImplementedError("A: implement CUBIC state/slow start per RFC 9438")

    def on_ack(self, acked_bytes: int, now_seconds: float, rtt_seconds: float) -> None:
        raise NotImplementedError("A: implement CUBIC ACK growth")

    def on_loss(self, now_seconds: float, recovery_marker: int) -> None:
        raise NotImplementedError("A: implement CUBIC loss recovery")

    def on_timeout(self, now_seconds: float) -> None:
        raise NotImplementedError("A: implement CUBIC timeout handling")
