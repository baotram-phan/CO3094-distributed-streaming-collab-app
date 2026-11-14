class ReplayWindow:
    def __init__(self, size: int = 4096):
        if type(size) is not int or size <= 0:
            raise ValueError("Invalid replay window size")

        self.size = size
        self.highest = -1
        self.received = set()

    def can_accept(self, pkt_num: int) -> bool:
        if type(pkt_num) is not int:
            return False

        if not (0 <= pkt_num < (1 << 64)):
            return False

        if pkt_num <= self.highest - self.size:
            return False

        if pkt_num in self.received:
            return False

        return True

    def commit(self, pkt_num: int) -> bool:
        if not self.can_accept(pkt_num):
            return False

        self.highest = max(self.highest, pkt_num)

        self.received.add(pkt_num)

        cutoff = self.highest - self.size + 1

        self.received = {num for num in self.received if num >= cutoff}

        return True
