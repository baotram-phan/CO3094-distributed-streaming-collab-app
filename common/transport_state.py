
import threading

from common.replay import ReplayWindow


class TransportConnectionState:
    def __init__(self, conn_id: int):
        if type(conn_id) is not int or not (1 <= conn_id < (1 << 64)):
            raise ValueError("Invalid conn_id")

        self.conn_id = conn_id

        self._next_send_packet_num = 0

        self.recv_replay = ReplayWindow(size=4096)

        self._send_lock = threading.Lock()

    def allocate_packet_number(self) -> int:
        with self._send_lock:
            if self._next_send_packet_num >= (1 << 64):
                raise OverflowError("Packet number exhausted")

            pkt_num = self._next_send_packet_num
            self._next_send_packet_num += 1

            return pkt_num
