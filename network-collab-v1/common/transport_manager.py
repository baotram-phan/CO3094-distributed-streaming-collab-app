import threading

from common.transport_state import TransportConnectionState


class TransportStateManager:
    def __init__(self):
        self._states: dict[int, TransportConnectionState] = {}

        self._lock = threading.Lock()

    @staticmethod
    def _valid_conn_id(conn_id: int) -> bool:
        return type(conn_id) is int and 1 <= conn_id < (1 << 64)

    def add(self, conn_id: int) -> TransportConnectionState:
        if not self._valid_conn_id(conn_id):
            raise ValueError("Invalid conn_id")

        with self._lock:
            # Nếu đã tồn tại, giữ nguyên state cũ
            state = self._states.get(conn_id)

            if state is None:
                state = TransportConnectionState(conn_id)
                self._states[conn_id] = state

            return state

    def get(self, conn_id: int) -> TransportConnectionState | None:
        if not self._valid_conn_id(conn_id):
            return None

        with self._lock:
            return self._states.get(conn_id)

    def connection_ids(self) -> set[int]:
        """Return a thread-safe snapshot of active connection IDs."""
        with self._lock:
            return set(self._states)

    def remove(self, conn_id: int) -> bool:
        if not self._valid_conn_id(conn_id):
            return False

        with self._lock:
            return self._states.pop(conn_id, None) is not None
