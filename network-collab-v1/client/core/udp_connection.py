"""A1.5 UDP REGISTER client using B's official packet/crypto/replay modules.

A TLS bootstrap provides conn_id, c2s_key, s2c_key and udp_port.
Use ONE socket and ONE TransportConnectionState per connection; never reset the
outbound packet number while retaining its AES-GCM key.  Keep this object alive
if A1.6 adds authenticated reliable streams and heartbeat to the session.
"""
from __future__ import annotations

import socket
import time

from cryptography.exceptions import InvalidTag

from common.constants import HEADER_SIZE, REGISTER, REGISTER_OK
from common.transport_state import TransportConnectionState
from common.udp_packet import decode_header, decode_packet, encode_packet


class UDPRegistrationClient:
    def __init__(
        self, *, host: str, udp_port: int, conn_id: int,
        c2s_key: bytes, s2c_key: bytes, bind_host: str = '0.0.0.0',
        bootstrap_deadline: float | None = None,
    ) -> None:
        """bootstrap_deadline: absolute time.monotonic() deadline (seconds).

        To respect the server's 10-second BOOTSTRAPPED deadline, the caller
        should calculate it *before* beginning TLS bootstrap, e.g.:
            started = time.monotonic()
            session = bootstrap(...)
            client = UDPRegistrationClient(..., bootstrap_deadline=started + 10)
        If omitted, the client uses a 10-second cap from construction; this
        cannot account for time already spent in the preceding TLS bootstrap.
        """
        if type(udp_port) is not int or not (1 <= udp_port <= 65535):
            raise ValueError('udp_port must be between 1 and 65535')
        if not isinstance(c2s_key, bytes) or len(c2s_key) != 32:
            raise ValueError('c2s_key must be 32 bytes')
        if not isinstance(s2c_key, bytes) or len(s2c_key) != 32:
            raise ValueError('s2c_key must be 32 bytes')
        if c2s_key == s2c_key:
            raise ValueError('UDP send and receive keys must differ')

        self.server_endpoint = (socket.gethostbyname(host), udp_port)
        self.conn_id = conn_id
        self.c2s_key = c2s_key
        self.s2c_key = s2c_key
        self.state = TransportConnectionState(conn_id)
        self.bootstrap_deadline = (
            float(bootstrap_deadline)
            if bootstrap_deadline is not None else time.monotonic() + 10.0
        )
        self.registered = False
        self._closed = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((bind_host, 0))
        except Exception:
            self.sock.close()
            raise

    @property
    def local_endpoint(self) -> tuple[str, int]:
        return self.sock.getsockname()

    def register(self, *, attempts: int = 10, wait_s: float = 0.5) -> tuple[str, int]:
        """Send new authenticated REGISTER each retry, verify REGISTER_OK.

        Never sends after bootstrap_deadline.  A positive attempt count and
        timeout are required.  A valid delayed reply to an earlier attempt is
        still acceptable; server packet-number replay protection applies.
        """
        if self._closed:
            raise RuntimeError('UDP socket is closed; bootstrap again')
        if self.registered:
            raise RuntimeError('Already registered; retain connection for A1.6')
        if type(attempts) is not int or not (1 <= attempts <= 10):
            raise ValueError('attempts must be an integer between 1 and 10')
        if wait_s <= 0:
            raise ValueError('wait_s must be positive')

        for _ in range(attempts):
            now = time.monotonic()
            if now >= self.bootstrap_deadline:
                break
            packet_number = self.state.allocate_packet_number()
            request = encode_packet(self.c2s_key, REGISTER, self.conn_id, packet_number)
            self.sock.sendto(request, self.server_endpoint)
            wait_deadline = min(self.bootstrap_deadline, now + wait_s)

            while True:
                remaining = wait_deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                try:
                    packet, source = self.sock.recvfrom(2048)
                except socket.timeout:
                    break
                if source != self.server_endpoint or len(packet) < HEADER_SIZE:
                    continue
                try:
                    kind, received_conn_id, pn = decode_header(packet[:HEADER_SIZE])
                    if kind != REGISTER_OK or received_conn_id != self.conn_id:
                        continue
                    if not self.state.recv_replay.can_accept(pn):
                        continue
                    decoded = decode_packet(self.s2c_key, packet)
                    if decoded != (REGISTER_OK, self.conn_id, pn, b''):
                        continue
                    self.state.recv_replay.commit(pn)
                    self.registered = True
                    return self.local_endpoint
                except (InvalidTag, ValueError, TypeError):
                    continue

        raise TimeoutError('No authenticated REGISTER_OK before bootstrap deadline; bootstrap again')

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
