"""Logic demo (NO socket I/O). Run: python -m examples.demo_congestion_feedback"""

from common.reliable_receive import ReliableReceiveState
from common.transport_state import TransportConnectionState
from common.constants import ACK
from common.udp_packet import encode_packet, encode_ack_body

CONN_ID = 808
OUT_KEY = bytes(range(32))
IN_KEY = bytes(range(32, 64))
ENDPOINT = ("127.0.0.1", 39009)

transport = ReliableReceiveState(TransportConnectionState(CONN_ID))
print("Initial CUBIC cwnd:", transport.cubic.cwnd_bytes)
transport.streams.queue_bytes(1, b"hello")
plan = transport.prepare_send(OUT_KEY, now_ms=1000)
assert plan is not None
print("Prepared:", plan.kind, "packet number:", plan.packet_num)

# B4.2.0 logic test: simulate sendto() having accepted the datagram.
transport.commit_send(plan)
print("In-flight bytes:", transport.sent.bytes_in_flight)

# Simulate a valid encrypted ACK from peer at 1100ms.
ack = encode_packet(
    IN_KEY,
    ACK,
    CONN_ID,
    0,
    encode_ack_body(0, [(plan.packet_num, plan.packet_num)]),
)
result = transport.accept(
    ack,
    key=IN_KEY,
    endpoint=ENDPOINT,
    bound_endpoint=ENDPOINT,
    now_ms=1100,
)
assert result is not None
print("ACKed packet numbers:", result.newly_acked_packets)
print("CUBIC cwnd after ACK:", transport.cubic.cwnd_bytes)
print("In-flight after ACK:", transport.sent.bytes_in_flight)
