
import socket

from common.constants import REGISTER, REGISTER_OK
from common.udp_packet import encode_packet, decode_packet

CONN_ID = 42
C2S_KEY = bytes(range(32))
S2C_KEY = bytes(range(32, 64))

server_addr = ("127.0.0.1", 9001)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)

    packet = encode_packet(
        C2S_KEY, REGISTER, CONN_ID, 0
    )

    sock.sendto(packet, server_addr)
    print("REGISTER sent:", len(packet), "bytes")

    response, addr = sock.recvfrom(2048)

    if addr != server_addr:
        raise ValueError("Unexpected server address")

    packet_type, conn_id, pkt_num, plaintext = decode_packet(
        S2C_KEY, response
    )

    if (packet_type, conn_id, plaintext) != (REGISTER_OK, CONN_ID, b""):
        raise ValueError("Invalid REGISTER_OK")

    print("REGISTER_OK received")
    print("Response packet number:", pkt_num)
