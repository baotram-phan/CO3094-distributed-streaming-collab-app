
import socket

from common.constants import REGISTER, REGISTER_OK
from common.udp_packet import encode_packet, decode_packet

CONN_ID = 42
C2S_KEY = bytes(range(32))
S2C_KEY = bytes(range(32, 64))

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 9001))
    print("UDP server listening on 127.0.0.1:9001")

    packet, client_addr = sock.recvfrom(2048)

    packet_type, conn_id, pkt_num, plaintext = decode_packet(
        C2S_KEY, packet
    )

    if (packet_type, conn_id, plaintext) != (REGISTER, CONN_ID, b""):
        raise ValueError("Invalid REGISTER")

    print("REGISTER received from:", client_addr)
    print("Packet number:", pkt_num)

    response = encode_packet(
        S2C_KEY, REGISTER_OK, CONN_ID, 0
    )

    sock.sendto(response, client_addr)
    print("REGISTER_OK sent")
