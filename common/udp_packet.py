import struct

from common.constants import (
    MAGIC,
    WIRE_VERSION,
    HEADER_SIZE,
    VALID_PACKET_TYPES,
    GCM_TAG_SIZE,
    MAX_UDP_DATAGRAM,
    REGISTER,
    REGISTER_OK,
    PING, 
    PONG
)

from common.crypto import encrypt_payload, decrypt_payload

HEADER_STRUCT = struct.Struct("!HBBQQ")

MAX_UINT64 = (1 << 64) - 1

def validate_uint64(value: int, name: str):
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")

    if not (0 <= value <= MAX_UINT64):
        raise ValueError(f"{name} must be uint64")

def encode_header(packet_type, conn_id, pkt_num):
    if type(packet_type) is not int:
        raise ValueError("packet_type must be an integer")

    if packet_type not in VALID_PACKET_TYPES:
        raise ValueError("Unsupported packet type")
    
    validate_uint64(conn_id, "conn_id")
    validate_uint64(pkt_num, "pkt_num")

    if conn_id == 0:
        raise ValueError("conn_id must not be zero")

    header = HEADER_STRUCT.pack(
        MAGIC,
        WIRE_VERSION,
        packet_type,
        conn_id,
        pkt_num
    )
    return header

def decode_header(data: bytes):
    if len(data) != HEADER_SIZE:
        raise ValueError("Invalid header size")
    
    magic, version, packet_type, conn_id, pkt_num = HEADER_STRUCT.unpack(data)
    
    if magic != MAGIC:
        raise ValueError("Invalid magic")

    if version != WIRE_VERSION:
        raise ValueError("Unsupported protocol version")
    
    if packet_type not in VALID_PACKET_TYPES:
        raise ValueError("Unsupported packet type")

    if conn_id == 0:
        raise ValueError("Invalid conn_id")

    return packet_type, conn_id, pkt_num


def encode_packet(
    key: bytes,
    packet_type: int,
    conn_id: int,
    pkt_num: int,
    plaintext: bytes = b""
) -> bytes:

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    max_plaintext = (
        MAX_UDP_DATAGRAM - HEADER_SIZE - GCM_TAG_SIZE
    )

    if len(plaintext) > max_plaintext:
        raise ValueError("UDP payload too large")

    validate_packet_body(packet_type, plaintext)

    header = encode_header(packet_type, conn_id, pkt_num)

    encrypted = encrypt_payload(
        key, pkt_num, plaintext, header
    )

    return header + encrypted


def decode_packet(key: bytes, packet: bytes):
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")

    min_size = HEADER_SIZE + GCM_TAG_SIZE

    if not (min_size <= len(packet) <= MAX_UDP_DATAGRAM):
        raise ValueError("Invalid UDP packet size")

    header = packet[:HEADER_SIZE]

    packet_type, conn_id, pkt_num = decode_header(header)

    encrypted_payload = packet[HEADER_SIZE:]

    plaintext = decrypt_payload(
        key,
        pkt_num,
        encrypted_payload,
        header
    )

    validate_packet_body(packet_type, plaintext)

    return packet_type, conn_id, pkt_num, plaintext


def validate_packet_body(packet_type: int, plaintext: bytes):
    if packet_type in (REGISTER, REGISTER_OK):
        if len(plaintext) != 0:
            raise ValueError("REGISTER/REGISTER_OK body must be empty")

    elif packet_type in (PING, PONG):
        if len(plaintext) != 8:
            raise ValueError("PING/PONG body must be 8 bytes")


