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
    PONG,
    DATA,
    MAX_DATA_PER_PACKET,
    ACK,
    WINDOW_UPDATE,
    CLOSE
)

from common.crypto import encrypt_payload, decrypt_payload

HEADER_STRUCT = struct.Struct("!HBBQQ")
DATA_STRUCT = struct.Struct("!IQBH")
ACK_HEADER_STRUCT = struct.Struct("!HB")
ACK_RANGE_STRUCT = struct.Struct("!QQ")
MAX_ACK_RANGES = 16
WINDOW_UPDATE_STRUCT = struct.Struct("!IQ")
CLOSE_STRUCT = struct.Struct("!H")

MAX_UINT64 = (1 << 64) - 1

def validate_uint64(value: int, name: str):
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")

    if not (0 <= value <= MAX_UINT64):
        raise ValueError(f"{name} must be uint64")

def validate_packet_body(packet_type: int, plaintext: bytes):
    if packet_type in (REGISTER, REGISTER_OK):
        if len(plaintext) != 0:
            raise ValueError("REGISTER/REGISTER_OK body must be empty")

    elif packet_type == DATA:
        decode_data_body(plaintext)

    elif packet_type == ACK:
        decode_ack_body(plaintext)

    elif packet_type == WINDOW_UPDATE:
        decode_window_update_body(plaintext)

    elif packet_type == CLOSE:
        decode_close_body(plaintext)

    elif packet_type in (PING, PONG):
        if len(plaintext) != 8:
            raise ValueError("PING/PONG body must be 8 bytes")

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

def encode_data_body(
    stream_id: int,
    offset: int,
    flags: int,
    data: bytes
) -> bytes:
    if type(stream_id) is not int or not (0 <= stream_id < (1 << 32)):
        raise ValueError("stream_id must be uint32")

    validate_uint64(offset, "offset")

    if type(flags) is not int or flags not in (0, 1):
        raise ValueError("DATA flags must be 0 or FIN (1)")

    if not isinstance(data, bytes):
        raise TypeError("DATA data must be bytes")

    if len(data) > MAX_DATA_PER_PACKET:
        raise ValueError("DATA data exceeds MAX_DATA_PER_PACKET")

    return DATA_STRUCT.pack(stream_id, offset, flags, len(data)) + data


def decode_data_body(body: bytes) -> tuple[int, int, int, bytes]:
    if not isinstance(body, bytes):
        raise TypeError("DATA body must be bytes")

    if len(body) < DATA_STRUCT.size:
        raise ValueError("DATA body is shorter than its 15-byte metadata")

    stream_id, offset, flags, data_len = DATA_STRUCT.unpack_from(body)
    data = body[DATA_STRUCT.size:]

    if flags not in (0, 1):
        raise ValueError("DATA flags contain unsupported bits")

    if data_len > MAX_DATA_PER_PACKET:
        raise ValueError("DATA data exceeds MAX_DATA_PER_PACKET")

    if data_len != len(data):
        raise ValueError("DATA data_len does not match actual data length")

    return stream_id, offset, flags, data

def _validate_ack_ranges(ranges: list[tuple[int, int]]) -> None:
    """Ranges are inclusive, sorted descending, and must not overlap."""
    if not isinstance(ranges, (list, tuple)):
        raise TypeError("ACK ranges must be a list or tuple")
    if not (1 <= len(ranges) <= MAX_ACK_RANGES):
        raise ValueError("ACK must contain 1 to 16 ranges")

    previous_start = None
    for ack_range in ranges:
        if not isinstance(ack_range, (list, tuple)) or len(ack_range) != 2:
            raise ValueError("ACK range must be (start, end)")
        start, end = ack_range
        validate_uint64(start, "ACK range start")
        validate_uint64(end, "ACK range end")
        if start > end:
            raise ValueError("ACK range start must not exceed end")
        # Higher-numbered range must precede lower-numbered range.
        # Equality would mean two inclusive ranges overlap.
        if previous_start is not None and end >= previous_start:
            raise ValueError("ACK ranges must be descending and nonoverlapping")
        previous_start = start

def encode_ack_body(
    ack_delay_ms: int,
    ranges: list[tuple[int, int]],
) -> bytes:
    """Encode ACK plaintext body only; not the encrypted UDP packet."""
    if type(ack_delay_ms) is not int or not (0 <= ack_delay_ms <= 65535):
        raise ValueError("ack_delay_ms must be uint16")
    _validate_ack_ranges(ranges)

    body = bytearray(ACK_HEADER_STRUCT.pack(ack_delay_ms, len(ranges)))
    for start, end in ranges:
        body.extend(ACK_RANGE_STRUCT.pack(start, end))
    return bytes(body)


def decode_ack_body(body: bytes) -> tuple[int, list[tuple[int, int]]]:
    """Decode and structurally validate ACK plaintext body."""
    if not isinstance(body, bytes):
        raise TypeError("ACK body must be bytes")
    if len(body) < ACK_HEADER_STRUCT.size:
        raise ValueError("ACK body missing 3-byte header")

    ack_delay_ms, range_count = ACK_HEADER_STRUCT.unpack_from(body)
    if not (1 <= range_count <= MAX_ACK_RANGES):
        raise ValueError("ACK range_count must be 1 to 16")
    expected_size = ACK_HEADER_STRUCT.size + ACK_RANGE_STRUCT.size * range_count
    if len(body) != expected_size:
        raise ValueError("ACK body length does not match range_count")

    ranges = []
    for i in range(range_count):
        offset = ACK_HEADER_STRUCT.size + i * ACK_RANGE_STRUCT.size
        ranges.append(ACK_RANGE_STRUCT.unpack_from(body, offset))
    _validate_ack_ranges(ranges)
    return ack_delay_ms, ranges


def encode_window_update_body(
    stream_id: int,
    max_offset: int
) -> bytes:
    """Đóng gói WINDOW_UPDATE plaintext body."""

    if type(stream_id) is not int or not (0 <= stream_id < (1 << 32)):
        raise ValueError("stream_id must be uint32")

    validate_uint64(max_offset, "max_offset")

    return WINDOW_UPDATE_STRUCT.pack(stream_id, max_offset)


def decode_window_update_body(
    body: bytes
) -> tuple[int, int]:
    """Giải mã WINDOW_UPDATE plaintext body."""

    if not isinstance(body, bytes):
        raise TypeError("WINDOW_UPDATE body must be bytes")

    if len(body) != WINDOW_UPDATE_STRUCT.size:
        raise ValueError("WINDOW_UPDATE body must be exactly 12 bytes")

    return WINDOW_UPDATE_STRUCT.unpack(body)

def encode_close_body(code: int) -> bytes:
    """Encode CLOSE plaintext body: code:u16."""

    if type(code) is not int or not (0 <= code <= 65535):
        raise ValueError("CLOSE code must be uint16")

    return CLOSE_STRUCT.pack(code)


def decode_close_body(body: bytes) -> int:
    """Decode CLOSE body containing exactly 2 bytes."""

    if not isinstance(body, bytes):
        raise TypeError("CLOSE body must be bytes")

    if len(body) != CLOSE_STRUCT.size:
        raise ValueError("CLOSE body must be exactly 2 bytes")

    (code,) = CLOSE_STRUCT.unpack(body)

    return code
