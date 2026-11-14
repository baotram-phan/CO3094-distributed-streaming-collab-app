"""A1.5 ONLY: minimal test adapter for encrypted REGISTER/REGISTER_OK.

NOT B's real UDP transport, NOT a production reliability implementation.
This intentionally does not implement DATA/ACK/streams/CUBIC/heartbeat.
Remove/replace this adapter when integrating B's codec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = 0x4E43
VERSION = 1
REGISTER = 0x01
REGISTER_OK = 0x02
MAX_DATAGRAM = 1200
HEADER = struct.Struct("!HBBQQ")  # 20 bytes
TAG_SIZE = 16


class BadDatagram(ValueError):
    """Wire format / AEAD verification failed."""


def make_register_packet(
    packet_type: int, conn_id: int, pkt_num: int, key: bytes
) -> bytes:
    """REGISTER types only. Encodes empty plaintext with AES-256-GCM.

    Each caller MUST allocate unique packet numbers per key/direction.
    """
    if packet_type not in (REGISTER, REGISTER_OK):
        raise ValueError("Only REGISTER/REGISTER_OK in A1.5 adapter")
    if not (0 < conn_id < 2**64 and 0 <= pkt_num < 2**64):
        raise ValueError("Invalid conn_id or packet number")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM key must be 32 bytes")
    header = HEADER.pack(MAGIC, VERSION, packet_type, conn_id, pkt_num)
    nonce = b"\x00" * 4 + pkt_num.to_bytes(8, "big")
    return header + AESGCM(key).encrypt(nonce, b"", header)


def peek_header(datagram: bytes) -> tuple[int, int, int]:
    """Untrusted parsing only; returned values are NOT authenticated yet."""
    if len(datagram) != HEADER.size + TAG_SIZE:
        raise BadDatagram("REGISTER must be 36 bytes")
    magic, version, kind, conn_id, pkt_num = HEADER.unpack_from(datagram)
    if magic != MAGIC or version != VERSION or kind not in (REGISTER, REGISTER_OK):
        raise BadDatagram("Wrong header")
    if conn_id == 0:
        raise BadDatagram("ConnID must be nonzero")
    return kind, conn_id, pkt_num


def verify_register_packet(
    datagram: bytes, key: bytes, *, expected_type: int
) -> tuple[int, int]:
    kind, conn_id, pkt_num = peek_header(datagram)
    if kind != expected_type:
        raise BadDatagram("Unexpected packet type")
    if len(key) != 32:
        raise BadDatagram("Bad key")
    nonce = b"\x00" * 4 + pkt_num.to_bytes(8, "big")
    try:
        plaintext = AESGCM(key).decrypt(
            nonce, datagram[HEADER.size :], datagram[: HEADER.size]
        )
    except (InvalidTag, ValueError) as exc:
        raise BadDatagram("Invalid AEAD tag") from exc
    if plaintext != b"":
        raise BadDatagram("REGISTER body must be empty")
    return conn_id, pkt_num


@dataclass
class ReplayWindow:
    """Small reference replay window allowing out-of-order pn within 4096 slots."""

    capacity: int = 4096
    highest: int = -1
    seen: set[int] = field(default_factory=set)

    def can_accept(self, pkt_num: int) -> bool:
        return (
            pkt_num >= 0
            and pkt_num not in self.seen
            and (self.highest < 0 or pkt_num > self.highest - self.capacity)
        )

    def commit(self, pkt_num: int) -> None:
        if not self.can_accept(pkt_num):
            raise BadDatagram("Replay or too old")
        self.highest = max(self.highest, pkt_num)
        self.seen.add(pkt_num)
        self.seen = {pn for pn in self.seen if pn > self.highest - self.capacity}
