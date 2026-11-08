
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def make_nonce(pkt_num: int) -> bytes:
    
    if type(pkt_num) is not int:
        raise ValueError("pkt_num must be an integer")

    if not (0 <= pkt_num < (1 << 64)):
        raise ValueError("pkt_num must be uint64")

    prefix = b"\x00" * 4

    packet_number_bytes = pkt_num.to_bytes(
        8, byteorder="big"
    )

    return prefix + packet_number_bytes


def encrypt_payload(
    key: bytes,
    pkt_num: int,
    plaintext: bytes,
    header: bytes
) -> bytes:
    
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    if len(header) != 20:
        raise ValueError("Invalid header size")

    nonce = make_nonce(pkt_num)

    aesgcm = AESGCM(key)

    return aesgcm.encrypt(
        nonce,
        plaintext,
        header
    )


def decrypt_payload(
    key: bytes,
    pkt_num: int,
    ciphertext: bytes,
    header: bytes
) -> bytes:

    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    if len(header) != 20:
        raise ValueError("Invalid header size")

    if len(ciphertext) < 16:
        raise ValueError("Missing GCM authentication tag")

    nonce = make_nonce(pkt_num)

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        header
    )
