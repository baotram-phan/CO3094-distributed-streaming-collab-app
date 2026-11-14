"""Tạo self-signed TLS certificate CHỈ để thử nghiệm local/LAN.

python -m scripts.gen_cert
Cài phụ thuộc (chỉ phục vụ sinh chứng chỉ): python -m pip install cryptography
"""

import argparse
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]


def generate_certificate(directory: Path, *, force: bool = False) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"

    if cert_path.exists() or key_path.exists():
        if not force:
            if cert_path.exists() and key_path.exists():
                return cert_path, key_path
            raise FileExistsError(
                "Chỉ thấy một trong hai file cert/key; kiểm tra hoặc dùng --force."
            )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        key_path.chmod(0o600)  # POSIX; Windows cần bảo vệ ACL/thư mục riêng
    except OSError:
        pass
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Sinh chứng chỉ TLS tự ký cho demo")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Tạo lại chứng chỉ (client phải cập nhật file tin cậy)",
    )
    parser.add_argument("--dir", type=Path, default=ROOT / "certs")
    args = parser.parse_args()
    cert_path, key_path = generate_certificate(args.dir, force=args.force)
    print("TLS certificate:", cert_path)
    print("TLS private key: ", key_path)
    print(
        "LƯU Ý: Không commit/chia sẻ private key; chỉ demo localhost hoặc địa chỉ SAN đã cấp."
    )


if __name__ == "__main__":
    main()
