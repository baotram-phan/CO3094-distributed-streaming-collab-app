"""TLS contexts cho kênh bootstrap; không làm thay giao thức UDP."""

"Cấu hình TLS cho client và server"
import ssl
from pathlib import Path


def server_context(certfile: Path, keyfile: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context


def client_context(trusted_certfile: Path) -> ssl.SSLContext:
    # verify_mode=CERT_REQUIRED và check_hostname=True theo mặc định.
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(trusted_certfile)
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
