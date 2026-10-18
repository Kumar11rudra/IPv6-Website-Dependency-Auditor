"""Local servers + throwaway CA/certs to exercise every probe stage against real sockets."""
from __future__ import annotations
import asyncio
import dataclasses
import datetime
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config import settings

CFG = dataclasses.replace(settings, tcp_timeout_s=1.0, tls_timeout_s=1.0, http_timeout_s=1.0)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name("test-ca")).issuer_name(_name("test-ca"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue(ca_key, ca_cert, host, tmp_path, name="srv"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(host)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cp, kp = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cp), str(kp)


def server_ctx(cert, key):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.load_cert_chain(cert, key)
    return c


def client_ctx_trusting(ca_cert, tmp_path):
    p = tmp_path / "ca.pem"
    p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ssl.create_default_context(cafile=str(p))


def ipv6_loopback_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def closed_port(host="127.0.0.1") -> int:
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_response(code: int) -> bytes:
    return f"HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()


async def start(behavior: str, code: int = 200, ssl_ctx=None, host="127.0.0.1"):
    """behavior: ok | drop | garbage | silent"""
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            if behavior == "ok":
                writer.write(http_response(code)); await writer.drain()
            elif behavior == "garbage":
                writer.write(b"not http at all\r\n\r\n"); await writer.drain()
            elif behavior == "silent":
                await asyncio.sleep(5)
        except Exception:  # noqa: BLE001
            pass
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, host, 0, ssl=ssl_ctx)
    return srv, srv.sockets[0].getsockname()[1]
