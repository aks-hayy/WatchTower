"""Local certificate authority and enrollment helpers for mesh mTLS."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def certificate_fingerprint(certificate_pem: bytes) -> str:
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    return certificate.fingerprint(hashes.SHA256()).hex()


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


class MeshAuthority:
    def __init__(self, data_dir: str):
        self.directory = Path(data_dir) / "mesh" / "controller"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.directory / "ca.key"
        self.ca_cert_path = self.directory / "ca.pem"
        self.server_key_path = self.directory / "server.key"
        self.server_cert_path = self.directory / "server.pem"

    @property
    def ready(self) -> bool:
        return all(path.exists() for path in (self.ca_key_path, self.ca_cert_path, self.server_key_path, self.server_cert_path))

    def initialize(self, host: str = "127.0.0.1") -> None:
        if self.ready:
            return
        now = datetime.now(timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WatchTower Mesh Local CA")])
        ca_cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        server_key = ec.generate_private_key(ec.SECP256R1())
        names = [x509.DNSName("localhost")]
        for name in {host, "127.0.0.1"}:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                names.append(x509.DNSName(name))
        server_cert = (
            x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_cert.subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        self._write_private(self.ca_key_path, ca_key)
        self.ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        self._write_private(self.server_key_path, server_key)
        self.server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    def rotate_server_certificate(self, host: str = "127.0.0.1") -> str:
        """Rotate only the controller listener certificate while retaining node trust."""
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            raise RuntimeError("Mesh certificate authority is not initialized")
        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        now = datetime.now(timezone.utc)
        server_key = ec.generate_private_key(ec.SECP256R1())
        names = [x509.DNSName("localhost")]
        for name in {host, "127.0.0.1"}:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                names.append(x509.DNSName(name))
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        temporary_key = self.server_key_path.with_suffix(".key.tmp")
        temporary_cert = self.server_cert_path.with_suffix(".pem.tmp")
        self._write_private(temporary_key, server_key)
        temporary_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        temporary_key.replace(self.server_key_path)
        temporary_cert.replace(self.server_cert_path)
        return certificate_fingerprint(self.server_cert_path.read_bytes())

    @staticmethod
    def _write_private(path: Path, key) -> None:
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def ca_certificate(self) -> bytes:
        return self.ca_cert_path.read_bytes()

    def server_credentials(self) -> Tuple[bytes, bytes, bytes]:
        return self.server_key_path.read_bytes(), self.server_cert_path.read_bytes(), self.ca_cert_path.read_bytes()

    def sign_csr(self, csr_pem: bytes, node_id: str) -> bytes:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("Invalid mesh enrollment CSR")
        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
            .issuer_name(ca_cert.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM)


def new_node_csr(node_id: str) -> Tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
        ).sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        csr.public_bytes(serialization.Encoding.PEM),
    )
