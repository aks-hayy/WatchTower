"""
Scanning and reconnaissance attack modules.

Tests against Watchtower detectors:
- watchtower.recon (port_scan, syn_flood, host_scan)
- watchtower.stateful.host (recon.port_scan, recon.host_scan)
- watchtower.lan.trust (arp binding conflicts)
"""

import random
import socket
import struct
import time
from typing import Optional

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, SCAN_RATE, SCAN_PORT_RANGE, SCAN_HOST_COUNT


class TCPConnectScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("tcp_connect_scan", "scanning", target_ip)
        self.ports = ports or list(range(SCAN_PORT_RANGE[0], min(SCAN_PORT_RANGE[1], 1024)))

    def execute(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((self.target_ip, port))
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "SYN",
                    "result": "open" if result == 0 else "closed",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "SYN",
                    "result": "error",
                    "error": str(e),
                })
            time.sleep(SCAN_RATE)


class TCPSYNScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("tcp_syn_scan", "scanning", target_ip)
        self.ports = ports or list(range(SCAN_PORT_RANGE[0], min(SCAN_PORT_RANGE[1], 1024)))

    def execute(self) -> None:
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                pkt = IP(dst=self.target_ip) / TCP(sport=src_port, dport=port, flags="S")
                response = sr1(pkt, timeout=0.3)
                flags = str(response[TCP].flags) if response and response.haslayer(TCP) else "no-response"
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "SYN",
                    "response_flags": flags,
                })
                time.sleep(SCAN_RATE)
        except ImportError:
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((self.target_ip, port))
                    self.log_packet({
                        "protocol": "TCP",
                        "dst_ip": self.target_ip,
                        "dst_port": port,
                        "flags": "SYN",
                        "method": "connect_fallback",
                    })
                    s.close()
                except Exception:
                    pass
                time.sleep(SCAN_RATE)


class TCPXMASScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("tcp_xmas_scan", "scanning", target_ip)
        self.ports = ports or list(range(1, 100))

    def execute(self) -> None:
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                pkt = IP(dst=self.target_ip) / TCP(
                    sport=src_port, dport=port, flags="FPU"
                )
                response = sr1(pkt, timeout=0.3)
                flags = "no-response"
                if response and response.haslayer(TCP):
                    flags = str(response[TCP].flags)
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "FPU",
                    "response_flags": flags,
                })
                time.sleep(SCAN_RATE)
        except ImportError:
            self.logger.warning("Scapy not available, using socket fallback")
            self.execute_socket_fallback()

    def execute_socket_fallback(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((self.target_ip, port))
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "FPU",
                    "method": "socket_fallback",
                })
                s.close()
            except Exception:
                pass
            time.sleep(SCAN_RATE)


class TCPNullScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("tcp_null_scan", "scanning", target_ip)
        self.ports = ports or list(range(1, 100))

    def execute(self) -> None:
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                pkt = IP(dst=self.target_ip) / TCP(
                    sport=src_port, dport=port, flags=""
                )
                response = sr1(pkt, timeout=0.3)
                flags = "no-response"
                if response and response.haslayer(TCP):
                    flags = str(response[TCP].flags)
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "NONE",
                    "response_flags": flags,
                })
                time.sleep(SCAN_RATE)
        except ImportError:
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "flags": "NONE",
                    "method": "no_response",
                })
                time.sleep(SCAN_RATE)


class UDPScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("udp_scan", "scanning", target_ip)
        self.ports = ports or [53, 67, 68, 69, 123, 135, 137, 138, 161, 162,
                               445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]

    def execute(self) -> None:
        try:
            from scapy.all import IP, UDP, sr1, conf
            conf.verb = 0
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                pkt = IP(dst=self.target_ip) / UDP(
                    sport=random.randint(1024, 65535), dport=port
                ) / b"\x00" * 16
                response = sr1(pkt, timeout=0.5)
                self.log_packet({
                    "protocol": "UDP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "responded": response is not None,
                })
                time.sleep(SCAN_RATE)
        except ImportError:
            for port in self.ports:
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.5)
                    s.sendto(b"\x00" * 16, (self.target_ip, port))
                    self.log_packet({
                        "protocol": "UDP",
                        "dst_ip": self.target_ip,
                        "dst_port": port,
                        "method": "socket_fallback",
                    })
                    s.close()
                except Exception:
                    pass
                time.sleep(SCAN_RATE)


class HorizontalScan(BaseAttack):
    def __init__(self, base_ip: str = "127.0.0.1", port: int = 80, count: int = SCAN_HOST_COUNT):
        super().__init__("horizontal_scan", "scanning", base_ip)
        self.port = port
        self.count = count

    def execute(self) -> None:
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
            octets = self.target_ip.split(".")
            base = ".".join(octets[:3]) + "."
            src_port = random.randint(1024, 65535)
            for i in range(1, self.count + 1):
                if self._stop_event.is_set():
                    break
                target = f"{base}{i}"
                pkt = IP(dst=target) / TCP(sport=src_port, dport=self.port, flags="S")
                try:
                    response = sr1(pkt, timeout=0.3)
                    self.log_packet({
                        "protocol": "TCP",
                        "dst_ip": target,
                        "dst_port": self.port,
                        "flags": "SYN",
                        "responded": response is not None,
                    })
                except Exception:
                    self.log_packet({
                        "protocol": "TCP",
                        "dst_ip": target,
                        "dst_port": self.port,
                        "flags": "SYN",
                        "responded": False,
                    })
                time.sleep(SCAN_RATE)
        except ImportError:
            octets = self.target_ip.split(".")
            base = ".".join(octets[:3]) + "."
            for i in range(1, self.count + 1):
                if self._stop_event.is_set():
                    break
                target = f"{base}{i}"
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((target, self.port))
                    s.close()
                except Exception:
                    pass
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": target,
                    "dst_port": self.port,
                    "method": "socket_fallback",
                })
                time.sleep(SCAN_RATE)


class ARPScan(BaseAttack):
    def __init__(self, base_ip: str = "127.0.0.1", count: int = 25):
        super().__init__("arp_scan", "scanning", base_ip)
        self.count = count

    def execute(self) -> None:
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0
            octets = self.target_ip.split(".")
            subnet = ".".join(octets[:3]) + ".0/24"
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(packet, timeout=2, verbose=0)
            for _, rcvd in answered:
                self.log_packet({
                    "protocol": "ARP",
                    "src_ip": rcvd.psrc,
                    "src_mac": rcvd.hwsrc,
                    "type": "ARP_REQUEST",
                })
        except ImportError:
            self.logger.warning("Scapy not available for ARP scan")


class ServiceEnumeration(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("service_enumeration", "scanning", target_ip)
        self.services = [
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
            (53, "DNS"), (80, "HTTP"), (110, "POP3"), (111, "RPCBind"),
            (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"), (443, "HTTPS"),
            (445, "SMB"), (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"),
            (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
            (8080, "HTTP-ALT"), (8443, "HTTPS-ALT"),
        ]

    def execute(self) -> None:
        for port, service_name in self.services:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                banner = ""
                if s.connect_ex((self.target_ip, port)) == 0:
                    try:
                        s.settimeout(1.0)
                        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                    except socket.timeout:
                        pass
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "service": service_name,
                    "banner": banner[:200] if banner else "",
                    "open": bool(banner),
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "service": service_name,
                    "error": str(e),
                })
            time.sleep(SCAN_RATE)


class SSHPortScan(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("ssh_nonstandard", "scanning", target_ip)
        self.ports = ports or [8022, 9022, 2222, 4422, 10022, 22022]

    def execute(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((self.target_ip, port)) == 0:
                    s.send(b"SSH-2.0-OpenSSH_8.9\r\n")
                    try:
                        banner = s.recv(1024)
                    except socket.timeout:
                        pass
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "payload": "SSH-2.0 banner on nonstandard port",
                    "test_for": "protocol.nonstandard_service",
                })
                s.close()
            except Exception:
                pass
            time.sleep(SCAN_RATE)


class RDPNonstandardPort(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, ports: Optional[list] = None):
        super().__init__("rdp_nonstandard", "scanning", target_ip)
        self.ports = ports or [3390, 4389, 5389, 8389]

    def execute(self) -> None:
        for port in self.ports:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((self.target_ip, port)) == 0:
                    tpkt_header = b"\x03\x00"
                    x224_cr = b"\xe0\x00\x00\x00"
                    s.send(tpkt_header + struct.pack(">H", len(tpkt_header) + len(x224_cr)) + x224_cr)
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": self.target_ip,
                    "dst_port": port,
                    "payload": "RDP TPKT/X.224 on nonstandard port",
                    "test_for": "protocol.nonstandard_service",
                })
                s.close()
            except Exception:
                pass
            time.sleep(SCAN_RATE)
