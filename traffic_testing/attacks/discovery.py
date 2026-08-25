"""
Network discovery and enumeration simulation modules.

Tests against Watchtower parsers and detectors:
- watchtower.discovery.parser (SSDP, mDNS, NBNS)
- watchtower.arp.parser (ARP binding extraction)
- watchtower.dhcp.parser (hostname extraction)
- watchtower.smb.parser (NetBIOS name extraction)
"""

import os
import random
import socket
import struct
import time

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, GATEWAY_IP


class SSDPDiscovery(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("ssdp_discovery", "discovery", target_ip)

    def execute(self) -> None:
        for i in range(20):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                ssdp_request = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 3\r\n"
                    "ST: ssdp:all\r\n"
                    "\r\n"
                )
                s.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))
                try:
                    response, addr = s.recvfrom(1024)
                    self.log_packet({
                        "protocol": "SSDP",
                        "dst_ip": "239.255.255.250",
                        "dst_port": 1900,
                        "type": "M-SEARCH",
                        "response_from": addr[0] if addr else None,
                        "test_for": "ssdp.device_discovery",
                    })
                except socket.timeout:
                    self.log_packet({
                        "protocol": "SSDP",
                        "dst_ip": "239.255.255.250",
                        "dst_port": 1900,
                        "type": "M-SEARCH",
                    })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "SSDP", "error": str(e)})
            time.sleep(0.5)

    def execute_with_target(self) -> None:
        for i in range(10):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                ssdp_request = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    f"HOST: {self.target_ip}:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 2\r\n"
                    "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
                    "\r\n"
                )
                s.sendto(ssdp_request.encode(), (self.target_ip, 1900))
                try:
                    response, addr = s.recvfrom(1024)
                    server = ""
                    for line in response.decode(errors="replace").split("\r\n"):
                        if line.upper().startswith("SERVER:"):
                            server = line.split(":", 1)[1].strip()
                    self.log_packet({
                        "protocol": "SSDP",
                        "dst_ip": self.target_ip,
                        "dst_port": 1900,
                        "type": "M-SEARCH",
                        "server_info": server,
                        "response_from": addr[0] if addr else None,
                    })
                except socket.timeout:
                    pass
                s.close()
            except Exception:
                pass
            time.sleep(0.5)


class MDNSDiscovery(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("mdns_discovery", "discovery", target_ip)

    def execute(self) -> None:
        queries = [
            "_http._tcp.local",
            "_smb._tcp.local",
            "_ssh._tcp.local",
            "_ftp._tcp.local",
            "_daap._tcp.local",
            "_airplay._tcp.local",
            "_ipp._tcp.local",
            "_printer._tcp.local",
            "_device-info._tcp.local",
            "_raop._tcp.local",
        ]
        for query in queries:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                dns_query = self._build_mdns_query(query)
                s.sendto(dns_query, ("224.0.0.251", 5353))
                try:
                    response, addr = s.recvfrom(1024)
                    self.log_packet({
                        "protocol": "mDNS",
                        "dst_ip": "224.0.0.251",
                        "dst_port": 5353,
                        "query_name": query,
                        "response_from": addr[0] if addr else None,
                        "test_for": "mdns.device_discovery",
                    })
                except socket.timeout:
                    self.log_packet({
                        "protocol": "mDNS",
                        "dst_ip": "224.0.0.251",
                        "dst_port": 5353,
                        "query_name": query,
                    })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "mDNS", "error": str(e)})
            time.sleep(0.3)

    def _build_mdns_query(self, name: str) -> bytes:
        tx_id = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tx_id, 0x8400, 1, 0, 0, 0)
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + struct.pack(">HH", 12, 1)
        return header + question


class NBNSDiscovery(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("nbns_discovery", "discovery", target_ip)

    def execute(self) -> None:
        names = ["WORKGROUP", "DC01", "FILESERVER", "PRINTSRV", "WEBSRV"]
        for name in names:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                nbns_query = self._build_nbns_query(name)
                s.sendto(nbns_query, (self.target_ip, 137))
                try:
                    response, addr = s.recvfrom(1024)
                    self.log_packet({
                        "protocol": "NBNS",
                        "dst_ip": self.target_ip,
                        "dst_port": 137,
                        "query_name": name,
                        "response_from": addr[0] if addr else None,
                        "test_for": "nbns.name_discovery",
                    })
                except socket.timeout:
                    self.log_packet({
                        "protocol": "NBNS",
                        "dst_ip": self.target_ip,
                        "dst_port": 137,
                        "query_name": name,
                    })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "NBNS", "error": str(e)})
            time.sleep(0.5)

    def _build_nbns_query(self, name: str) -> bytes:
        encoded_name = b""
        name_padded = name.ljust(15, "\x00").upper()[:15]
        for char in name_padded:
            byte = ord(char)
            encoded_name += bytes([0x41 + (byte >> 4), 0x41 + (byte & 0x0F)])
        encoded_name += b"\x00"
        header = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0110, 1, 0, 0, 0)
        question = b"\x20" + encoded_name + struct.pack(">HH", 0x0020, 1)
        return header + question


class DHCPDiscovery(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("dhcp_discovery", "discovery", target_ip)

    def execute(self) -> None:
        for i in range(5):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2.0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                discover = self._build_dhcp_discover()
                s.sendto(discover, ("255.255.255.255", 67))
                self.log_packet({
                    "protocol": "DHCP",
                    "dst_ip": "255.255.255.255",
                    "dst_port": 67,
                    "type": "DISCOVER",
                    "hostname": f"attacker-pc-{i}",
                    "test_for": "dhcp.hostname_extraction",
                })
                s.close()
            except Exception as e:
                self.log_packet({"protocol": "DHCP", "error": str(e)})
            time.sleep(1.0)

    def _build_dhcp_discover(self) -> bytes:
        op = b"\x01"
        htype = b"\x01"
        hlen = b"\x06"
        hops = b"\x00"
        xid = os.urandom(4)
        secs = b"\x00\x00"
        flags = b"\x00\x00"
        ciaddr = b"\x00\x00\x00\x00"
        yiaddr = b"\x00\x00\x00\x00"
        siaddr = b"\x00\x00\x00\x00"
        giaddr = b"\x00\x00\x00\x00"
        chaddr = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]) + b"\x00" * 10
        sname = b"\x00" * 64
        file_ = b"\x00" * 128
        magic = b"\x63\x82\x53\x63"
        options = b"\x35\x01\x01"
        options += b"\x3d\x06\x01" + bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        hostname = b"attacker-pc"
        options += b"\x0c" + bytes([len(hostname)]) + hostname
        options += b"\x37\x04\x01\x03\x06\x2a"
        options += b"\xff"
        return op + htype + hlen + hops + xid + secs + flags + ciaddr + yiaddr + siaddr + giaddr + chaddr + sname + file_ + magic + options


class ARPPoisoning(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, gateway_ip: str = GATEWAY_IP):
        super().__init__("arp_poisoning", "discovery", target_ip)
        self.gateway_ip = gateway_ip

    def execute(self) -> None:
        try:
            from scapy.all import ARP, Ether, send, conf
            conf.verb = 0
            fake_mac = f"de:ad:be:ef:{random.randint(10,99):02x}:{random.randint(10,99):02x}"
            for i in range(15):
                if self._stop_event.is_set():
                    break
                arp_reply = ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    hwsrc=fake_mac,
                    pdst=self.target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
                send(arp_reply, verbose=0)
                self.log_packet({
                    "protocol": "ARP",
                    "src_ip": self.gateway_ip,
                    "src_mac": fake_mac,
                    "dst_ip": self.target_ip,
                    "type": "Gratuitous ARP Reply",
                    "op": "ARP Reply (op=2)",
                    "test_for": "network.arp.binding_conflict",
                    "note": f"Claiming to be {self.gateway_ip} with MAC {fake_mac}",
                })
                time.sleep(2)
        except ImportError:
            self.logger.warning("Scapy not available for ARP poisoning")
