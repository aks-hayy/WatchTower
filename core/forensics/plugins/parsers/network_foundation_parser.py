"""Foundational LAN, IPv6, and transport metadata parsers."""

from typing import Any, Dict
import re

import scapy.all as scapy
from scapy.layers.inet import ICMP, UDP
from scapy.layers.inet6 import (
    ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6EchoRequest,
    ICMPv6EchoReply, ICMPv6NDOptSrcLLAddr,
)

from core.forensics.base import BaseParser


class ARPNDPParser(BaseParser):
    name = "ARP and NDP Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        timestamp = float(getattr(packet, "time", 0.0) or 0.0)
        if scapy.ARP in packet:
            arp = packet[scapy.ARP]
            metadata = {
                "arp_operation": int(arp.op),
                "arp_sender_ip": str(arp.psrc),
                "arp_target_ip": str(arp.pdst),
                "arp_sender_mac": str(arp.hwsrc),
            }
            return {
                "identities": {"mac": str(arp.hwsrc)},
                "metadata": metadata,
                "observations": [{
                    "timestamp": timestamp, "source_type": "network",
                    "device_id": (context or {}).get("device_id"),
                    "observation_type": "arp", "subject": str(arp.psrc),
                    "peer": str(arp.pdst), "metadata": metadata,
                }],
            }
        for layer, event_name in (
            (ICMPv6ND_NS, "ndp_neighbor_solicitation"),
            (ICMPv6ND_NA, "ndp_neighbor_advertisement"),
            (ICMPv6ND_RA, "ipv6_router_advertisement"),
        ):
            if packet.haslayer(layer):
                value = packet[layer]
                metadata = {"icmpv6_type": int(value.type), "target": str(getattr(value, "tgt", ""))}
                source_ip = str(packet[scapy.IPv6].src) if packet.haslayer(scapy.IPv6) else ""
                source_mac = None
                if packet.haslayer(ICMPv6NDOptSrcLLAddr):
                    source_mac = str(packet[ICMPv6NDOptSrcLLAddr].lladdr)
                elif packet.haslayer(scapy.Ether):
                    # NDP is link-local neighbor traffic, so this is a direct
                    # binding unlike an arbitrary routed IP frame.
                    source_mac = str(packet[scapy.Ether].src)
                if source_ip and source_mac:
                    metadata.update({"ndp_sender_ip": source_ip, "ndp_sender_mac": source_mac})
                if layer is ICMPv6ND_RA:
                    metadata.update({
                        "router_lifetime": int(getattr(value, "routerlifetime", 0)),
                        "managed": int(getattr(value, "M", 0)),
                        "other": int(getattr(value, "O", 0)),
                    })
                result = {"metadata": {"ndp_event": event_name, **metadata}}
                if source_mac:
                    result["identities"] = {"mac": source_mac}
                return result
        return {}


class ICMPMetadataParser(BaseParser):
    name = "ICMP Metadata Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if ICMP in packet:
            layer = packet[ICMP]
            return {"metadata": {
                "icmp_type": int(layer.type), "icmp_code": int(layer.code),
                "icmp_id": int(getattr(layer, "id", 0) or 0),
                "icmp_sequence": int(getattr(layer, "seq", 0) or 0),
            }}
        for layer in (ICMPv6EchoRequest, ICMPv6EchoReply):
            if packet.haslayer(layer):
                value = packet[layer]
                return {"metadata": {
                    "icmpv6_type": int(value.type),
                    "icmp_id": int(getattr(value, "id", 0) or 0),
                    "icmp_sequence": int(getattr(value, "seq", 0) or 0),
                }}
        return {}


class DHCPv6Parser(BaseParser):
    name = "DHCPv6 Parser"
    watched_ports = (546, 547)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if UDP not in packet or {int(packet[UDP].sport), int(packet[UDP].dport)}.isdisjoint({546, 547}):
            return {}
        payload = bytes(packet[UDP].payload)
        if len(payload) < 4:
            return {}
        message_names = {
            1: "solicit", 2: "advertise", 3: "request", 5: "renew",
            6: "rebind", 7: "reply", 8: "release", 11: "information-request",
        }
        return {"metadata": {
            "dhcpv6_message": message_names.get(payload[0], f"type-{payload[0]}"),
            "dhcpv6_transaction_id": payload[1:4].hex(),
        }}


class LinkDiscoveryParser(BaseParser):
    name = "LLDP and CDP Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if scapy.Ether in packet and int(packet[scapy.Ether].type) == 0x88CC:
            payload = bytes(packet[scapy.Ether].payload)
            text = re.sub(rb"[^ -~]+", b" ", payload).decode("ascii", errors="ignore").strip()
            return {"metadata": {"discovery_protocol": "LLDP", "lldp_text": text[:256]}}
        raw = bytes(packet)
        if b"\x01\x00\x0c\xcc\xcc\xcc" in raw[:32] or b"Cisco" in raw:
            text = re.sub(rb"[^ -~]+", b" ", raw).decode("ascii", errors="ignore").strip()
            return {"metadata": {"discovery_protocol": "CDP", "cdp_text": text[:256]}}
        return {}


class QUICMetadataParser(BaseParser):
    name = "QUIC Metadata Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if UDP not in packet or 443 not in {int(packet[UDP].sport), int(packet[UDP].dport)}:
            return {}
        payload = bytes(packet[UDP].payload)
        if len(payload) < 7 or not payload[0] & 0x80:
            return {}
        version = int.from_bytes(payload[1:5], "big")
        dcid_length = payload[5]
        if dcid_length > 20 or len(payload) < 6 + dcid_length + 1:
            return {}
        cursor = 6
        dcid = payload[cursor:cursor + dcid_length].hex()
        cursor += dcid_length
        scid_length = payload[cursor]
        cursor += 1
        if scid_length > 20 or len(payload) < cursor + scid_length:
            return {}
        return {"metadata": {
            "application_protocol": "QUIC", "quic_version": f"0x{version:08x}",
            "quic_dcid": dcid, "quic_scid": payload[cursor:cursor + scid_length].hex(),
        }}
