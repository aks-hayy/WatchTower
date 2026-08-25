"""Transport payload extraction that excludes link-layer padding."""

from __future__ import annotations

import scapy.all as scapy
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6


def application_payload(packet, maximum: int = 16 * 1024 * 1024) -> bytes:
    if packet is None:
        return b""
    # Rust-assisted replay already has a length-bounded application payload.
    # Reading it directly avoids materializing a Scapy layer graph for every
    # packet while preserving the same link-padding exclusion policy.
    fast_payload = getattr(packet, "application_payload", None)
    if isinstance(fast_payload, bytes):
        return fast_payload[:maximum]
    layer = next((packet[item] for item in (TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply) if item in packet), None)
    if layer is None:
        return b""
    raw = bytes(layer.payload)
    if not raw:
        return b""
    declared = _declared_payload_length(packet, layer)
    if declared <= 0:
        return b""
    return raw[:min(int(maximum), declared)]


def _declared_payload_length(packet, layer) -> int:
    try:
        if IP in packet:
            network = packet[IP]
            network_payload = int(network.len or len(network)) - int(network.ihl or 5) * 4
        elif IPv6 in packet:
            network_payload = int(packet[IPv6].plen or len(bytes(packet[IPv6].payload)))
        else:
            # Non-IP transports use an explicit Raw layer; Padding alone is never payload.
            return len(bytes(layer[scapy.Raw].load)) if scapy.Raw in layer else 0
        if TCP in packet:
            return max(0, network_payload - int(packet[TCP].dataofs or 5) * 4)
        if UDP in packet:
            udp_length = packet[UDP].len
            if udp_length is None:
                # Scapy fixtures and generated packets do not populate UDP.len
                # until serialization.  Raw excludes Ethernet padding here.
                return len(bytes(packet[UDP][scapy.Raw].load)) if scapy.Raw in packet[UDP] else 0
            return max(0, min(network_payload - 8, int(udp_length) - 8))
        if ICMP in packet or ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
            return max(0, network_payload - 8)
    except (AttributeError, TypeError, ValueError):
        return 0
    return 0
