"""Low-overhead packet view for Rust-assisted offline PCAP analysis.

The view intentionally implements only the Scapy surface used by WatchTower's
lightweight parsers and detectors.  Complex protocol parsers still receive a
real Scapy packet through the bounded deep-decode fallback in the engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address
from typing import Optional

from core.packet_engine.schemas import PacketEvent


class _Payload:
    def __init__(self, value: bytes):
        self.load = value

    def __bytes__(self) -> bytes:
        return self.load

    def __len__(self) -> int:
        return len(self.load)

    def __bool__(self) -> bool:
        return bool(self.load)


class _TcpFlags:
    _NAMES = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"))

    def __init__(self, value: int):
        self.value = value

    def __int__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return "".join(name for mask, name in self._NAMES if self.value & mask)


@dataclass
class _Network:
    src: str
    dst: str
    ttl: int = 0
    hlim: int = 0


@dataclass
class _Transport:
    sport: int
    dport: int
    payload: _Payload
    seq: int = 0
    ack: int = 0
    flags: object = ""


@dataclass
class _Ethernet:
    src: str
    dst: str
    type: int
    payload: _Payload


@dataclass
class _Arp:
    op: int
    psrc: str
    pdst: str
    hwsrc: str
    hwdst: str


@dataclass
class _Icmp:
    type: int
    code: int
    id: int = 0
    seq: int = 0


def _mac(raw: bytes) -> str:
    return ":".join(f"{value:02x}" for value in raw)


class FastPacket:
    """A parsed L2-L4 view backed by a Rust ``PacketEvent`` raw frame."""

    def __init__(self, event: PacketEvent):
        self.time = float(event.timestamp)
        self.raw = bytes(event.raw or b"")
        self.link_type = str(event.link_type or "ethernet")
        self.size = int(event.size or len(self.raw))
        self.src_ip = str(event.src_ip)
        self.dst_ip = str(event.dst_ip)
        self.sport = int(event.src_port or 0)
        self.dport = int(event.dst_port or 0)
        self.protocol_number = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58, "ARP": 254}.get(
            str(event.protocol).upper(), 0
        )
        self.application_payload = b""
        self.transport: Optional[_Transport] = None
        self.network: Optional[_Network] = None
        self.ethernet: Optional[_Ethernet] = None
        self.arp: Optional[_Arp] = None
        self.icmp: Optional[_Icmp] = None
        self.ip_version = 0
        self._parse()

    @property
    def valid(self) -> bool:
        return self.ip_version in {4, 6} or self.arp is not None

    def __bytes__(self) -> bytes:
        return self.raw

    def __len__(self) -> int:
        return self.size

    @property
    def protocol(self) -> str:
        if self.protocol_number == 6:
            return "TCP"
        if self.protocol_number == 17:
            return "UDP"
        if self.arp is not None:
            return "ARP"
        return "OTHER"

    @property
    def flow_id(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.sport, self.dport, self.protocol)

    @property
    def flags(self) -> str:
        return str(self.transport.flags) if self.transport else ""

    @property
    def sequence(self) -> int:
        return int(self.transport.seq) if self.transport else 0

    @property
    def hop_limit(self) -> int:
        if not self.network:
            return 0
        return int(self.network.ttl or self.network.hlim or 0)

    def _parse(self) -> None:
        raw = self.raw
        if self.link_type == "raw-ip":
            if not raw:
                return
            if raw[0] >> 4 == 4:
                self._parse_ipv4(0)
            elif raw[0] >> 4 == 6:
                self._parse_ipv6(0)
            return
        if len(raw) < 14:
            return
        offset = 14
        ethertype = int.from_bytes(raw[12:14], "big")
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(raw) < offset + 4:
                return
            ethertype = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += 4
        self.ethernet = _Ethernet(_mac(raw[6:12]), _mac(raw[0:6]), ethertype, _Payload(raw[offset:]))
        if ethertype == 0x0800:
            self._parse_ipv4(offset)
        elif ethertype == 0x86DD:
            self._parse_ipv6(offset)
        elif ethertype == 0x0806:
            self._parse_arp(offset)

    def _parse_arp(self, offset: int) -> None:
        raw = self.raw
        if len(raw) < offset + 28 or raw[offset + 4] != 6 or raw[offset + 5] != 4:
            return
        self.arp = _Arp(
            int.from_bytes(raw[offset + 6 : offset + 8], "big"),
            ".".join(str(value) for value in raw[offset + 14 : offset + 18]),
            ".".join(str(value) for value in raw[offset + 24 : offset + 28]),
            _mac(raw[offset + 8 : offset + 14]),
            _mac(raw[offset + 18 : offset + 24]),
        )
        self.src_ip, self.dst_ip = self.arp.psrc, self.arp.pdst
        self.protocol_number = 254

    def _parse_ipv4(self, offset: int) -> None:
        raw = self.raw
        if len(raw) < offset + 20 or raw[offset] >> 4 != 4:
            return
        header_len = (raw[offset] & 0x0F) * 4
        if header_len < 20 or len(raw) < offset + header_len:
            return
        total_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        end = min(len(raw), offset + (total_len or len(raw) - offset))
        self.src_ip = ".".join(str(value) for value in raw[offset + 12 : offset + 16])
        self.dst_ip = ".".join(str(value) for value in raw[offset + 16 : offset + 20])
        self.protocol_number = raw[offset + 9]
        self.network = _Network(self.src_ip, self.dst_ip, ttl=raw[offset + 8])
        self.ip_version = 4
        self._parse_transport(offset + header_len, end)

    def _parse_ipv6(self, offset: int) -> None:
        raw = self.raw
        if len(raw) < offset + 40 or raw[offset] >> 4 != 6:
            return
        payload_len = int.from_bytes(raw[offset + 4 : offset + 6], "big")
        end = min(len(raw), offset + 40 + (payload_len or len(raw) - offset - 40))
        self.src_ip = str(IPv6Address(raw[offset + 8 : offset + 24]))
        self.dst_ip = str(IPv6Address(raw[offset + 24 : offset + 40]))
        next_header, cursor = raw[offset + 6], offset + 40
        for _ in range(8):
            if next_header in {0, 43, 60}:
                if cursor + 2 > end:
                    return
                size = (raw[cursor + 1] + 1) * 8
                next_header, cursor = raw[cursor], cursor + size
            elif next_header == 44:
                if cursor + 8 > end:
                    return
                next_header, cursor = raw[cursor], cursor + 8
            elif next_header == 51:
                if cursor + 2 > end:
                    return
                size = (raw[cursor + 1] + 2) * 4
                next_header, cursor = raw[cursor], cursor + size
            else:
                break
            if cursor > end:
                return
        self.protocol_number = next_header
        self.network = _Network(self.src_ip, self.dst_ip, hlim=raw[offset + 7])
        self.ip_version = 6
        self._parse_transport(cursor, end)

    def _parse_transport(self, offset: int, end: int) -> None:
        raw = self.raw
        if self.protocol_number == 6:
            if offset + 20 > end:
                return
            header_len = ((raw[offset + 12] >> 4) & 0x0F) * 4
            if header_len < 20 or offset + header_len > end:
                return
            self.sport = int.from_bytes(raw[offset : offset + 2], "big")
            self.dport = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            self.application_payload = raw[offset + header_len : end]
            self.transport = _Transport(
                self.sport,
                self.dport,
                _Payload(self.application_payload),
                seq=int.from_bytes(raw[offset + 4 : offset + 8], "big"),
                ack=int.from_bytes(raw[offset + 8 : offset + 12], "big"),
                flags=_TcpFlags(raw[offset + 13]),
            )
        elif self.protocol_number == 17:
            if offset + 8 > end:
                return
            self.sport = int.from_bytes(raw[offset : offset + 2], "big")
            self.dport = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            declared = int.from_bytes(raw[offset + 4 : offset + 6], "big")
            payload_end = min(end, offset + declared) if declared else end
            self.application_payload = raw[offset + 8 : payload_end]
            self.transport = _Transport(self.sport, self.dport, _Payload(self.application_payload))
        elif self.protocol_number in {1, 58}:
            if offset + 4 > end:
                return
            self.application_payload = raw[offset + 8 : end] if offset + 8 <= end else b""
            identifier = int.from_bytes(raw[offset + 4 : offset + 6], "big") if offset + 8 <= end else 0
            sequence = int.from_bytes(raw[offset + 6 : offset + 8], "big") if offset + 8 <= end else 0
            self.icmp = _Icmp(raw[offset], raw[offset + 1], identifier, sequence)

    @staticmethod
    def _layer_name(layer) -> str:
        return layer if isinstance(layer, str) else getattr(layer, "__name__", "")

    def __contains__(self, layer) -> bool:
        name = self._layer_name(layer)
        return {
            "Ether": self.ethernet is not None,
            "IP": self.ip_version == 4,
            "IPv6": self.ip_version == 6,
            "TCP": self.protocol_number == 6 and self.transport is not None,
            "UDP": self.protocol_number == 17 and self.transport is not None,
            "Raw": bool(self.application_payload),
            "ARP": self.arp is not None,
            "ICMP": self.protocol_number == 1 and self.icmp is not None,
            "ICMPv6EchoRequest": self.protocol_number == 58 and self.icmp is not None and self.icmp.type == 128,
            "ICMPv6EchoReply": self.protocol_number == 58 and self.icmp is not None and self.icmp.type == 129,
        }.get(name, False)

    def haslayer(self, layer) -> bool:
        return layer in self

    def __getitem__(self, layer):
        name = self._layer_name(layer)
        mapping = {
            "Ether": self.ethernet,
            "IP": self.network if self.ip_version == 4 else None,
            "IPv6": self.network if self.ip_version == 6 else None,
            "TCP": self.transport if self.protocol_number == 6 else None,
            "UDP": self.transport if self.protocol_number == 17 else None,
            "Raw": _Payload(self.application_payload) if self.application_payload else None,
            "ARP": self.arp,
            "ICMP": self.icmp if self.protocol_number == 1 else None,
            "ICMPv6EchoRequest": self.icmp if self.protocol_number == 58 and self.icmp and self.icmp.type == 128 else None,
            "ICMPv6EchoReply": self.icmp if self.protocol_number == 58 and self.icmp and self.icmp.type == 129 else None,
        }
        value = mapping.get(name)
        if value is None:
            raise IndexError(f"Layer unavailable: {name}")
        return value

    def getlayer(self, layer):
        try:
            return self[layer]
        except IndexError:
            return None
