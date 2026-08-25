"""Declarative calibration corpus loading and deterministic traffic generation."""

from __future__ import annotations

import base64
import ipaddress
import math
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import scapy.all as scapy
import yaml
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_RA

from core.calibration.contracts import CalibrationCase
from core.packet_engine.schemas import FlowAggregate


class CorpusError(ValueError):
    pass


def _seed_recipe(value: Any, seed: int, key: str = "") -> Any:
    """Create deterministic scenario diversity without changing its semantics."""
    if isinstance(value, dict):
        return {name: _seed_recipe(child, seed, str(name)) for name, child in value.items()}
    if isinstance(value, list):
        return [_seed_recipe(child, seed, key) for child in value]
    if seed == 0:
        return value
    if key in {"src", "dst"} and isinstance(value, str) and "{" not in value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        if address.version == 4 and value.startswith("10.250."):
            octets = list(address.packed)
            octets[2] = ((octets[2] - 1 + seed) % 253) + 1
            return str(ipaddress.ip_address(bytes(octets)))
        return value
    if key in {"start_time", "last_seen", "timestamp"} and isinstance(value, (int, float)):
        return value + seed * 10_000
    if key == "arrival_times" and isinstance(value, (int, float)):
        return value + seed * 10_000
    if key == "sport" and isinstance(value, int) and value >= 1024:
        return min(65_535, value + seed)
    if key == "payload_seed" and isinstance(value, int):
        return value + seed
    if key in {"src_mac", "dst_mac", "hwsrc", "hwdst"} and isinstance(value, str):
        parts = value.split(":")
        if len(parts) == 6:
            try:
                parts[-1] = f"{(int(parts[-1], 16) + seed) & 0xff:02x}"
                return ":".join(parts)
            except ValueError:
                return value
    return value


def load_corpus(path: Path) -> List[CalibrationCase]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CorpusError(f"unable to load calibration corpus {path}: {exc}") from exc
    if not isinstance(data, dict) or int(data.get("schema_version") or 0) != 1:
        raise CorpusError("calibration corpus schema_version must be 1")
    defaults = dict(data.get("defaults") or {})
    try:
        matrix_seeds = int(data.get("matrix_seeds") or 1)
    except (TypeError, ValueError) as exc:
        raise CorpusError("matrix_seeds must be an integer") from exc
    if not 1 <= matrix_seeds <= 100:
        raise CorpusError("matrix_seeds must be 1..100")
    raw_cases = data.get("cases") or []
    if not isinstance(raw_cases, list):
        raise CorpusError("calibration corpus cases must be a list")
    cases: List[CalibrationCase] = []
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise CorpusError("each calibration case must be a mapping")
        variants = raw.get("variants")
        expanded_variants = []
        if isinstance(variants, list) and variants:
            for variant in variants:
                item = deepcopy(raw)
                item.pop("variants", None)
                item["variant"] = str(variant)
                item["id"] = f"{item.get('id')}.{str(variant).lower().replace(' ', '-')}"
                expanded_variants.append(item)
        else:
            expanded_variants.append(raw)
        for variant_item in expanded_variants:
            repeat = max(1, min(1000, int(variant_item.get("repeat") or 1)))
            for index in range(repeat):
                expanded = deepcopy(variant_item)
                expanded.pop("repeat", None)
                if repeat > 1:
                    expanded["id"] = f"{expanded.get('id')}.{index + 1:03d}"
                    expanded.setdefault("recipe", {})["case_index"] = index
                # Integrated representatives exercise the complete
                # production path once. Keep the remaining seeds as
                # isolation cases so the labeled matrix still contains the
                # required positive/benign volume without replaying a large
                # PCAP ten times through every backend and mode.
                seed_count = matrix_seeds
                for seed in range(seed_count):
                    seeded = deepcopy(expanded)
                    if seed_count > 1:
                        seeded["id"] = f"{seeded.get('id')}.seed{seed + 1:03d}"
                        seeded["recipe"] = _seed_recipe(seeded.get("recipe") or {}, seed)
                        seeded.setdefault("recipe", {})["calibration_seed"] = seed
                    modes = tuple(seeded.get("modes") or defaults.get("modes") or ())
                    if (
                        seed > 0
                        and "integrated" in modes
                        and not (isinstance(variants, list) and variants)
                    ):
                        seeded["modes"] = [mode for mode in modes if mode != "integrated"] or ["isolation"]
                    case = CalibrationCase.from_dict(seeded, defaults)
                    errors = case.validate()
                    if errors:
                        raise CorpusError(f"{case.case_id or '<unknown>'}: " + "; ".join(errors))
                    cases.append(case)
    identifiers = [case.case_id for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise CorpusError("calibration corpus contains duplicate case IDs")
    return cases


def _format_value(value: Any, variables: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format(**variables)
        except (KeyError, ValueError):
            return value
    if isinstance(value, list):
        return [_format_value(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _format_value(child, variables) for key, child in value.items()}
    return value


def _payload(spec: Dict[str, Any]) -> bytes:
    provided = [
        key for key in (
            "payload_text", "payload_hex", "payload_base64", "payload_deterministic_bytes",
        )
        if key in spec
    ]
    if len(provided) > 1:
        raise CorpusError("a packet may specify only one payload encoding")
    if "payload_text" in spec:
        return str(spec["payload_text"]).encode("utf-8")
    if "payload_hex" in spec:
        try:
            return bytes.fromhex(str(spec["payload_hex"]))
        except ValueError as exc:
            raise CorpusError("invalid hexadecimal packet payload") from exc
    if "payload_base64" in spec:
        try:
            return base64.b64decode(str(spec["payload_base64"]), validate=True)
        except (ValueError, TypeError) as exc:
            raise CorpusError("invalid base64 packet payload") from exc
    if "payload_deterministic_bytes" in spec:
        size = max(0, min(1024 * 1024, int(spec.get("payload_deterministic_bytes") or 0)))
        seed = int(spec.get("payload_seed") or 17) & 0xFF
        pattern = bytes(((index * 73 + seed) & 0xFF) for index in range(256))
        return (pattern * ((size + 255) // 256))[:size]
    return b""


def packet_from_spec(spec: Dict[str, Any], timestamp: float = 1.0):
    link_type = str(spec.get("link_type") or "ethernet").lower()
    if link_type == "ethernet":
        packet = scapy.Ether(
            src=str(spec.get("src_mac") or "02:00:00:00:00:01"),
            dst=str(spec.get("dst_mac") or "02:00:00:00:00:02"),
        )
    elif link_type == "raw-ip":
        packet = None
    else:
        raise CorpusError(f"unsupported calibration link type: {link_type}")

    network = str(spec.get("network") or "ipv4").lower()
    src = str(spec.get("src") or "10.250.0.10")
    dst = str(spec.get("dst") or "10.250.0.20")
    if network == "ipv4":
        layer = scapy.IP(src=src, dst=dst, ttl=int(spec.get("ttl") or 64))
    elif network == "ipv6":
        layer = scapy.IPv6(src=src, dst=dst, hlim=int(spec.get("hop_limit") or 64))
    elif network == "arp":
        layer = scapy.ARP(
            psrc=src, pdst=dst, op=int(spec.get("op") or 1),
            hwsrc=str(spec.get("hwsrc") or spec.get("src_mac") or "02:00:00:00:00:01"),
            hwdst=str(spec.get("hwdst") or spec.get("dst_mac") or "00:00:00:00:00:00"),
        )
    else:
        raise CorpusError(f"unsupported calibration network protocol: {network}")
    packet = layer if packet is None else packet / layer

    transport = str(spec.get("transport") or "tcp").lower()
    if network != "arp":
        if transport == "tcp":
            packet /= scapy.TCP(
                sport=int(spec.get("sport") or 50000), dport=int(spec.get("dport") or 80),
                flags=str(spec.get("flags") or "PA"), seq=int(spec.get("seq") or 1),
                ack=int(spec.get("ack") or 0),
            )
        elif transport == "udp":
            packet /= scapy.UDP(sport=int(spec.get("sport") or 50000), dport=int(spec.get("dport") or 53))
        elif transport == "icmp":
            packet /= scapy.ICMP(type=int(spec.get("icmp_type") or 8), code=int(spec.get("icmp_code") or 0))
        elif transport == "icmpv6":
            packet /= scapy.ICMPv6EchoRequest(id=int(spec.get("icmp_id") or 1))
        elif transport != "none":
            raise CorpusError(f"unsupported calibration transport: {transport}")

    if spec.get("icmpv6_nd_na"):
        target = str(spec.get("target") or src)
        packet /= ICMPv6ND_NA(tgt=target, R=0, S=1, O=1)
    if spec.get("icmpv6_ra"):
        packet /= ICMPv6ND_RA()
    dhcp = spec.get("dhcp")
    if dhcp:
        message = dhcp.get("message_type") or "offer"
        server = str(dhcp.get("server_id") or src)
        yiaddr = str(dhcp.get("yiaddr") or "10.250.40.50")
        packet /= BOOTP(op=2, yiaddr=yiaddr, siaddr=server)
        packet /= DHCP(options=[("message-type", message), ("server_id", server), "end"])
    dns = spec.get("dns")
    if dns:
        packet /= scapy.DNS(
            qr=int(dns.get("qr") or 0), rcode=int(dns.get("rcode") or 0),
            qd=scapy.DNSQR(qname=str(dns.get("qname") or "example.invalid"), qtype=str(dns.get("qtype") or "A")),
        )
    payload = _payload(spec)
    if payload:
        packet /= scapy.Raw(payload)
    packet.time = float(spec.get("timestamp") if spec.get("timestamp") is not None else timestamp)
    return packet


def packets_for_case(case: CalibrationCase) -> List[Any]:
    recipe = case.recipe
    if "packets" in recipe:
        packets = []
        current = float(recipe.get("start_time") or 1.0)
        packet_index = 0
        for spec_index, raw_spec in enumerate(recipe.get("packets") or []):
            repeat = max(1, min(1000000, int(raw_spec.get("repeat") or 1)))
            interval = float(raw_spec.get("interval") or 0.001)
            for repeat_index in range(repeat):
                variables = {
                    "case_index": int(recipe.get("case_index") or 0),
                    "spec_index": spec_index,
                    "repeat_index": repeat_index,
                    "packet_index": packet_index,
                    "i": repeat_index,
                    "n": repeat_index + 1,
                }
                spec = _format_value(raw_spec, variables)
                packets.append(packet_from_spec(spec, current))
                current += interval
                packet_index += 1
        return packets
    if case.input_kind == "stream":
        parts = [str(part).encode("utf-8") for part in (recipe.get("parts") or [])]
        src, dst = str(recipe.get("src") or "10.250.0.10"), str(recipe.get("dst") or "10.250.0.20")
        sport, dport = int(recipe.get("sport") or 50000), int(recipe.get("dport") or 80)
        packets, sequence, current = [], int(recipe.get("seq") or 1), float(recipe.get("start_time") or 1.0)
        for part in parts:
            spec = {
                "src": src, "dst": dst, "sport": sport, "dport": dport,
                "flags": "PA", "seq": sequence, "payload_base64": base64.b64encode(part).decode("ascii"),
            }
            packets.append(packet_from_spec(spec, current))
            sequence += len(part)
            current += float(recipe.get("interval") or 0.01)
        if recipe.get("retransmit") and packets:
            packets.append(packets[-1].copy())
            packets[-1].time = current
        if recipe.get("reorder") and len(packets) > 1:
            packets[-2], packets[-1] = packets[-1], packets[-2]
        return packets
    if case.input_kind == "packet":
        return [packet_from_spec(recipe, float(recipe.get("start_time") or 1.0))]
    if case.input_kind in {"flow", "session"}:
        packets = []
        for flow in (flows_for_case(case) if case.input_kind == "session" else [flow_for_recipe(recipe)]):
            packets.extend(_packets_for_flow(flow))
        return sorted(packets, key=lambda packet: float(getattr(packet, "time", 0.0)))
    return []


def _packets_for_flow(flow: FlowAggregate) -> List[Any]:
    """Render bounded packet evidence from a canonical flow calibration recipe."""
    src, dst, sport, dport, protocol = flow.flow_id
    start = float(flow.start_time or 1.0)
    end = max(start, float(flow.last_seen or start))
    duration = max(0.001, end - start)
    packets: List[Any] = []

    if protocol == "TCP" and int(flow.tcp_syn_count or 0) > 0:
        syn_count = int(flow.tcp_syn_count or 0)
        interval = duration / max(1, syn_count)
        for index in range(syn_count):
            packets.append(packet_from_spec({
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "transport": "tcp",
                "flags": "S",
                "seq": index + 1,
            }, start + index * interval))
        if bool((flow.l7_metadata or {}).get("auth_failure")):
            packets.append(packet_from_spec({
                "src": dst,
                "dst": src,
                "sport": dport,
                "dport": sport,
                "transport": "tcp",
                "flags": "PA",
                "seq": 1,
                "payload_text": "authentication failed",
            }, start + min(0.0001, interval / 2)))
        syn_ack_count = min(syn_count, int(flow.tcp_syn_ack_count or 0))
        for index in range(syn_ack_count):
            packets.append(packet_from_spec({
                "src": dst,
                "dst": src,
                "sport": dport,
                "dport": sport,
                "transport": "tcp",
                "flags": "SA",
                "seq": index + 1,
                "ack": index + 2,
            }, start + index * interval + min(0.0001, interval / 2)))
        return packets

    # Ethernet + IPv4 + TCP/UDP overhead is kept below the legal IPv4 length.
    maximum_frame_bytes = 65_000
    transport_overhead = 54 if protocol == "TCP" else 42

    def emit_direction(
        direction_src: str,
        direction_dst: str,
        direction_sport: int,
        direction_dport: int,
        total_bytes: int,
        time_offset: float,
    ) -> None:
        frame_count = max(1, int(math.ceil(max(1, total_bytes) / maximum_frame_bytes)))
        remaining = max(1, int(total_bytes))
        sequence = 1
        for index in range(frame_count):
            frame_bytes = min(maximum_frame_bytes, remaining)
            payload_bytes = max(0, frame_bytes - transport_overhead)
            timestamp = start + time_offset + duration * index / max(1, frame_count)
            spec = {
                "src": direction_src,
                "dst": direction_dst,
                "sport": direction_sport,
                "dport": direction_dport,
                "transport": "tcp" if protocol == "TCP" else "udp",
                "flags": "PA",
                "seq": sequence,
                "payload_deterministic_bytes": payload_bytes,
                "payload_seed": 31 + (index % 17),
            }
            packets.append(packet_from_spec(spec, timestamp))
            sequence += payload_bytes
            remaining -= frame_bytes

    emit_direction(src, dst, int(sport), int(dport), int(flow.byte_count or 0), 0.0)
    reverse_bytes = int((flow.l7_metadata or {}).get("reverse_byte_count") or 0)
    if reverse_bytes > 0:
        emit_direction(dst, src, int(dport), int(sport), reverse_bytes, 0.0002)
    return packets


def flow_for_recipe(recipe: Dict[str, Any]) -> FlowAggregate:
    flow_id = (
        str(recipe.get("src") or "10.250.0.10"), str(recipe.get("dst") or "10.250.0.20"),
        int(recipe.get("sport") or 50000), int(recipe.get("dport") or 443),
        str(recipe.get("protocol") or "TCP").upper(),
    )
    arrivals = [float(value) for value in (recipe.get("arrival_times") or [])]
    start = float(recipe.get("start_time") if recipe.get("start_time") is not None else (arrivals[0] if arrivals else 1.0))
    end = float(recipe.get("last_seen") if recipe.get("last_seen") is not None else (arrivals[-1] if arrivals else start))
    flow = FlowAggregate(flow_id, start, end)
    flow.packet_count = int(recipe.get("packet_count") or len(arrivals) or 1)
    flow.byte_count = int(recipe.get("byte_count") or flow.packet_count * 64)
    flow.tcp_syn_count = int(recipe.get("tcp_syn_count") or 0)
    flow.tcp_syn_ack_count = int(recipe.get("tcp_syn_ack_count") or 0)
    flow.tcp_rst_count = int(recipe.get("tcp_rst_count") or 0)
    flow.arrival_times = arrivals
    flow.packet_sizes = [int(value) for value in (recipe.get("packet_sizes") or [64] * flow.packet_count)]
    flow.l7_metadata = dict(recipe.get("l7_metadata") or {})
    return flow


def flows_for_case(case: CalibrationCase) -> List[FlowAggregate]:
    flows = []
    for spec_index, raw_spec in enumerate(case.recipe.get("flows") or []):
        repeat = max(1, min(10000, int(raw_spec.get("repeat") or 1)))
        for repeat_index in range(repeat):
            variables = {
                "case_index": int(case.recipe.get("case_index") or 0),
                "spec_index": spec_index,
                "repeat_index": repeat_index,
                "i": repeat_index,
                "n": repeat_index + 1,
            }
            spec = _format_value(raw_spec, variables)
            spec.pop("repeat", None)
            flows.append(flow_for_recipe(spec))
    return flows


def stream_for_case(case: CalibrationCase) -> bytes:
    parts = case.recipe.get("parts") or []
    return b"".join(str(part).encode("utf-8") for part in parts)


def write_case_pcap(case: CalibrationCase, path: Path) -> Path:
    packets = packets_for_case(case)
    if not packets:
        raise CorpusError(f"{case.case_id}: integrated mode requires packet or stream recipes")
    scapy.wrpcap(str(path), packets)
    return path
