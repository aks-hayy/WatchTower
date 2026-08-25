"""Bounded, evidence-led detectors for LAN, application, and OT traffic."""

from collections import defaultdict, deque
from ipaddress import ip_address
import math
import re
from typing import Deque, Dict, List, Set, Tuple

import scapy.all as scapy
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_RA, IPv6

from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2
from core.detection.payload import application_payload


def _alert(kind, severity, score, explanation, evidence, timestamp=0.0):
    return ForensicAlert(timestamp, kind, severity, score, explanation, evidence)


def _payload(packet) -> bytes:
    return application_payload(packet, maximum=8192)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(value) for value in set(data)]
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts)


class LANTrustDetector(BaseDetector):
    name = "LAN Trust Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.lan.trust", name=name, input_kinds=("packet",),
        finding_types=("network.arp.binding_conflict", "network.ndp.binding_conflict", "network.dhcp.untrusted_server", "network.ipv6.untrusted_router"),
        signal_family="identity", correlation_group="lan-trust",
    )
    finding_metadata = {
        "network.arp.binding_conflict": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8},
        "network.ndp.binding_conflict": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8},
        "network.dhcp.untrusted_server": {"category": "POLICY_VIOLATION", "impact": "HIGH", "confidence": 0.85},
        "network.ipv6.untrusted_router": {"category": "POLICY_VIOLATION", "impact": "HIGH", "confidence": 0.85},
    }
    MAX_BINDINGS = 4096

    VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01", "00:00:0c:07:ac")

    def __init__(self, trusted_dhcp_servers=None, trusted_ipv6_routers=None, protected_gateways=None):
        self.trusted_dhcp_servers = set(trusted_dhcp_servers or ())
        self.trusted_ipv6_routers = set(trusted_ipv6_routers or ())
        self.protected_gateways = set(protected_gateways or ())
        self.reset()

    def reset(self, source: str = None) -> None:
        self.bindings: Dict[str, str] = {}
        self.dhcp_servers: Set[str] = set()
        self.ipv6_routers: Set[str] = set()
        self.binding_conflicts: Dict[Tuple[str, str, str], Deque[float]] = defaultdict(lambda: deque(maxlen=3))
        self.policy_alerts = set()

    def _remember(self, table: Dict[str, str], key: str, value: str):
        if len(table) >= self.MAX_BINDINGS and key not in table:
            table.pop(next(iter(table)))
        previous = table.get(key)
        table[key] = value
        return previous

    def detect(self, packet=None, **kwargs) -> List[ForensicAlert]:
        if packet is None:
            return []
        timestamp = float(getattr(packet, "time", 0.0) or 0.0)
        if scapy.ARP in packet and int(packet[scapy.ARP].op) == 2:
            arp = packet[scapy.ARP]
            ip, mac = str(arp.psrc), str(arp.hwsrc).lower()
            previous = self.bindings.get(ip)
            if not previous:
                self._remember(self.bindings, ip, mac)
            elif previous != mac and not mac.startswith(self.VIRTUAL_MAC_PREFIXES) and not previous.startswith(self.VIRTUAL_MAC_PREFIXES):
                confirmations = self.binding_conflicts[(ip, previous, mac)]
                confirmations.append(timestamp)
                while confirmations and timestamp - confirmations[0] > 60:
                    confirmations.popleft()
                if len(confirmations) < 3:
                    return []
                self.bindings[ip] = mac
                return [_alert("ARP_SPOOFING", "HIGH", 55.0,
                    "An IPv4 address was advertised by multiple MAC addresses.",
                    {"ip": ip, "previous_mac": previous, "observed_mac": mac,
                     "confirmations": len(confirmations), "protected_gateway": ip in self.protected_gateways}, timestamp)]
        if packet.haslayer(ICMPv6ND_NA) and IPv6 in packet and scapy.Ether in packet:
            target = str(packet[ICMPv6ND_NA].tgt)
            mac = str(packet[scapy.Ether].src).lower()
            previous = self.bindings.get(target)
            if not previous:
                self._remember(self.bindings, target, mac)
            elif previous != mac and not mac.startswith(self.VIRTUAL_MAC_PREFIXES) and not previous.startswith(self.VIRTUAL_MAC_PREFIXES):
                confirmations = self.binding_conflicts[(target, previous, mac)]
                confirmations.append(timestamp)
                while confirmations and timestamp - confirmations[0] > 60:
                    confirmations.popleft()
                if len(confirmations) < 3:
                    return []
                self.bindings[target] = mac
                return [_alert("NDP_SPOOFING", "HIGH", 55.0,
                    "An IPv6 neighbor address was advertised by multiple MAC addresses.",
                    {"ip": target, "previous_mac": previous, "observed_mac": mac,
                     "confirmations": len(confirmations), "protected_gateway": target in self.protected_gateways}, timestamp)]
        if DHCP in packet and BOOTP in packet:
            options = dict(item for item in packet[DHCP].options if isinstance(item, tuple) and len(item) == 2)
            message = options.get("message-type")
            if message in {2, 5, "offer", "ack"}:
                server = str(options.get("server_id") or packet[BOOTP].siaddr)
                if server and server != "0.0.0.0":
                    self.dhcp_servers.add(server)
                    if self.trusted_dhcp_servers and server not in self.trusted_dhcp_servers and ("dhcp", server) not in self.policy_alerts:
                        self.policy_alerts.add(("dhcp", server))
                        return [_alert("ROGUE_DHCP", "HIGH", 50.0,
                            "A DHCP server outside the configured trust policy answered a client.",
                            {"server": server, "trusted_servers": sorted(self.trusted_dhcp_servers)[:16]}, timestamp)]
        if packet.haslayer(ICMPv6ND_RA) and IPv6 in packet:
            self.ipv6_routers.add(str(packet[IPv6].src))
            router = str(packet[IPv6].src)
            if self.trusted_ipv6_routers and router not in self.trusted_ipv6_routers and ("router", router) not in self.policy_alerts:
                self.policy_alerts.add(("router", router))
                return [_alert("ROGUE_IPV6_RA", "HIGH", 50.0,
                    "An IPv6 router outside the configured trust policy advertised itself.",
                    {"router": router, "trusted_routers": sorted(self.trusted_ipv6_routers)[:16]}, timestamp)]
        return []


class ReconLateralDetector(BaseDetector):
    name = "Reconnaissance and Lateral Movement Detector"
    enabled = False
    manifest = DetectorManifestV2(
        detector_id="watchtower.recon", name=name, input_kinds=("packet", "flow"),
        finding_types=("recon.port_scan", "recon.syn_flood", "lateral.admin_fanout"),
        signal_family="behavior", correlation_group="recon-lateral",
    )
    finding_metadata = {
        "recon.port_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1046", "correlation_group": "recon"},
        "recon.syn_flood": {"category": "THREAT", "impact": "HIGH", "confidence": 0.9, "mitre_technique": "T1498", "correlation_group": "availability"},
        "lateral.admin_fanout": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1021", "correlation_group": "lateral-movement"},
    }
    WINDOW_SECONDS = 60.0
    MAX_EVENTS_PER_HOST = 512
    ADMIN_PORTS = {22, 135, 139, 445, 3389, 5900, 5985, 5986}

    def __init__(self, trusted_scanners=None):
        self.trusted_scanners = set(trusted_scanners or ())
        self.reset()

    def reset(self, source: str = None) -> None:
        self.events: Dict[str, Deque[Tuple[float, str, int, bool, float]]] = defaultdict(
            lambda: deque(maxlen=self.MAX_EVENTS_PER_HOST)
        )
        self.last_alert: Dict[Tuple[str, str], float] = {}

    def _emit_once(self, src: str, kind: str, now: float) -> bool:
        key = (src, kind)
        if now - self.last_alert.get(key, -10_000.0) < self.WINDOW_SECONDS:
            return False
        self.last_alert[key] = now
        return True

    def detect(self, packet=None, flow=None, **kwargs) -> List[ForensicAlert]:
        if packet is not None and (scapy.IP in packet or IPv6 in packet) and TCP in packet:
            flags = int(packet[TCP].flags)
            if not (flags & 0x02) or flags & 0x10:
                return []
            network = packet[scapy.IP] if scapy.IP in packet else packet[IPv6]
            src, dst, dport = str(network.src), str(network.dst), int(packet[TCP].dport)
            protocol, now = "TCP", float(getattr(packet, "time", 0.0) or 0.0)
            peer_novelty, response_ratio = False, 0.0
        elif flow is not None:
            if flow.flow_id[4] != "TCP" or flow.tcp_syn_count < 1:
                return []
            src, dst, _sport, dport, protocol = flow.flow_id
            now = float(flow.last_seen)
            peer_novelty = bool(flow.l7_metadata.get("peer_novelty"))
            response_ratio = float(getattr(flow, "tcp_syn_ack_count", 0) or 0) / max(1, int(flow.tcp_syn_count or 0))
        else:
            return []
        if src in self.trusted_scanners:
            return []
        queue = self.events[src]
        queue.append((now, dst, int(dport), peer_novelty, response_ratio))
        while queue and now - queue[0][0] > self.WINDOW_SECONDS:
            queue.popleft()
        hosts = {event[1] for event in queue}
        ports = {event[2] for event in queue}
        alerts = []
        if flow is not None:
            duration = max(0.0, float(flow.last_seen or 0.0) - float(flow.start_time or 0.0))
            syn_count = int(flow.tcp_syn_count or 0)
            if duration >= 3.0 and syn_count / duration >= 1000.0 and response_ratio < 0.10 and self._emit_once(src, "SYN_FLOOD", now):
                alerts.append(_alert("SYN_FLOOD", "HIGH", 55.0,
                    "Sustained SYN rate exceeded 1,000/s with fewer than 10% SYN-ACK responses.",
                    {"source": src, "dst_ip": dst, "syn_count": syn_count,
                     "duration_seconds": duration, "syn_rate": round(syn_count / duration, 2),
                     "syn_ack_ratio": round(response_ratio, 4)}, now))
        low_response = sum(event[4] for event in queue) / max(1, len(queue)) < 0.5
        if protocol == "TCP" and (len(ports) >= 20 or len(hosts) >= 20) and low_response and self._emit_once(src, "PORT_SCAN", now):
            alerts.append(_alert("PORT_SCAN", "MEDIUM", 30.0,
                "One source contacted an unusual number of hosts or ports in a short window.",
                {"source": src, "unique_hosts": len(hosts), "unique_ports": len(ports), "window_seconds": self.WINDOW_SECONDS}, now))
        admin_events = [event for event in queue if event[2] in self.ADMIN_PORTS]
        admin_hosts = {event[1] for event in admin_events}
        try:
            internal = ip_address(src).is_private and all(ip_address(host).is_private for host in admin_hosts)
        except ValueError:
            internal = False
        corroborated = any(event[3] for event in admin_events)
        if internal and len(admin_hosts) >= 5 and corroborated and self._emit_once(src, "LATERAL_MOVEMENT", now):
            alerts.append(_alert("LATERAL_MOVEMENT", "HIGH", 45.0,
                "A private host contacted administrative services on multiple internal systems.",
                {"source": src, "destination_count": len(admin_hosts), "admin_ports": sorted(ports & self.ADMIN_PORTS),
                 "peer_novelty": corroborated}, now))
        return alerts


class ApplicationAbuseDetector(BaseDetector):
    name = "Application Abuse Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.application.abuse", name=name, version="2.1.0",
        input_kinds=("packet", "stream"),
        finding_types=("credential.cleartext.generic", "auth.failure_burst", "icmp.tunnel.suspected", "tls.protocol_mismatch", "protocol.nonstandard_service"),
        signal_family="content", correlation_group="application-abuse",
    )
    finding_metadata = {
        "credential.cleartext.generic": {"category": "EXPOSURE", "impact": "HIGH", "confidence": 0.85, "mitre_technique": "T1552", "correlation_group": "credential-exposure"},
        "auth.failure_burst": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1110", "correlation_group": "authentication"},
        "icmp.tunnel.suspected": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1095", "correlation_group": "covert-channel"},
        "tls.protocol_mismatch": {"category": "ANOMALY", "impact": "LOW", "confidence": 0.9, "correlation_group": "protocol-integrity"},
        "protocol.nonstandard_service": {"category": "ANOMALY", "impact": "LOW", "confidence": 0.9, "correlation_group": "protocol-integrity"},
    }
    MAX_TLS_CONNECTIONS = 4096
    SECRET_RE = re.compile(rb"(?i)(?:authorization:\s*basic|password\s*[=:]|passwd\s*[=:]|user\s+\S+\s+pass\s+)")
    FAILURE_RE = re.compile(rb"(?i)(?:authentication failed|login failed|invalid password|535 authentication)")
    SUCCESS_RE = re.compile(rb"(?i)(?:authentication successful|login successful|230 login successful)")

    def __init__(self):
        self.reset()

    def reset(self, source: str = None) -> None:
        self.failures: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=64))
        self.icmp_events: Dict[str, Deque[Tuple[float, int, float]]] = defaultdict(lambda: deque(maxlen=512))
        self.icmp_last_alert: Dict[str, float] = {}
        self.tls_connections = set()
        self.tls_inspected = set()

    @staticmethod
    def _remember(values, item, maximum):
        if item in values:
            return
        if len(values) >= maximum:
            values.pop()
        values.add(item)

    @staticmethod
    def _is_rdp_tpkt(payload: bytes) -> bool:
        """Validate a TPKT frame carrying an X.224 connection TPDU."""
        if len(payload) < 7 or payload[0:2] != b"\x03\x00":
            return False
        declared_length = int.from_bytes(payload[2:4], "big")
        if declared_length < 7 or declared_length > len(payload):
            return False
        # X.224 connection request/confirm TPDUs use E0/D0 in the high nibble
        # after the length indicator. Data TPDUs use F0.
        length_indicator = int(payload[4])
        if length_indicator < 2 or 5 + length_indicator > declared_length:
            return False
        return payload[5] in {0xE0, 0xD0, 0xF0}

    def detect(self, packet=None, flow=None, domain=None, stream=None, direction=None,
               timestamp=0.0, claimed_protocol=False, truncated=False,
               application_payload=None, **kwargs) -> List[ForensicAlert]:
        if stream is not None:
            bounded = bytes(stream[:1024 * 1024])
            if claimed_protocol or truncated or not self.SECRET_RE.search(bounded):
                return []
            return [_alert(
                "CLEARTEXT_SECRET", "HIGH", 50.0,
                "A credential-bearing pattern was observed in a cleartext application stream.",
                {
                    "payload_length": len(bounded), "direction": direction or "unknown",
                    "stream_evidence_hash": __import__("hashlib").sha256(bounded).hexdigest(),
                },
                float(timestamp or 0.0),
            )]
        if packet is None:
            return []
        now = float(getattr(packet, "time", 0.0) or 0.0)
        payload = application_payload if application_payload is not None else _payload(packet)
        src, dst = "unknown", "unknown"
        if scapy.IP in packet: src, dst = str(packet[scapy.IP].src), str(packet[scapy.IP].dst)
        elif IPv6 in packet: src, dst = str(packet[IPv6].src), str(packet[IPv6].dst)
        alerts = []
        if payload and not claimed_protocol and self.SECRET_RE.search(payload):
            alerts.append(_alert("CLEARTEXT_SECRET", "HIGH", 50.0,
                "A credential-bearing pattern was observed in cleartext application data.",
                {"source": src, "payload_length": len(payload)}, now))
        if payload and self.FAILURE_RE.search(payload):
            known_services = {21, 22, 25, 110, 143, 389, 445, 3389, 587, 993, 995}
            client = dst if TCP in packet and int(packet[TCP].sport) in known_services else src
            failures = self.failures[client]
            failures.append(now)
            while failures and now - failures[0] > 300:
                failures.popleft()
            if len(failures) == 5:
                alerts.append(_alert("AUTHENTICATION_ABUSE", "HIGH", 45.0,
                    "Repeated authentication failures were observed from one source.",
                    {"source": client, "server": src if client == dst else dst,
                     "failure_count": len(failures), "window_seconds": 300}, now))
        if payload and self.SUCCESS_RE.search(payload):
            known_services = {21, 22, 25, 110, 143, 389, 445, 3389, 587, 993, 995}
            client = dst if TCP in packet and int(packet[TCP].sport) in known_services else src
            failures = self.failures[client]
            while failures and now - failures[0] > 300:
                failures.popleft()
            if len(failures) >= 5:
                alerts.append(_alert("AUTHENTICATION_ABUSE", "HIGH", 45.0,
                    "A successful authentication followed a burst of failures from the same client.",
                    {"source": client, "server": src if client == dst else dst,
                     "failure_count": len(failures), "later_success": True,
                     "window_seconds": 300}, now))
                failures.clear()
        if any(layer in packet for layer in (ICMP, ICMPv6EchoRequest, ICMPv6EchoReply)) and payload:
            entropy = _entropy(payload)
            events = self.icmp_events[src]
            events.append((now, len(payload), entropy))
            while events and now - events[0][0] > 300:
                events.popleft()
            high_entropy = [event for event in events if event[2] >= 7.0]
            total_bytes = sum(event[1] for event in high_entropy)
            if (len(high_entropy) >= 10 and total_bytes >= 64 * 1024
                    and now - self.icmp_last_alert.get(src, -10_000.0) >= 300.0):
                self.icmp_last_alert[src] = now
                alerts.append(_alert("ICMP_TUNNELING", "HIGH", 45.0,
                    "Repeated high-entropy ICMP payloads exceeded 64 KiB in five minutes.",
                    {"source": src, "payload_count": len(high_entropy), "payload_bytes": total_bytes,
                     "mean_entropy": round(sum(event[2] for event in high_entropy) / len(high_entropy), 3)}, now))
        if TCP in packet:
            tcp = packet[TCP]
            sport, dport, flags = int(tcp.sport), int(tcp.dport), int(tcp.flags)
            ports = {sport, dport}
            dst = "unknown"
            if scapy.IP in packet: dst = str(packet[scapy.IP].dst)
            elif IPv6 in packet: dst = str(packet[IPv6].dst)
            connection, direction = None, None
            if dport == 443:
                connection, direction = (src, sport, dst, dport), "client"
                if flags & 0x02 and not flags & 0x10 and not payload:
                    self._remember(self.tls_connections, connection, self.MAX_TLS_CONNECTIONS)
            elif sport == 443:
                connection, direction = (dst, dport, src, sport), "server"
            marker = (connection, direction)
            initiator_direction = not flow or flow.l7_metadata.get("conversation_direction") in {None, "to_responder"}
            if (direction == "client" and initiator_direction and payload and len(payload) >= 5
                    and connection in self.tls_connections and marker not in self.tls_inspected):
                self._remember(self.tls_inspected, marker, self.MAX_TLS_CONNECTIONS * 2)
                tls_record = payload[0] in {0x14, 0x15, 0x16, 0x17} and payload[1] == 0x03 and payload[2] <= 0x04
                if not tls_record:
                    alerts.append(_alert("TLS_PROTOCOL_MISMATCH", "MEDIUM", 25.0,
                        "The first payload on an observed port-443 connection was not a TLS record.",
                        {"source": src, "application_bytes": len(payload),
                         "evidence_hash": __import__("hashlib").sha256(payload).hexdigest()}, now))
            signatures = ((b"SSH-", 22, "SSH"), (b"RFB ", 5900, "VNC"))
            for signature, expected_port, protocol in signatures:
                if payload.startswith(signature) and expected_port not in ports:
                    alerts.append(_alert("PROTOCOL_MISMATCH", "MEDIUM", 30.0,
                        f"{protocol} was identified on a nonstandard port.",
                        {"source": src, "identified_protocol": protocol, "ports": sorted(ports)}, now))
                    break
            if self._is_rdp_tpkt(payload) and 3389 not in ports:
                alerts.append(_alert(
                    "PROTOCOL_MISMATCH", "MEDIUM", 30.0,
                    "RDP transport was identified on a nonstandard port.",
                    {"source": src, "identified_protocol": "RDP", "ports": sorted(ports)}, now,
                ))
        return alerts


class IoTOTSafetyDetector(BaseDetector):
    name = "IoT and OT Safety Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.iot-ot.safety", name=name, input_kinds=("packet",),
        finding_types=("ot.modbus.unauthorized_write", "credential.cleartext.mqtt"),
        signal_family="ot-policy", correlation_group="iot-ot",
    )
    finding_metadata = {
        "ot.modbus.unauthorized_write": {"category": "POLICY_VIOLATION", "impact": "HIGH", "confidence": 0.9, "mitre_technique": "T0831", "correlation_group": "ot-policy"},
        "credential.cleartext.mqtt": {"category": "EXPOSURE", "impact": "HIGH", "confidence": 0.9, "correlation_group": "credential-exposure"},
    }
    MODBUS_WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}

    def __init__(self, policy=None):
        self.policy = dict(policy or {})

    def reset(self, source: str = None) -> None:
        return None

    def detect(self, packet=None, application_payload=None, **kwargs) -> List[ForensicAlert]:
        if packet is None:
            return []
        now = float(getattr(packet, "time", 0.0) or 0.0)
        payload = application_payload if application_payload is not None else _payload(packet)
        if TCP in packet and 502 in {int(packet[TCP].sport), int(packet[TCP].dport)}:
            if len(payload) >= 8 and payload[2:4] == b"\x00\x00" and payload[7] in self.MODBUS_WRITE_FUNCTIONS:
                src = str(packet[scapy.IP].src) if scapy.IP in packet else str(packet[IPv6].src) if IPv6 in packet else "unknown"
                if not self.policy.get("enabled"):
                    return []
                unit_id, function_code = int(payload[6]), int(payload[7])
                authorized_masters = set(self.policy.get("authorized_masters") or ())
                authorized_units = {int(value) for value in (self.policy.get("authorized_units") or ())}
                authorized_functions = {int(value) for value in (self.policy.get("authorized_write_functions") or ())}
                violations = []
                if authorized_masters and src not in authorized_masters: violations.append("master")
                if authorized_units and unit_id not in authorized_units: violations.append("unit")
                if authorized_functions and function_code not in authorized_functions: violations.append("function")
                if not violations:
                    return []
                return [_alert("UNSAFE_OT_COMMAND", "HIGH", 55.0,
                    "A Modbus write violated the configured master, unit, or function policy.",
                    {"source": src, "function_code": function_code, "unit_id": unit_id,
                     "policy_violations": violations}, now)]
        if TCP in packet and 1883 in {int(packet[TCP].sport), int(packet[TCP].dport)}:
            if len(payload) >= 10 and payload[0] >> 4 == 1 and payload[9] & 0xC0:
                return [_alert("IOT_CLEARTEXT_CREDENTIALS", "HIGH", 45.0,
                    "An unencrypted MQTT CONNECT packet declares username or password fields.",
                    {"username_flag": bool(payload[9] & 0x80), "password_flag": bool(payload[9] & 0x40)}, now)]
        return []
