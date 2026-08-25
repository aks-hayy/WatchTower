"""Passive local-asset profiling built from Watchtower's stored evidence."""

from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional, Set, Tuple
import time

from core.intelligence.evidence import CaptureEvidence


SERVICE_NAMES = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD Printing",
    587: "SMTP Submission",
    631: "IPP Printing",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    9100: "JetDirect Printing",
}

SERVER_PORTS = set(SERVICE_NAMES) - {68, 5353, 1900}


@dataclass
class LocalAssetProfile:
    ip: str
    source: str
    scope: str
    subnet: Optional[str]
    role: str
    role_confidence: float
    role_reasons: List[str] = field(default_factory=list)
    served_services: List[Dict] = field(default_factory=list)
    consumed_services: List[Dict] = field(default_factory=list)
    internal_peers: List[Dict] = field(default_factory=list)
    external_peers: List[Dict] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    inbound_packets: int = 0
    outbound_packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    identity_completeness: float = 0.0
    insights: List[str] = field(default_factory=list)
    profiled_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)


def classify_ip(ip: str) -> Tuple[str, Optional[str]]:
    address = ip_address(ip)
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link-local"
    elif address.is_multicast:
        scope = "multicast"
    elif address.is_unspecified:
        scope = "unspecified"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "global"
    else:
        scope = "reserved"

    if address.version == 4 and scope in {"private", "link-local"}:
        subnet = str(ip_network(f"{ip}/24", strict=False))
    elif address.version == 6 and scope in {"private", "link-local"}:
        subnet = str(ip_network(f"{ip}/64", strict=False))
    else:
        subnet = None
    return scope, subnet


def _is_internal(ip: str) -> bool:
    try:
        address = ip_address(ip)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return False


class LocalAssetProfiler:
    """Builds a reproducible asset profile from entity and flow records."""

    def __init__(self, db):
        self.db = db

    def build(self, ip: str, source: Optional[str] = None, persist: bool = True,
              sensor_node_id: Optional[str] = None) -> LocalAssetProfile:
        entity = self.db.get_entity(ip) or {"ip": ip}
        effective_source = source or entity.get("source") or "live"
        flow_kwargs = {"source": source, "limit": 5000}
        if sensor_node_id:
            flow_kwargs["sensor_node_id"] = sensor_node_id
        flows = self.db.get_entity_flows(ip, **flow_kwargs)
        scope, subnet = classify_ip(ip)
        evidence = CaptureEvidence(flows)
        endpoint = evidence.endpoint(ip)
        # Entity rows created by older captures may contain a gateway MAC on a
        # routed public IP.  Profile only direct ARP/NDP or local-interface
        # MAC evidence, never a generic Ethernet source.
        entity = dict(entity)
        trusted_mac = (endpoint.get("mac") or {}).get("mac")
        entity["mac"] = trusted_mac
        if not trusted_mac:
            entity["vendor"] = None

        served: Dict[Tuple[int, str], Dict] = {}
        consumed: Dict[Tuple[int, str], Dict] = {}
        peers: Dict[str, Dict] = {}
        domains: Set[str] = set()
        inbound_bytes = outbound_bytes = inbound_packets = outbound_packets = 0
        timestamps = []

        for flow in flows:
            is_outbound = flow.get("src_ip") == ip
            peer = flow.get("dst_ip") if is_outbound else flow.get("src_ip")
            byte_count = int(flow.get("byte_count") or 0)
            packet_count = int(flow.get("packet_count") or 0)
            timestamps.extend(ts for ts in (flow.get("start_time"), flow.get("last_seen")) if ts)

            peer_stats = peers.setdefault(peer, {"ip": peer, "bytes": 0, "packets": 0})
            peer_stats["bytes"] += byte_count
            peer_stats["packets"] += packet_count

            if is_outbound:
                outbound_bytes += byte_count
                outbound_packets += packet_count
                port = int(flow.get("dst_port") or 0)
                self._add_service(consumed, port, flow, byte_count, packet_count)
                src_port = int(flow.get("src_port") or 0)
                if src_port in SERVER_PORTS:
                    self._add_service(served, src_port, flow, byte_count, packet_count)
            else:
                inbound_bytes += byte_count
                inbound_packets += packet_count
                port = int(flow.get("dst_port") or 0)
                if port in SERVER_PORTS:
                    self._add_service(served, port, flow, byte_count, packet_count)

            metadata = flow.get("l7_metadata") or {}
            if isinstance(metadata, dict):
                self._collect_domains(metadata, domains)

        served_services = sorted(served.values(), key=lambda item: (-item["packets"], item["port"]))
        consumed_services = sorted(consumed.values(), key=lambda item: (-item["packets"], item["port"]))
        internal_peers = self._sorted_peers(peers, internal=True)
        external_peers = self._sorted_peers(peers, internal=False)
        role, role_confidence, reasons = self._infer_role(
            entity, served_services, consumed_services,
            external_endpoint=scope == "global" and not endpoint.get("is_local_endpoint"),
        )
        completeness = self._identity_completeness(entity)
        insights = self._build_insights(
            entity, served_services, internal_peers, external_peers,
            inbound_bytes, outbound_bytes, completeness,
        )

        profile = LocalAssetProfile(
            ip=ip,
            source=effective_source,
            scope=scope,
            subnet=subnet,
            role=role,
            role_confidence=role_confidence,
            role_reasons=reasons,
            served_services=served_services,
            consumed_services=consumed_services,
            internal_peers=internal_peers,
            external_peers=external_peers,
            domains=sorted(domains)[:100],
            inbound_bytes=inbound_bytes,
            outbound_bytes=outbound_bytes,
            inbound_packets=inbound_packets,
            outbound_packets=outbound_packets,
            first_seen=min(timestamps) if timestamps else entity.get("first_seen"),
            last_seen=max(timestamps) if timestamps else entity.get("last_seen"),
            identity_completeness=completeness,
            insights=insights,
        )

        if persist:
            self.db.upsert_asset_profile(profile.to_dict())
            # A public peer responding on port 443 is an observed service, not
            # a proven device role.  Do not turn that into canonical identity.
            if scope != "global" or endpoint.get("is_local_endpoint"):
                self.db.update_entity_asset_role(ip, role)
        return profile

    def build_many(self, ips: List[str], source: str, persist: bool = True) -> Dict[str, LocalAssetProfile]:
        """Build several source-scoped profiles from one flow query.

        Offline PCAP analysis commonly has hundreds of endpoints.  Calling
        ``get_entity_flows`` per endpoint repeatedly decoded the same source
        rows and dominated the analysis tail.  This adapter preserves the
        established single-profile implementation while serving it immutable
        in-memory evidence.
        """
        requested = sorted({str(ip) for ip in ips if ip})
        if not requested:
            return {}
        wanted = set(requested)
        flows_by_ip = {ip: [] for ip in requested}
        for flow in self.db.get_source_flows(source):
            src, dst = str(flow.get("src_ip") or ""), str(flow.get("dst_ip") or "")
            if src in wanted:
                flows_by_ip[src].append(flow)
            if dst in wanted and dst != src:
                flows_by_ip[dst].append(flow)
        entities = self.db.get_entities_by_ips(requested)

        class _CachedProfileDB:
            def __init__(self, delegate):
                self._delegate = delegate

            def get_entity(self, ip):
                return dict(entities.get(str(ip)) or {"ip": str(ip)})

            def get_entity_flows(self, ip, source=None, limit=5000):
                return list(flows_by_ip.get(str(ip), ()))[:limit]

            def upsert_asset_profile(self, profile):
                return self._delegate.upsert_asset_profile(profile)

            def update_entity_asset_role(self, ip, role):
                return self._delegate.update_entity_asset_role(ip, role)

        cached_profiler = LocalAssetProfiler(_CachedProfileDB(self.db))
        return {
            ip: cached_profiler.build(ip, source=source, persist=persist)
            for ip in requested
        }

    @staticmethod
    def _add_service(target: Dict, port: int, flow: Dict, byte_count: int, packet_count: int):
        if port not in SERVICE_NAMES:
            return
        key = (port, flow.get("protocol") or "OTHER")
        service = target.setdefault(key, {
            "port": port,
            "protocol": key[1],
            "name": SERVICE_NAMES[port],
            "bytes": 0,
            "packets": 0,
        })
        service["bytes"] += byte_count
        service["packets"] += packet_count

    @staticmethod
    def _collect_domains(value, domains: Set[str]):
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in {"remote_hostname", "sni", "domain", "dns_query", "host"}:
                    LocalAssetProfiler._collect_domains(nested, domains)
                elif isinstance(nested, (dict, list, tuple, set)):
                    LocalAssetProfiler._collect_domains(nested, domains)
        elif isinstance(value, (list, tuple, set)):
            for nested in value:
                LocalAssetProfiler._collect_domains(nested, domains)
        elif isinstance(value, str):
            candidate = value.strip().lower().rstrip(".")
            if "." in candidate and " " not in candidate and len(candidate) <= 253:
                domains.add(candidate)

    @staticmethod
    def _sorted_peers(peers: Dict[str, Dict], internal: bool) -> List[Dict]:
        selected = [stats for peer, stats in peers.items() if _is_internal(peer) == internal]
        return sorted(selected, key=lambda item: (-item["bytes"], item["ip"]))[:25]

    @staticmethod
    def _infer_role(entity: Dict, served: List[Dict], consumed: List[Dict],
                    external_endpoint: bool = False) -> Tuple[str, float, List[str]]:
        if external_endpoint:
            if served:
                names = ", ".join(service["name"] for service in served[:3])
                return "External service endpoint", 0.55, [f"Observed responding on {names}; not device identity"]
            return "External network peer", 0.40, ["Observed IP peer; no local asset identity is inferred"]
        existing = entity.get("asset_role")
        ports = {service["port"] for service in served}
        role_rules = [
            ({88, 389, 636}, "Directory / Authentication Server", 0.94),
            ({53}, "DNS Server", 0.90),
            ({67}, "DHCP Server", 0.90),
            ({445, 139}, "File Server", 0.86),
            ({9100, 631, 515}, "Network Printer", 0.92),
            ({1433, 3306, 5432, 6379}, "Database Server", 0.88),
            ({80, 443, 8080, 8443}, "Web Server", 0.82),
            ({22, 3389, 5900}, "Remote Administration Host", 0.76),
        ]
        for required, role, confidence in role_rules:
            matched = ports & required
            if matched:
                names = ", ".join(SERVICE_NAMES[port] for port in sorted(matched))
                return role, confidence, [f"Observed serving {names}"]

        device_type = (entity.get("device_type") or "").lower()
        if any(token in device_type for token in ("tv", "speaker", "streamer", "iot")):
            return "IoT / Media Device", 0.82, [f"Device fingerprint: {entity.get('device_type')}"]
        if served:
            return "Multi-service Host", 0.68, [f"Observed {len(served)} served service(s)"]
        if consumed:
            return "Client / Workstation", 0.62, ["Initiates service connections without observed server services"]
        if existing and existing.lower() not in {"unknown", "client", "workstation", "unclassified"}:
            return existing, 0.75, ["Previously identified asset role; no contradicting traffic observed"]
        return "Unclassified", 0.25, ["Insufficient observed traffic"]

    @staticmethod
    def _identity_completeness(entity: Dict) -> float:
        fields = ("mac", "hostname", "username", "os", "vendor", "device_type")
        present = sum(bool(entity.get(field) and str(entity[field]).lower() != "unknown") for field in fields)
        return round(present / len(fields), 2)

    @staticmethod
    def _build_insights(entity, served, internal_peers, external_peers, inbound, outbound, completeness):
        insights = []
        if served:
            names = ", ".join(service["name"] for service in served[:4])
            insights.append(f"Provides {names} to observed peers")
        if external_peers:
            insights.append(f"Communicates with {len(external_peers)} external peer(s)")
        if internal_peers:
            insights.append(f"Connected to {len(internal_peers)} internal peer(s)")
        total = inbound + outbound
        if total:
            outbound_ratio = outbound / total
            if outbound_ratio >= 0.85:
                insights.append("Traffic is strongly outbound-oriented")
            elif outbound_ratio <= 0.15:
                insights.append("Traffic is strongly inbound-oriented")
        if completeness < 0.5:
            insights.append("Device attributes are incomplete; more passive observation is needed")
        if not insights:
            insights.append("No strong behavioral characteristics observed yet")
        return insights
