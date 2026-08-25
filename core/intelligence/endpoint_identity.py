"""Versioned endpoint identity cards built from trustworthy WatchTower evidence.

An endpoint identity describes what WatchTower can actually associate with an
address in one capture scope. It deliberately distinguishes a hostname or
organization from a reliable address role such as a multicast group or direct
LAN neighbor. No record turns a port, a routed Ethernet MAC, or an unverified
guess into a device identity.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Optional

from core.intelligence.evidence import CONTROL_DESTINATIONS, CaptureEvidence, ip_scope, usable_geo
from core.intelligence.host_inventory import HostNetworkInventory


IDENTITY_MODEL_VERSION = "endpoint-identity-v2"


def _manufacturer(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    try:
        from scapy.config import conf
        value = str(conf.manufdb._get_manuf(mac) or "").strip()
    except Exception:
        return None
    return value if value and value.lower() != mac.lower() else None


def _role_label(roles: Iterable[str]) -> Optional[str]:
    labels = {
        "default_gateway": "Default gateway",
        "dhcp_server": "DHCP server",
        "dns_server": "DNS server",
    }
    values = [labels[item] for item in sorted(set(roles)) if item in labels]
    return " / ".join(values) or None


def _eui64_mac(ip: str) -> Optional[str]:
    """Recover the original MAC only from an IPv6 modified EUI-64 interface ID."""
    try:
        address = ip_address(ip)
    except ValueError:
        return None
    if address.version != 6:
        return None
    value = address.packed[-8:]
    if value[3:5] != b"\xff\xfe":
        return None
    mac = bytes((value[0] ^ 0x02, value[1], value[2], value[5], value[6], value[7]))
    return ":".join(f"{byte:02x}" for byte in mac)


@dataclass(frozen=True)
class EndpointIdentityRecord:
    entity_ip: str
    source: str
    capture_interface: Optional[str]
    capture_session_id: Optional[str]
    model_version: str
    identity_type: str
    identity_label: str
    confidence: float
    verification: str
    evidence: List[Dict[str, Any]]
    first_seen: Optional[float]
    last_seen: Optional[float]
    identity_state: str = ""
    evidence_completeness: float = -1.0
    next_action: Optional[str] = None
    observation_count: int = 0

    def __post_init__(self) -> None:
        if not self.identity_state:
            if any(item.get("kind") == "arp_target_observation" for item in self.evidence):
                state = "unconfirmed_target"
            elif self.identity_type in {"capture_host", "direct_network_neighbor"}:
                state = "confirmed_endpoint"
            elif self.identity_type in {"multicast_group", "broadcast_group", "special_address"}:
                state = "protocol_group"
            elif self.verification == "address_only":
                state = "address_only"
            else:
                state = "probable_endpoint"
            object.__setattr__(self, "identity_state", state)
        if self.evidence_completeness < 0:
            completeness = min(1.0, max((float(item.get("confidence") or 0.0) for item in self.evidence), default=0.0))
            object.__setattr__(self, "evidence_completeness", round(completeness, 2))
        if self.next_action is None:
            actions = {
                "confirmed_endpoint": "Review protocol, process, and service evidence",
                "probable_endpoint": "Confirm with a direct binding or protocol identity",
                "unconfirmed_target": "Wait for an ARP/NDP response or run bounded live confirmation",
                "protocol_group": "Use protocol events and member observations for investigation",
                "address_only": "Run cached public enrichment or collect more protocol evidence",
            }
            object.__setattr__(self, "next_action", actions.get(self.identity_state, "Collect more evidence"))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EndpointIdentityResolver:
    """Consolidates raw capture and local inventory facts into endpoint cards."""

    def __init__(self, flows: Iterable[Dict[str, Any]], inventory: Optional[HostNetworkInventory] = None,
                 observations: Optional[Iterable[Dict[str, Any]]] = None):
        self.flows = [dict(flow) for flow in flows]
        self.evidence = CaptureEvidence(self.flows)
        self.inventory = inventory or HostNetworkInventory.collect()
        self.confirmed_macs: Dict[str, Dict[str, str]] = {}
        for observation in observations or ():
            if observation.get("observation_type") not in {"arp_binding", "ndp_binding", "active_arp_confirmation"}:
                continue
            value = observation.get("value") or {}
            if value.get("mac"):
                self.confirmed_macs[str(observation.get("subject_ip"))] = {
                    "mac": str(value["mac"]).lower(), "source": "active_confirmation" if observation.get("observation_type") == "active_arp_confirmation" else "captured_binding",
                }
        self.by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for flow in self.flows:
            for value in (flow.get("src_ip"), flow.get("dst_ip")):
                try:
                    ip = str(ip_address(str(value)))
                except ValueError:
                    continue
                self.by_ip[ip].append(flow)

    @staticmethod
    def _time_bounds(flows: List[Dict[str, Any]]) -> tuple[Optional[float], Optional[float]]:
        values = [
            float(flow[key]) for flow in flows for key in ("start_time", "last_seen")
            if flow.get(key) is not None
        ]
        return (min(values), max(values)) if values else (None, None)

    @staticmethod
    def _purposes(flows: List[Dict[str, Any]]) -> List[str]:
        values = set()
        for flow in flows:
            metadata = flow.get("l7_metadata") or {}
            context = metadata.get("watchtower_intel_v1") if isinstance(metadata, dict) else {}
            if isinstance(context, dict) and context.get("purpose"):
                values.add(str(context["purpose"]))
        return sorted(values)[:4]

    @staticmethod
    def _arp_target(flows: List[Dict[str, Any]], ip: str) -> bool:
        return any(
            str((flow.get("l7_metadata") or {}).get("arp_target_ip") or "") == ip
            for flow in flows
        )

    @staticmethod
    def _service_context(flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for flow in flows:
            metadata = flow.get("l7_metadata") or {}
            context = metadata.get("watchtower_intel_v1") if isinstance(metadata, dict) else {}
            service = context.get("service") if isinstance(context, dict) else None
            parser_keys = {"application_protocol", "tls_sni", "http_host", "server_name", "ssh_banner", "smb_dialect", "mqtt_client_id"}
            parser_confirmed = isinstance(metadata, dict) and any(metadata.get(key) for key in parser_keys)
            if isinstance(service, dict) and service.get("name") and (service.get("basis") == "application_parser" or parser_confirmed):
                service = dict(service)
                service["basis"] = service.get("basis") if service.get("basis") == "application_parser" else "protocol_metadata"
                return {
                    "name": str(service["name"]), "port": service.get("port"),
                    "protocol": str(flow.get("protocol") or "OTHER"),
                }
        return None

    @staticmethod
    def _observed_services(flows: List[Dict[str, Any]], ip: str) -> List[Dict[str, Any]]:
        """Summarize bounded service evidence without treating ports as proof."""
        services: Dict[tuple, Dict[str, Any]] = {}
        for flow in flows:
            if str(flow.get("dst_ip")) == ip:
                port = int(flow.get("dst_port") or 0)
            elif str(flow.get("src_ip")) == ip:
                port = int(flow.get("src_port") or 0)
            else:
                continue
            metadata = flow.get("l7_metadata") or {}
            observed = CaptureEvidence._service_observation(
                metadata, str(flow.get("protocol") or "OTHER").upper(),
                int(flow.get("src_port") or 0), int(flow.get("dst_port") or 0),
            )
            parser_confirmed = any(metadata.get(key) for key in {
                "application_protocol", "tls_sni", "http_host", "server_name", "ssh_banner", "smb_dialect", "mqtt_client_id",
            })
            if not observed or (observed.get("basis") == "well_known_port" and not parser_confirmed):
                continue
            key = (observed.get("name"), observed.get("port"), observed.get("protocol"))
            item = services.setdefault(key, {**observed, "flows": 0, "bytes": 0})
            item["flows"] += 1
            item["bytes"] += int(flow.get("byte_count") or 0)
        return sorted(services.values(), key=lambda item: (-item["flows"], str(item["name"])))[:8]

    @staticmethod
    def _evidence(kind: str, summary: str, confidence: float, **details: Any) -> Dict[str, Any]:
        return {
            "kind": kind,
            "summary": summary,
            "confidence": round(float(confidence), 2),
            "details": {key: value for key, value in details.items() if value not in (None, "", [], {})},
        }

    def _record(self, ip: str, source: str, interface: Optional[str], session_id: Optional[str]) -> EndpointIdentityRecord:
        endpoint = self.evidence.endpoint(ip)
        flows = self.by_ip[ip]
        first_seen, last_seen = self._time_bounds(flows)
        scope = endpoint["scope"]
        evidence: List[Dict[str, Any]] = []

        local = self.inventory.local_addresses.get(ip)
        if local:
            label = f"Capture host {self.inventory.hostname} ({local.get('interface') or 'local interface'})"
            evidence.append(self._evidence(
                "local_interface_inventory", "Address belongs to the local capture host", 1.0,
                interface=local.get("interface"), mac=local.get("mac"), observed_at=self.inventory.observed_at,
            ))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "capture_host", label,
                1.0, "verified", evidence, first_seen, last_seen,
            )

        if scope == "multicast":
            label = CONTROL_DESTINATIONS.get(ip, f"IPv{ip_address(ip).version} multicast group {ip}")
            evidence.append(self._evidence("protocol_address", "Standard multicast group address", 1.0, address=ip))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "multicast_group", label,
                1.0, "verified", evidence, first_seen, last_seen,
            )

        if scope == "unspecified":
            label = f"IPv{ip_address(ip).version} unspecified address"
            evidence.append(self._evidence("protocol_address", "Protocol-defined unspecified address", 1.0, address=ip))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "special_address", label,
                1.0, "verified", evidence, first_seen, last_seen,
            )

        if endpoint.get("is_local_broadcast") or ip == "255.255.255.255":
            label = "Directed broadcast for the local Ethernet network" if endpoint.get("is_local_broadcast") else "IPv4 limited broadcast"
            evidence.append(self._evidence(
                "protocol_address", "Broadcast address derived from local interface network configuration", 1.0,
                address=ip,
            ))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "broadcast_group", label,
                1.0, "verified", evidence, first_seen, last_seen,
            )

        if scope == "global":
            geo = usable_geo(endpoint.get("geoip"))
            organization = geo.get("org") or geo.get("isp") or geo.get("asn")
            names = [str(item.get("value")) for item in endpoint.get("names") or [] if item.get("value")]
            name_hint = names[0] if names else None
            if organization:
                asn = geo.get("asn")
                suffix = f" ({asn})" if asn and asn not in str(organization) else ""
                label = f"{organization}{suffix} / {name_hint}" if name_hint else f"{organization} network endpoint{suffix}"
                evidence.append(self._evidence(
                    "capture_geoip", "Ownership information captured with observed traffic", 0.93,
                    organization=organization, asn=asn, country=geo.get("country"), city=geo.get("city"),
                ))
                for name in endpoint.get("names") or []:
                    evidence.append(self._evidence("dns_answer", "Observed DNS answer association", 0.88, name=name.get("value")))
                return EndpointIdentityRecord(
                    ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "network_organization", label,
                    0.93, "captured", evidence, first_seen, last_seen,
                )
            label = f"Public network endpoint {ip}"
            evidence.append(self._evidence(
                "capture_address", "Observed public IP address without ownership metadata", 0.3, address=ip,
            ))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "public_endpoint", label,
                0.3, "address_only", evidence, first_seen, last_seen,
            )

        captured_mac = (endpoint.get("mac") or {}).get("mac")
        captured_source = (endpoint.get("mac") or {}).get("source")
        if not captured_mac and ip in self.confirmed_macs:
            captured_mac = self.confirmed_macs[ip]["mac"]
            captured_source = self.confirmed_macs[ip]["source"]
        cached_mac = self.inventory.neighbors.get(ip)
        roles = self.inventory.roles.get(ip, set())
        eui64_mac = _eui64_mac(ip)
        mac = captured_mac or eui64_mac or cached_mac
        role = _role_label(roles)
        vendor = _manufacturer(mac)
        if mac:
            if captured_mac:
                evidence.append(self._evidence(
                    f"capture_{captured_source}", "Direct ARP/NDP binding observed in the capture", 0.98,
                    mac=mac, vendor=vendor,
                ))
                confidence = 0.99 if role else 0.96
                verification = "captured"
            elif eui64_mac:
                evidence.append(self._evidence(
                    "ipv6_eui64", "MAC recovered from a modified EUI-64 IPv6 interface identifier", 0.94,
                    mac=mac, vendor=vendor,
                ))
                confidence = 0.98 if role else 0.94
                verification = "captured"
            else:
                evidence.append(self._evidence(
                    "current_neighbor_cache", "Current host neighbor-cache binding; not packet-time evidence", 0.9,
                    mac=mac, vendor=vendor, observed_at=self.inventory.observed_at,
                ))
                confidence = 0.94 if role else 0.9
                verification = "current_host_state"
            if role:
                label = f"{role} ({mac})"
            else:
                label = f"LAN neighbor {mac}" + (f" ({vendor})" if vendor else "")
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "direct_network_neighbor", label,
                confidence, verification, evidence, first_seen, last_seen,
            )

        purposes = self._purposes(flows)
        services = self._observed_services(flows, ip)
        if role:
            label = f"{role} ({ip})"
            evidence.append(self._evidence(
                "local_network_configuration", "Role observed in local host network configuration", 0.98,
                role=role, observed_at=self.inventory.observed_at,
            ))
            return EndpointIdentityRecord(
                ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "network_service_role", label,
                0.98, "current_host_state", evidence, first_seen, last_seen,
            )
        if scope == "link-local":
            label = f"IPv{ip_address(ip).version} link-local endpoint {ip}"
            identity_type = "link_local_endpoint"
        elif scope == "private":
            service = self._service_context(flows)
            names = [str(item.get("value")) for item in endpoint.get("names") or [] if item.get("value")]
            if self._arp_target(flows, ip):
                label = f"ARP resolution target {ip} (no direct reply captured)"
                evidence.append(self._evidence(
                    "arp_target_observation", "An ARP request named this address but no reply binding was captured",
                    0.2, address=ip, confirmation_required=True,
                ))
            elif service:
                label = f"Private endpoint observed for {service['name']} ({service['port']}/{service['protocol']})"
                evidence.append(self._evidence(
                    "observed_service", "Parser-confirmed service metadata was observed for this endpoint",
                    0.78, service=service,
                ))
                return EndpointIdentityRecord(
                    ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "network_service_endpoint", label,
                    0.78, "captured", evidence, first_seen, last_seen,
                )
            elif services:
                names = ", ".join(f"{item['name']} ({item['port']})" for item in services[:3])
                label = f"Private service endpoint {ip}: {names}"
                evidence.append(self._evidence(
                    "observed_service", "Application or well-known service context observed in flows",
                    0.72, services=services,
                ))
                return EndpointIdentityRecord(
                    ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "network_service_endpoint", label,
                    0.72, "captured", evidence, first_seen, last_seen,
                )
            elif names:
                label = f"Named private endpoint {names[0]} ({ip})"
                evidence.append(self._evidence(
                    "protocol_name", "Hostname or service name observed in captured protocol metadata",
                    0.7, names=names[:8],
                ))
                return EndpointIdentityRecord(
                    ip, source, interface, session_id, IDENTITY_MODEL_VERSION, "named_private_endpoint", label,
                    0.7, "captured", evidence, first_seen, last_seen,
                )
            else:
                label = f"Private network endpoint {ip}"
            identity_type = "private_endpoint"
        else:
            label = f"Network endpoint {ip}"
            identity_type = "address_endpoint"
        evidence.append(self._evidence(
            "capture_address", "Address and scoped traffic observations", 0.25,
            scope=scope, flow_count=len(flows), purposes=purposes,
        ))
        return EndpointIdentityRecord(
            ip, source, interface, session_id, IDENTITY_MODEL_VERSION, identity_type, label,
            0.25, "address_only", evidence, first_seen, last_seen,
        )

    def resolve(self, source: str, interface: Optional[str], session_id: Optional[str]) -> List[EndpointIdentityRecord]:
        return [
            self._record(ip, source, interface, session_id)
            for ip in sorted(self.by_ip, key=lambda value: (ip_address(value).version, int(ip_address(value))))
        ]

    @staticmethod
    def coverage(records: Iterable[EndpointIdentityRecord]) -> Dict[str, Any]:
        values = list(records)
        types = Counter(record.identity_type for record in values)
        verification = Counter(record.verification for record in values)
        states = Counter(record.identity_state for record in values)
        actionable = [record for record in values if record.identity_state in {"confirmed_endpoint", "probable_endpoint"}]
        evidence_backed = [record for record in values if record.identity_state not in {"address_only", "unconfirmed_target"}]
        return {
            "endpoints": len(values),
            "address_coverage": len(values),
            "observed_addresses": len(values),
            "confirmed_endpoints": states.get("confirmed_endpoint", 0),
            "probable_endpoints": states.get("probable_endpoint", 0),
            "unconfirmed_targets": states.get("unconfirmed_target", 0),
            "address_only": states.get("address_only", 0),
            "evidence_backed_identities": len(evidence_backed),
            "actionable_identities": len(actionable),
            "strong_identities": sum(record.confidence >= 0.9 for record in actionable),
            # Compatibility projection: protocol groups remain identifiable
            # records, while v2 consumers use actionable_identities for host
            # investigation counts.
            "identified": len(values) - states.get("address_only", 0) - states.get("unconfirmed_target", 0),
            "identity_types": dict(sorted(types.items())),
            "verification": dict(sorted(verification.items())),
        }
