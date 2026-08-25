"""Evidence-backed endpoint and flow context.

This module deliberately separates what a packet reveals at layer two from
what it reveals at layer three.  A routed packet's Ethernet source is a next
hop, not the remote IP owner's MAC address.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address, ip_interface
from typing import Any, Dict, Iterable, Optional


CONTROL_DESTINATIONS = {
    "224.0.0.1": "IPv4 all-host multicast",
    "224.0.0.22": "IGMP multicast membership",
    "224.0.0.251": "mDNS service discovery",
    "239.255.255.250": "SSDP service discovery",
    "ff02::1": "IPv6 all-nodes multicast",
    "ff02::2": "IPv6 all-routers multicast",
    "ff02::16": "IPv6 multicast listener discovery",
    "ff02::1:2": "IPv6 DHCP relay and servers multicast",
    "ff02::fb": "IPv6 mDNS service discovery",
}

# A port is transport context, not an identity claim.  These labels let an
# analyst distinguish familiar service traffic from traffic that needs a stream
# or packet-level follow-up without pretending that an unparsed flow is an
# application-layer fact.
TCP_SERVICES = {
    20: "FTP data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS session",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle database",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7680: "Windows Delivery Optimization",
    8008: "Google Cast HTTP",
    8009: "Google Cast control",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    5222: "XMPP",
    5228: "Google mobile messaging",
}

UDP_SERVICES = {
    7: "Echo",
    53: "DNS",
    67: "DHCP server",
    68: "DHCP client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS name service",
    138: "NetBIOS datagram",
    161: "SNMP",
    162: "SNMP trap",
    500: "IKE",
    514: "Syslog",
    5353: "mDNS",
    5355: "LLMNR",
    1900: "SSDP",
    3702: "WS-Discovery",
}


def ip_scope(ip: str) -> str:
    """Return an operator-facing address scope without treating multicast as global."""
    address = ip_address(ip)
    if address.is_unspecified:
        return "unspecified"
    if address.is_multicast:
        return "multicast"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_private:
        return "private"
    if address.is_global:
        return "global"
    return "reserved"


def usable_geo(geo: Any) -> Dict[str, Any]:
    """Keep only provider data that is meaningful for an investigation."""
    if not isinstance(geo, dict):
        return {}
    result = {
        key: geo.get(key)
        for key in ("country", "city", "asn", "isp", "org", "lat", "lng")
        if geo.get(key) not in (None, "", "Unknown", "Unknown ASN", "Unknown ISP", "Unknown Org", "International", "Remote", "Private", "Local Network")
    }
    return result if result.get("asn") or result.get("isp") or result.get("org") else {}


def _metadata(flow: Dict[str, Any]) -> Dict[str, Any]:
    value = flow.get("l7_metadata") or {}
    return value if isinstance(value, dict) else {}


@lru_cache(maxsize=1)
def _local_address_index() -> tuple[Dict[str, Dict[str, str]], set[str]]:
    """Return local addresses and directed broadcasts without network probing."""
    try:
        import psutil
        import socket
    except Exception:
        return {}, set()

    result: Dict[str, Dict[str, str]] = {}
    broadcasts: set[str] = {"255.255.255.255"}
    for interface, addresses in psutil.net_if_addrs().items():
        mac = next(
            (
                str(item.address).lower()
                for item in addresses
                if getattr(item, "family", None) == psutil.AF_LINK and item.address
            ),
            None,
        )
        for item in addresses:
            if getattr(item, "family", None) not in {socket.AF_INET, socket.AF_INET6}:
                continue
            value = str(item.address or "").split("%", 1)[0]
            try:
                ip_address(value)
            except ValueError:
                continue
            result[value] = {"interface": interface, "mac": mac or ""}
            if getattr(item, "family", None) == socket.AF_INET and getattr(item, "netmask", None):
                try:
                    broadcasts.add(str(ip_interface(f"{value}/{item.netmask}").network.broadcast_address))
                except ValueError:
                    pass
    return result, broadcasts


class CaptureEvidence:
    """Indexes only facts that were observed in a capture or on this host."""

    def __init__(self, flows: Iterable[Dict[str, Any]]):
        self.local_addresses, self.local_broadcasts = _local_address_index()
        self.endpoint_geo: Dict[str, Dict[str, Any]] = {}
        self.endpoint_names: Dict[str, list[Dict[str, str]]] = {}
        self.trusted_macs: Dict[str, Dict[str, str]] = {}
        self._build(flows)

    def _remember_mac(self, ip: Any, mac: Any, source: str) -> None:
        if not ip or not mac:
            return
        try:
            subject = str(ip_address(str(ip)))
        except ValueError:
            return
        value = str(mac).lower()
        if len(value.split(":")) != 6:
            return
        self.trusted_macs[subject] = {"mac": value, "source": source}

    def _remember_name(self, ip: Any, name: Any, source: str) -> None:
        if not ip or not name:
            return
        try:
            subject = str(ip_address(str(ip)))
        except ValueError:
            return
        value = str(name).strip().rstrip(".").lower()
        if not value:
            return
        records = self.endpoint_names.setdefault(subject, [])
        if not any(item["value"] == value for item in records):
            records.append({"value": value, "source": source})

    def _remember_geo(self, ip: Any, geo: Any) -> None:
        if not ip:
            return
        try:
            subject = str(ip_address(str(ip)))
        except ValueError:
            return
        value = usable_geo(geo)
        if not value:
            return
        prior = self.endpoint_geo.get(subject) or {}
        # Prefer the most complete ownership record, without letting a
        # packet-wide placeholder overwrite endpoint-specific enrichment.
        if len(value) >= len(prior):
            self.endpoint_geo[subject] = value

    def _build(self, flows: Iterable[Dict[str, Any]]) -> None:
        for ip, record in self.local_addresses.items():
            self._remember_mac(ip, record.get("mac"), "local_interface")

        for flow in flows:
            meta = _metadata(flow)
            # These are packet-time names, not reverse-DNS guesses.  Attach
            # them to the observed remote endpoint so identity cards can show
            # useful pivots even when a separate DNS answer was not captured.
            destination = str(flow.get("dst_ip") or "")
            source_ip = str(flow.get("src_ip") or "")
            geo = meta.get("geoip")
            explicit_destination = meta.get("geoip_destination_ip") or meta.get("enrichment_ip")
            explicit_source = meta.get("geoip_source_ip")
            self._remember_geo(explicit_destination or destination, geo)
            if explicit_source:
                self._remember_geo(explicit_source, meta.get("geoip_source") or geo)

            # ARP and NDP are direct neighbor protocols; their advertised MACs
            # are trustworthy for their advertised IPs.  Generic Ethernet frames
            # are intentionally excluded.
            self._remember_mac(meta.get("arp_sender_ip"), meta.get("arp_sender_mac"), "arp")
            self._remember_mac(meta.get("ndp_sender_ip"), meta.get("ndp_sender_mac"), "ndp")

            for key, evidence_source in (
                ("tls_sni", "tls_sni"), ("server_name", "tls_sni"),
                ("http_host", "http_host"), ("hostname", "protocol_hostname"),
                ("netbios_name", "netbios"), ("mdns_name", "mdns"),
                ("dhcp_hostname", "dhcp"),
            ):
                value = meta.get(key)
                if value:
                    self._remember_name(destination, value, evidence_source)
            for key in ("source_hostname", "source_name", "server_hostname"):
                value = meta.get(key)
                if value:
                    self._remember_name(meta.get("server_ip") or source_ip, value, "protocol_hostname")
            for key in ("dns_domain", "dns_query", "query_name"):
                value = meta.get(key)
                if value:
                    self._remember_name(destination, value, "dns_query")

            for answer in meta.get("dns_answers") or []:
                if not isinstance(answer, dict):
                    continue
                self._remember_name(answer.get("address"), answer.get("name"), "dns_answer")

    def endpoint(self, ip: str) -> Dict[str, Any]:
        scope = ip_scope(ip)
        local = self.local_addresses.get(ip)
        mac = self.trusted_macs.get(ip)
        return {
            "ip": ip,
            "scope": scope,
            "is_local_endpoint": bool(local),
            "local_interface": local.get("interface") if local else None,
            "is_local_broadcast": ip in self.local_broadcasts,
            "geoip": dict(self.endpoint_geo.get(ip) or {}),
            "names": list(self.endpoint_names.get(ip) or []),
            "mac": dict(mac) if mac else None,
        }

    @staticmethod
    def _service_observation(meta: Dict[str, Any], protocol: str, src_port: int, dst_port: int) -> Optional[Dict[str, Any]]:
        """Return a deliberately conservative application or port observation."""
        application = str(meta.get("application_protocol") or "").strip()
        if application:
            return {
                "name": application.upper(),
                "port": dst_port or src_port or None,
                "endpoint": "parsed",
                "basis": "application_parser",
            }

        if protocol == "TCP":
            services = TCP_SERVICES
        elif protocol == "UDP":
            services = UDP_SERVICES
        else:
            return None

        # The destination convention is more useful for client traffic, while
        # the source fallback preserves the context of reply-direction rows.
        for endpoint, port in (("destination", dst_port), ("source", src_port)):
            name = services.get(port)
            if name:
                return {
                    "name": name,
                    "port": port,
                    "endpoint": endpoint,
                    "basis": "well_known_port",
                }
        if protocol == "UDP" and (src_port == 443 or dst_port == 443):
            endpoint = "destination" if dst_port == 443 else "source"
            return {
                "name": "QUIC/UDP service",
                "port": 443,
                "endpoint": endpoint,
                "basis": "well_known_port",
            }
        return None

    @staticmethod
    def _traffic_direction(source: Dict[str, Any], destination: Dict[str, Any]) -> str:
        if destination.get("scope") in {"multicast", "unspecified"} or destination.get("is_local_broadcast"):
            return "control_or_discovery"
        if source.get("is_local_endpoint") and destination.get("is_local_endpoint"):
            return "local_host"
        if source.get("is_local_endpoint"):
            return "outbound_from_capture_host"
        if destination.get("is_local_endpoint"):
            return "inbound_to_capture_host"
        if source.get("scope") == "private" and destination.get("scope") == "private":
            return "private_network_lateral"
        if source.get("scope") == "private" and destination.get("scope") == "global":
            return "private_network_to_external"
        if source.get("scope") == "global" and destination.get("scope") == "private":
            return "external_to_private_network"
        return "unattributed_direction"

    @staticmethod
    def _recommended_action(purpose: str, direction: str, service: Optional[Dict[str, Any]],
                            destination_scope: str) -> str:
        if direction == "control_or_discovery" or "neighbor" in purpose.lower() or "control" in purpose.lower():
            return "Treat as local control or discovery traffic; investigate only if the sender or rate is unexpected."
        if direction == "inbound_to_capture_host":
            return "Confirm that inbound service exposure is expected for this capture host."
        if direction in {"outbound_from_capture_host", "private_network_to_external"}:
            if destination_scope == "private":
                return "Confirm that the private peer and observed service are expected on this local network."
            if service:
                return "Correlate the external peer with DNS, SNI, or HTTP host evidence and expected application use."
            return "Use packet or stream evidence to identify the unclassified external application if it matters to the case."
        if direction == "private_network_lateral":
            return "Confirm the local peer relationship and service are expected for these two private endpoints."
        if service:
            return "Use the observed service and endpoint history to determine whether this peer relationship is expected."
        return "Retain this transport observation as context; inspect packet or stream evidence only when investigation priority warrants it."

    def flow_context(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        source = str(flow.get("src_ip") or "")
        destination = str(flow.get("dst_ip") or "")
        protocol = str(flow.get("protocol") or "OTHER").upper()
        meta = _metadata(flow)
        src_port = int(flow.get("src_port") or 0)
        dst_port = int(flow.get("dst_port") or 0)
        source_endpoint = self.endpoint(source) if source else {}
        destination_endpoint = self.endpoint(destination) if destination else {}
        destination_scope = destination_endpoint.get("scope", "unknown")
        service = self._service_observation(meta, protocol, src_port, dst_port)
        direction = self._traffic_direction(source_endpoint, destination_endpoint)

        purpose = f"{protocol} transport observed ({src_port} -> {dst_port})"
        confidence = "observed"
        if meta.get("arp_operation") is not None or protocol == "ARP":
            purpose = "LAN neighbor resolution (ARP)"
        elif meta.get("ndp_event"):
            purpose = f"IPv6 neighbor/router control ({meta['ndp_event']})"
        elif destination in CONTROL_DESTINATIONS:
            purpose = CONTROL_DESTINATIONS[destination]
        elif meta.get("dns_domain"):
            purpose = "DNS response" if meta.get("dns_is_response") else "DNS query"
        elif meta.get("application_protocol"):
            purpose = f"{meta['application_protocol']} application traffic"
            confidence = "parsed"
        elif service:
            purpose = f"{service['name']} service transport observed ({service['port']}/{protocol})"
        elif destination_scope in {"multicast", "unspecified"} or destination_endpoint.get("is_local_broadcast"):
            purpose = "Network control or discovery traffic"

        evidence = [
            item for item in (
                "capture_flow_metadata.geoip" if self.endpoint_geo.get(destination) else None,
                "arp_or_ndp_binding" if self.trusted_macs.get(source) or self.trusted_macs.get(destination) else None,
                "dns_answer" if self.endpoint_names.get(destination) else None,
                "application_parser" if meta.get("application_protocol") else None,
                "well_known_port" if service and service.get("basis") == "well_known_port" else None,
            ) if item
        ]

        return {
            "version": "evidence-v1",
            "purpose": purpose,
            "confidence": confidence,
            "traffic_direction": direction,
            "service": service,
            "recommended_action": self._recommended_action(purpose, direction, service, destination_scope),
            "src": source_endpoint,
            "dst": destination_endpoint,
            "evidence": evidence,
        }
