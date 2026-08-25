"""Passive IP intelligence assembled from WatchTower observations and cached lookups."""

from __future__ import annotations

from ipaddress import ip_address
from collections import Counter
from typing import Any, Dict, List, Optional
import time
import json

from core.intelligence.local_assets import LocalAssetProfiler, SERVICE_NAMES, classify_ip
from core.intelligence.evidence import CaptureEvidence, usable_geo
from core.packet_engine.utils import get_geoip_info, get_reverse_dns


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"unknown", "none", "n/a", "null"}:
        return None
    return text


def _public_geo_value(geo: Dict[str, Any], key: str) -> Optional[str]:
    value = _clean(geo.get(key))
    if value in {"Unknown ASN", "Unknown ISP", "Unknown Org", "International", "Remote"}:
        return None
    return value


def _first(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = _clean(value)
        if cleaned:
            return cleaned
    return None


def _top_services(profile: Dict[str, Any], limit: int = 8) -> List[Dict[str, Any]]:
    services = []
    for direction, key in (("served", "served_services"), ("consumed", "consumed_services")):
        for item in profile.get(key) or []:
            service = dict(item)
            service["direction"] = direction
            service.setdefault("name", SERVICE_NAMES.get(int(service.get("port") or 0), "Unknown"))
            services.append(service)
    return sorted(
        services,
        key=lambda item: (-int(item.get("packets") or 0), str(item.get("direction")), int(item.get("port") or 0)),
    )[:limit]


class IpLookupService:
    """Build an operator-facing IP profile without active probing."""

    def __init__(self, db):
        self.db = db
        self.asset_profiler = LocalAssetProfiler(db)

    def _cached_public(self, ip: str, provider: str, loader):
        key = f"identity.public_enrichment.{provider}.{ip}"
        try:
            stored = self.db.get_metadata(key)
            if stored:
                value = json.loads(stored)
                if float(value.get("expires_at") or 0) > time.time():
                    return value.get("value")
        except (TypeError, ValueError, AttributeError):
            pass
        try:
            value = loader()
        except Exception:
            value = None
        ttl = 30 * 86400 if value else 6 * 3600
        try:
            self.db.set_metadata(key, json.dumps({
                "ip": ip, "provider": provider, "value": value,
                "fetched_at": time.time(), "expires_at": time.time() + ttl,
            }, sort_keys=True, default=str))
        except Exception:
            pass
        return value

    def lookup(self, ip: str, source: Optional[str] = None, persist: bool = True,
               sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        try:
            address = ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {ip}") from exc

        scope, subnet = classify_ip(ip)
        entity = self.db.get_entity(ip) or {"ip": ip}
        effective_source = source or entity.get("source") or "live"
        flow_kwargs = {"source": source, "limit": 5000}
        alert_kwargs = {"entity_ip": ip, "source": source, "limit": 1000}
        file_kwargs = {"entity_ip": ip, "source": source}
        if sensor_node_id:
            flow_kwargs["sensor_node_id"] = sensor_node_id
            alert_kwargs["sensor_node_id"] = sensor_node_id
            file_kwargs["sensor_node_id"] = sensor_node_id
        flows = self.db.get_entity_flows(ip, **flow_kwargs)
        alerts = self.db.get_alerts(**alert_kwargs)
        files = self.db.get_carved_files(**file_kwargs)
        evidence = CaptureEvidence(flows)
        endpoint = evidence.endpoint(ip)
        profile = self.asset_profiler.build(
            ip, source=source, persist=persist, sensor_node_id=sensor_node_id,
        ).to_dict()

        is_local = scope in {"private", "loopback", "link-local", "multicast", "unspecified"} or bool(endpoint.get("is_local_endpoint"))
        allow_public_enrichment = scope == "global" and not bool(endpoint.get("is_local_endpoint"))
        # Do not send private, multicast, link-local, or local interface
        # addresses through public DNS/GeoIP enrichment.  Those addresses need
        # local passive identity evidence, not an Internet lookup.
        reverse_dns = _first(
            entity.get("reverse_dns"),
            self._cached_public(ip, "ptr", lambda: get_reverse_dns(ip)) if allow_public_enrichment else None,
        )
        captured_geo = usable_geo(endpoint.get("geoip"))
        # Capture-time provider data is reproducible evidence.  It must win
        # over a fresh, rate-limited provider request during historical hunt.
        geo = captured_geo or (self._cached_public(ip, "geoip", lambda: get_geoip_info(ip)) if allow_public_enrichment else {}) or {}
        safe_entity = dict(entity)
        trusted_mac = (endpoint.get("mac") or {}).get("mac")
        safe_entity["mac"] = trusted_mac
        if not trusted_mac:
            safe_entity["vendor"] = None
        remote_endpoint = scope == "global" and not endpoint.get("is_local_endpoint")
        if remote_endpoint and safe_entity.get("device_type") in {"Web Server", "Client / Workstation", "Multi-service Host"}:
            safe_entity["device_type"] = None
        organization = _first(
            safe_entity.get("vendor") if is_local else None,
            _public_geo_value(geo, "org"),
            _public_geo_value(geo, "isp"),
        )
        company = organization
        hostname = _first(safe_entity.get("hostname"), safe_entity.get("netbios_name"), reverse_dns)
        device_type = _first(safe_entity.get("device_type"), None if remote_endpoint else profile.get("role"))
        location = self._location(scope, geo)
        observed_names = self._observed_names(safe_entity, reverse_dns, profile, endpoint.get("names") or [])
        activity = self._activity(safe_entity, flows, alerts, files, profile)
        identity = self._identity(safe_entity, hostname, organization, company, device_type, reverse_dns)
        endpoint_identity = (
            self.db.get_endpoint_identity(ip, source=source, sensor_node_id=sensor_node_id)
            if sensor_node_id and hasattr(self.db, "get_endpoint_identity")
            else self.db.get_endpoint_identity(ip, source=source) if hasattr(self.db, "get_endpoint_identity") else None
        )
        if hasattr(self.db, "get_endpoint_process_observations"):
            process_kwargs = {"ip": ip, "limit": 25}
            if sensor_node_id:
                process_kwargs["sensor_node_id"] = sensor_node_id
            endpoint_processes = self.db.get_endpoint_process_observations(**process_kwargs)
        else:
            endpoint_processes = []
        enrichment = self._enrichment(scope, subnet, address.version, geo, reverse_dns, observed_names)
        enrichment["evidence_source"] = (
            "capture_flow_metadata" if captured_geo
            else "provider_fallback" if allow_public_enrichment
            else "not_applicable"
        )
        enrichment["is_local_endpoint"] = bool(endpoint.get("is_local_endpoint"))
        enrichment["local_interface"] = endpoint.get("local_interface")
        gaps = self._gaps(scope, safe_entity, profile, geo, reverse_dns, flows, endpoint)
        next_actions = self._next_actions(scope, profile, gaps, alerts)
        flow_contexts = [evidence.flow_context(flow) for flow in flows]
        direction_counts = Counter(context.get("traffic_direction") for context in flow_contexts if context.get("traffic_direction"))
        action_counts = Counter(context.get("recommended_action") for context in flow_contexts if context.get("recommended_action"))
        services: Dict[tuple, Dict[str, Any]] = {}
        for flow, context in zip(flows, flow_contexts):
            service = context.get("service") or {}
            if not service:
                continue
            key = (service.get("name"), service.get("port"), flow.get("protocol"), service.get("basis"))
            item = services.setdefault(key, {
                "name": service.get("name"),
                "port": service.get("port"),
                "protocol": flow.get("protocol"),
                "basis": service.get("basis"),
                "flow_count": 0,
            })
            item["flow_count"] += 1

        return {
            "ip": ip,
            "source": effective_source,
            "generated_at": time.time(),
            "scope": scope,
            "subnet": subnet,
            "ip_version": address.version,
            "is_private": bool(address.is_private),
            "is_global": bool(address.is_global),
            "summary": self._summary(ip, scope, identity, activity, gaps),
            "identity": identity,
            "endpoint_identity": endpoint_identity,
            "endpoint_processes": endpoint_processes,
            "enrichment": enrichment,
            "asset_profile": profile,
            "activity": activity,
            "services": _top_services(profile),
            "peers": {
                "internal": list(profile.get("internal_peers") or [])[:10],
                "external": list(profile.get("external_peers") or [])[:10],
            },
            "observed_names": observed_names,
            "flow_intelligence": {
                "total_flows": len(flow_contexts),
                "purposes": sorted({item["purpose"] for item in flow_contexts}),
                "directions": dict(sorted(direction_counts.items())),
                "services": sorted(
                    services.values(),
                    key=lambda item: (-item["flow_count"], str(item["name"]), int(item["port"] or 0)),
                )[:12],
                "recommended_actions": [
                    action for action, _count in action_counts.most_common(5)
                ],
                "capture_geo_available": bool(captured_geo),
                "trusted_mac_source": (endpoint.get("mac") or {}).get("source"),
            },
            "location": location,
            "gaps": gaps,
            "next_actions": next_actions,
        }

    @staticmethod
    def _observed_names(entity: Dict[str, Any], reverse_dns: Optional[str], profile: Dict[str, Any],
                        resolved_names: List[Dict[str, str]] = None) -> List[Dict[str, str]]:
        names = []
        for label, value, source in (
            ("hostname", entity.get("hostname"), entity.get("identity_source") or "entity"),
            ("netbios", entity.get("netbios_name"), entity.get("identity_source") or "entity"),
            ("reverse_dns", reverse_dns, "reverse_dns"),
        ):
            cleaned = _clean(value)
            if cleaned:
                names.append({"type": label, "value": cleaned, "source": source})
        for domain in (profile.get("domains") or [])[:20]:
            if domain and all(item["value"] != domain for item in names):
                names.append({"type": "observed_domain", "value": str(domain), "source": "flow_metadata"})
        for record in resolved_names or []:
            value = _clean(record.get("value"))
            if value and all(item["value"] != value for item in names):
                names.append({"type": "dns_answer", "value": value, "source": record.get("source") or "dns_answer"})
        return names

    @staticmethod
    def _location(scope: str, geo: Dict[str, Any]) -> Dict[str, Any]:
        if scope in {"private", "loopback", "link-local", "multicast", "unspecified"}:
            return {
                "label": "Local network" if scope == "private" else scope.replace("-", " ").title(),
                "city": None,
                "country": "Local Network",
                "latitude": 0.0,
                "longitude": 0.0,
            }
        city = _public_geo_value(geo, "city")
        country = _public_geo_value(geo, "country")
        label = ", ".join(part for part in (city, country) if part) or "Unknown public location"
        return {
            "label": label,
            "city": city,
            "country": country,
            "latitude": float(geo.get("lat") or 0.0),
            "longitude": float(geo.get("lng") or 0.0),
        }

    @staticmethod
    def _identity(entity: Dict[str, Any], hostname, organization, company, device_type, reverse_dns) -> Dict[str, Any]:
        return {
            "hostname": hostname,
            "reverse_dns": reverse_dns,
            "mac": _clean(entity.get("mac")),
            "vendor": _clean(entity.get("vendor")),
            "organization": organization,
            "company": company,
            "device_type": device_type,
            "asset_role": _clean(entity.get("asset_role")),
            "os": _clean(entity.get("os")),
            "username": _clean(entity.get("username")),
            "full_name": _clean(entity.get("full_name")),
            "identity_source": _clean(entity.get("identity_source")),
            "identity_confidence": float(entity.get("confidence_score") or 0.0),
        }

    @staticmethod
    def _enrichment(scope, subnet, version, geo, reverse_dns, observed_names) -> Dict[str, Any]:
        return {
            "scope": scope,
            "subnet": subnet,
            "ip_version": version,
            "asn": _public_geo_value(geo, "asn"),
            "isp": _public_geo_value(geo, "isp"),
            "org": _public_geo_value(geo, "org"),
            "reverse_dns": reverse_dns,
            "observed_name_count": len(observed_names),
            "source": "watchtower-passive,dns,geoip-cache",
        }

    @staticmethod
    def _activity(entity, flows, alerts, files, profile) -> Dict[str, Any]:
        first_seen = profile.get("first_seen") or entity.get("first_seen")
        last_seen = profile.get("last_seen") or entity.get("last_seen")
        protocols = sorted({str(flow.get("protocol") or "OTHER") for flow in flows})
        # Entity counters are cross-source lifetime aggregates.  An IP lookup
        # must report the selected capture scope when flows are available.
        total_packets = sum(int(flow.get("packet_count") or 0) for flow in flows)
        total_bytes = sum(int(flow.get("byte_count") or 0) for flow in flows)
        return {
            "flow_count": len(flows),
            "alert_count": len(alerts),
            "artifact_count": len(files),
            "total_packets": total_packets if flows else int(entity.get("total_packets") or 0),
            "total_bytes": total_bytes if flows else int(entity.get("total_bytes") or 0),
            "outbound_bytes": int(profile.get("outbound_bytes") or 0),
            "inbound_bytes": int(profile.get("inbound_bytes") or 0),
            "protocols": protocols[:12],
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    @staticmethod
    def _gaps(scope, entity, profile, geo, reverse_dns, flows, endpoint=None) -> List[str]:
        gaps = []
        endpoint = endpoint or {}
        if scope in {"private", "link-local"}:
            if not _clean(entity.get("mac")):
                gaps.append("No MAC address has been observed, so manufacturer/OUI cannot be inferred.")
            if not _first(entity.get("hostname"), entity.get("netbios_name")):
                gaps.append("No DHCP, NBNS, mDNS, SMB, Kerberos, or similar hostname evidence has been observed.")
            if not _clean(entity.get("device_type")) and profile.get("role") == "Unclassified":
                gaps.append("No service or discovery fingerprint is strong enough to classify the device type.")
        elif scope == "global":
            if not reverse_dns:
                gaps.append("Reverse DNS did not resolve or has not been observed.")
            if not (_public_geo_value(geo, "org") or _public_geo_value(geo, "isp")):
                gaps.append("GeoIP/ASN data is unavailable or too generic for ownership attribution.")
            if not profile.get("domains") and not endpoint.get("names"):
                gaps.append("No DNS, SNI, or HTTP host metadata was associated with this IP in stored flows.")
        if not flows:
            gaps.append("No WatchTower flows are stored for this IP in the selected source.")
        return gaps

    @staticmethod
    def _next_actions(scope, profile, gaps, alerts) -> List[str]:
        actions = []
        if alerts:
            actions.append("Open the investigation timeline and review alert evidence linked to this IP.")
        if profile.get("served_services"):
            actions.append("Confirm observed served services are expected for this asset or external peer.")
        if scope in {"private", "link-local"}:
            actions.append("Keep passive capture running through DHCP/NBNS/mDNS/SMB activity to improve hostname and device attribution.")
            if any("MAC address" in gap for gap in gaps):
                actions.append("Use passive ARP/NDP observations or an authorized local survey to learn the MAC/vendor.")
        elif scope == "global":
            actions.append("Correlate this IP with DNS/SNI/HTTP host metadata from recent flows before treating GeoIP ownership as definitive.")
        if not actions:
            actions.append("Continue passive observation until WatchTower has enough identity and service evidence.")
        return actions

    @staticmethod
    def _summary(ip, scope, identity, activity, gaps) -> str:
        name = _first(identity.get("hostname"), identity.get("reverse_dns"), identity.get("organization"), ip) or ip
        role = _first(identity.get("asset_role"), identity.get("device_type"), scope)
        flow_count = int(activity.get("flow_count") or 0)
        gap_text = " ".join(gaps[:2]) if gaps else "Identity context is supported by current observations."
        return f"{name} is currently classified as {role} with {flow_count} stored flow(s). {gap_text}"
