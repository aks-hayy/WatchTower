"""Application service translating internal WatchTower records into API DTOs."""

from dataclasses import asdict
import base64
from hashlib import sha256
import ipaddress
import json
import os
import platform
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import psutil
import yaml

from core import __version__
from core.capture_sources import default_registry
from core.api.pcap_jobs import PcapJobManager
from core.backend_policy import BackendPolicyError, backend_policy
from core.ai.config import AIConfig, CredentialStore
from core.ai.contracts import ScopedContext
from core.ai.orchestrator import AIOrchestrator
from core.ai.provider_service import AIProviderService
from core.ai.providers import ProviderUnavailable
from core.context import context
from core.daemon.client import DaemonClient
from core.intelligence.ip_lookup import IpLookupService
from core.investigation.service import InvestigationService
from core.storage.database import WatchtowerDB
from core.utils.network import format_flow_id


class ApiServiceError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str, details: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


class WatchtowerApiService:
    def __init__(self, db=None, daemon=None, registry=None, jobs=None):
        self.db = db or WatchtowerDB()
        self.daemon = daemon or DaemonClient()
        if daemon is None:
            self.daemon._timeout = 1.5
        self.registry = registry or default_registry()
        self.jobs = jobs or PcapJobManager(self.db)
        self._daemon_cache = (0.0, {"running": False})
        self._daemon_lock = threading.Lock()
        self._capture_stop_lock = threading.Lock()
        self._capture_stops: Dict[str, Dict[str, Any]] = {}
        self._read_cache_lock = threading.RLock()
        self._device_inventory_cache = (0.0, [])
        self._entity_cache: Dict[Any, Any] = {}
        self._stats_cache: Dict[Any, Any] = {}
        self._topology_cache: Dict[Any, Any] = {}
        self.ai = AIOrchestrator(self.db, self)
        self.ai_providers = AIProviderService(self.db)
        self._mesh = None
        self._graph = None
        self.graph_worker = None

    def mesh(self):
        if self._mesh is None:
            from core.mesh.service import MeshControllerService
            self._mesh = MeshControllerService(self.db)
        return self._mesh

    def graph(self):
        if self._graph is None:
            from core.graph.service import EvidenceGraphService
            self._graph = EvidenceGraphService(self.db)
        return self._graph

    def _cached(self, cache: Dict, key: Any, ttl: float, producer):
        now = time.monotonic()
        with self._read_cache_lock:
            cached = cache.get(key)
            if cached and now - cached[0] < ttl:
                return cached[1]
            value = producer()
            cache[key] = (now, value)
            return value

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
                return decoded if isinstance(decoded, dict) else {}
            except (TypeError, ValueError):
                return {}
        return {}

    @staticmethod
    def _decode_cursor(cursor: Any) -> Dict[str, Any]:
        if cursor in (None, "", 0, "0"):
            return {}
        if isinstance(cursor, int) or str(cursor).isdigit():
            return {"offset": max(0, int(cursor))}
        try:
            padding = "=" * (-len(str(cursor)) % 4)
            value = json.loads(base64.urlsafe_b64decode(str(cursor) + padding).decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ApiServiceError(422, "invalid_cursor", "The page cursor is invalid or expired")

    @staticmethod
    def _encode_cursor(payload: Dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _live_match(record: Dict, source: Optional[str]) -> bool:
        if not source:
            return True
        record_source = str(record.get("source") or "")
        return record_source.startswith("live") if source == "live" else record_source == source

    def daemon_status(self, force: bool = False) -> Dict[str, Any]:
        checked_at, cached = self._daemon_cache
        cache_ttl = 1.0 if cached.get("running") else 10.0
        if not force and time.monotonic() - checked_at < cache_ttl:
            return cached
        with self._daemon_lock:
            checked_at, cached = self._daemon_cache
            cache_ttl = 1.0 if cached.get("running") else 10.0
            if not force and time.monotonic() - checked_at < cache_ttl:
                return cached
            try:
                result = self.daemon.get_status()
                status = result if isinstance(result, dict) else {"running": False}
            except Exception as exc:
                status = {"running": False, "healthy": False, "message": str(exc)}
            self._daemon_cache = (time.monotonic(), status)
            return status

    def health(self) -> Dict[str, Any]:
        database = "ok"
        try:
            self.db.get_capture_sessions(limit=1)
        except Exception:
            database = "error"
        daemon = self.daemon_status()
        daemon_running = bool(daemon.get("running"))
        return {
            "status": "ok" if database == "ok" else "degraded",
            "version": __version__,
            "database": database,
            "daemon": "online" if daemon_running else "offline",
            "daemon_healthy": daemon_running and bool(daemon.get("healthy", True)),
        }

    def capabilities(self) -> Dict[str, Any]:
        devices = self.devices()
        return {
            "api_version": "v1",
            "ai_mode": "local-agentic",
            "ai_provider_ready": False,
            "capture_backends": sorted({backend for item in devices for backend in item["backends"]}),
            "capture_sources": sorted({item["source_type"] for item in devices}),
            "features": {
                "flows": True,
                "alerts": True,
                "investigation": True,
                "historical_sigma_hunt": True,
                "pcap_analysis": True,
                "capture_control": True,
                "plugin_inventory": True,
                "sigma_management": True,
                "behavioral_scoring_v2": True,
                "ip_lookup": True,
                "evidence_enrichment": True,
                "endpoint_identity": True,
                "ai": True,
            },
        }

    def system_info(self) -> Dict[str, Any]:
        boot_time = psutil.boot_time()
        disk_root = os.path.abspath(os.sep)
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "uptime": max(0.0, time.time() - boot_time),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage(disk_root).percent,
            "is_admin": context.is_admin,
            "capture_capable": context.is_admin,
            "version": __version__,
        }

    def devices(self) -> List[Dict[str, Any]]:
        daemon = self.daemon_status()
        engines = daemon.get("engines") or {}
        result = []
        with self._read_cache_lock:
            cached_at, devices = self._device_inventory_cache
            if time.monotonic() - cached_at >= 30.0:
                try:
                    devices = self.registry.list_devices()
                except Exception as exc:
                    raise ApiServiceError(503, "source_discovery_failed", str(exc)) from exc
                self._device_inventory_cache = (time.monotonic(), devices)
        address_map = psutil.net_if_addrs()
        for device in devices:
            item = asdict(device)
            addresses = address_map.get(device.name) or []
            item["mac"] = next(
                (str(address.address) for address in addresses if getattr(address, "family", None) == psutil.AF_LINK),
                None,
            )
            engine = engines.get(device.device_id) or engines.get(device.name)
            item["capturing"] = bool(engine)
            item["engine"] = engine
            result.append(item)
        return result

    def sessions(self, interface: Optional[str], limit: int, sensor_node_id: Optional[str] = None) -> List[Dict[str, Any]]:
        daemon = self.daemon_status()
        engines = daemon.get("engines") or {}
        return [
            self._capture_session_projection(self._merge_live_session(row, engines))
            for row in self.db.get_capture_sessions(interface=interface, limit=limit, sensor_node_id=sensor_node_id)
        ]

    def flows(
        self,
        source: Optional[str],
        interface: Optional[str],
        session: Optional[str],
        entity: Optional[str],
        protocol: Optional[str],
        port: Optional[int],
        limit: int,
        offset: int = 0,
        sensor_node_id: Optional[str] = None,
        after_packet_count: Optional[int] = None,
        after_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        kwargs = {
            "source": source,
            "interface": interface,
            "capture_session_id": session,
            "limit": limit,
        }
        if protocol:
            kwargs["protocol"] = protocol
        if port is not None:
            kwargs["port"] = port
        if after_packet_count is not None and after_id is not None:
            kwargs["after_packet_count"] = after_packet_count
            kwargs["after_id"] = after_id
        if offset:
            kwargs["offset"] = offset
        if sensor_node_id:
            kwargs["sensor_node_id"] = sensor_node_id
        if entity:
            rows = self.db.get_entity_flows(entity, **kwargs)
        else:
            rows = self.db.get_flows(**kwargs)
        identities = self._flow_identity_summaries(rows, source, interface, session)
        result = []
        for row in rows:
            item = dict(row)
            item["src_port"] = int(item.get("src_port") or 0)
            item["dst_port"] = int(item.get("dst_port") or 0)
            item["l7_metadata"] = self._safe_dict(item.get("l7_metadata"))
            item["flow_id"] = item.get("flow_id") or format_flow_id(
                item.get("src_ip"), item["src_port"], item.get("dst_ip"), item["dst_port"], item.get("protocol"),
            )
            item["src_identity"] = identities.get(self._identity_key(item, "src_ip"))
            item["dst_identity"] = identities.get(self._identity_key(item, "dst_ip"))
            result.append(item)
        return result[:limit]

    @staticmethod
    def _identity_key(flow: Dict[str, Any], endpoint_field: str) -> tuple[str, str, str, str]:
        return (
            str(flow.get(endpoint_field) or ""),
            str(flow.get("source") or ""),
            str(flow.get("capture_interface") or ""),
            str(flow.get("capture_session_id") or ""),
        )

    def _flow_identity_summaries(
        self,
        rows: List[Dict[str, Any]],
        source: Optional[str],
        interface: Optional[str],
        session: Optional[str],
    ) -> Dict[tuple[str, str, str, str], Dict[str, Any]]:
        """Fetch one bounded identity projection for the current flow page."""
        if not rows or not hasattr(self.db, "get_endpoint_identities"):
            return {}
        identities = self.db.get_endpoint_identities(
            source=source,
            interface=interface,
            capture_session_id=session,
            limit=min(10000, max(1000, len(rows) * 2)),
        )
        fields = (
            "entity_ip", "identity_type", "identity_label", "confidence", "verification",
            "identity_state", "evidence_completeness", "next_action", "observation_count",
            "model_version", "updated_at",
        )
        return {
            (
                str(row.get("entity_ip") or ""),
                str(row.get("source") or ""),
                str(row.get("capture_interface") or ""),
                str(row.get("capture_session_id") or ""),
            ): {field: row.get(field) for field in fields}
            for row in identities
        }

    def alerts(
        self,
        source: Optional[str],
        interface: Optional[str],
        session: Optional[str],
        entity: Optional[str],
        severity: Optional[str],
        limit: int,
        offset: int = 0,
        sensor_node_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        kwargs = dict(
            entity_ip=entity,
            source=source,
            interface=interface,
            capture_session_id=session,
            limit=limit,
        )
        if sensor_node_id:
            kwargs["sensor_node_id"] = sensor_node_id
        if offset:
            kwargs["offset"] = offset
        rows = self.db.get_alerts(**kwargs)
        result = []
        for row in rows:
            if severity and str(row.get("severity") or "").upper() != severity.upper():
                continue
            item = dict(row)
            item["evidence"] = self._safe_dict(item.get("evidence"))
            item["entity_ip"] = str(item.get("entity_ip") or "unknown")
            result.append(item)
        return result[:limit]

    @staticmethod
    def _page(items: List[Dict[str, Any]], limit: int, next_cursor: Optional[str]) -> Dict[str, Any]:
        has_more = len(items) > limit
        return {
            "items": items[:limit],
            "next_cursor": next_cursor if has_more else None,
            "limit": limit,
        }

    @staticmethod
    def _offset_page(items: List[Dict[str, Any]], cursor: int, limit: int) -> Dict[str, Any]:
        has_more = len(items) > limit
        return {
            "items": items[:limit],
            "next_cursor": cursor + limit if has_more else None,
            "limit": limit,
        }

    def flow_page(self, source=None, interface=None, session=None, entity=None,
                  protocol=None, port=None, limit=100, cursor=0, sensor_node_id=None):
        position = self._decode_cursor(cursor)
        items = self.flows(
            source, interface, session, entity, protocol, port, limit + 1,
            int(position.get("offset") or 0), sensor_node_id,
            position.get("packet_count"), position.get("id"),
        )
        last = items[min(limit, len(items)) - 1] if items else None
        next_cursor = self._encode_cursor({
            "packet_count": int(last.get("packet_count") or 0),
            "id": int(last.get("id") or 0),
        }) if last else None
        return self._page(items, limit, next_cursor)

    def alert_page(self, source=None, interface=None, session=None, entity=None,
                   severity=None, limit=100, cursor=0, sensor_node_id=None):
        position = self._decode_cursor(cursor)
        rows = self.db.get_detection_findings(
            subject=entity, source=source, interface=interface,
            capture_session_id=session, include_suppressed=False,
            limit=limit + 1, sensor_node_id=sensor_node_id,
            after_last_seen=position.get("last_seen"), after_id=position.get("id"),
            offset=int(position.get("offset") or 0),
        )
        risk_rows = self.db.get_risk_snapshots(
            source, interface, session, limit=500, sensor_node_id=sensor_node_id,
        )
        risk_by_subject = {str(item["subject"]): item for item in risk_rows}
        items = []
        for row in rows:
            risk = risk_by_subject.get(str(row.get("subject"))) or {}
            contributor = next(
                (
                    item for item in risk.get("contributors") or []
                    if int(item.get("finding_id") or -1) == int(row.get("id") or -2)
                ),
                {},
            )
            item = {
                **row,
                "entity_ip": row.get("subject"),
                "severity": row.get("impact"),
                "impact": row.get("impact"),
                "effective_contribution": float(contributor.get("effective_contribution") or 0.0),
                "current_entity_priority": float(risk.get("priority_score") or 0.0),
                "risk_level": risk.get("risk_level") or "LOW",
                "assessment_confidence": float(risk.get("assessment_confidence") or 0.0),
                "scope": {"type": risk.get("scope_type"), "id": risk.get("scope_id")},
                "processing_completeness": "complete",
            }
            if severity and str(item["impact"] or "").upper() != str(severity).upper():
                continue
            items.append(item)
        last = rows[min(limit, len(rows)) - 1] if rows else None
        next_cursor = self._encode_cursor({
            "last_seen": float(last.get("last_seen") or 0.0),
            "id": int(last.get("id") or 0),
        }) if last else None
        return self._page(items, limit, next_cursor)

    def finding_page(self, subject=None, source=None, interface=None, session=None,
                     finding_type=None, include_suppressed=False, limit=100,
                     cursor=None, sensor_node_id=None):
        position = self._decode_cursor(cursor)
        rows = self.db.get_detection_findings(
            subject=subject, source=source, interface=interface,
            capture_session_id=session, finding_type=finding_type,
            include_suppressed=include_suppressed, limit=limit + 1,
            sensor_node_id=sensor_node_id,
            after_last_seen=position.get("last_seen"), after_id=position.get("id"),
            offset=int(position.get("offset") or 0),
        )
        last = rows[min(limit, len(rows)) - 1] if rows else None
        next_cursor = self._encode_cursor({
            "last_seen": float(last.get("last_seen") or 0.0),
            "id": int(last.get("id") or 0),
        }) if last else None
        return self._page(rows, limit, next_cursor)

    def topology_page(self, source=None, interface=None, session=None, limit=100, cursor=0, sensor_node_id=None):
        page = self.flow_page(source, interface, session, None, None, None, limit, cursor, sensor_node_id)
        entities = {item["ip"]: item for item in self.entities(source, None, 500)}
        priorities = {
            item["subject"]: item
            for item in self.scoring_entities(source, interface, session, limit=500, offset=0, sensor_node_id=sensor_node_id)["items"]
        }
        node_ids = {ip for flow in page["items"] for ip in (flow.get("src_ip"), flow.get("dst_ip")) if ip}
        nodes = [{"data": {
            "id": ip,
            "label": entities.get(ip, {}).get("hostname") or ip,
            "type": entities.get(ip, {}).get("asset_role") or entities.get(ip, {}).get("device_type") or "unknown",
            "risk": float(priorities.get(ip, {}).get("priority_score") or 0),
            "risk_level": priorities.get(ip, {}).get("risk_level", "LOW"),
            "assessment_confidence": float(priorities.get(ip, {}).get("assessment_confidence") or 0),
        }} for ip in sorted(node_ids)]
        edges = [{"data": {
            "source": flow.get("src_ip"), "target": flow.get("dst_ip"),
            "weight": int(flow.get("byte_count") or 0),
        }} for flow in page["items"]]
        return {"nodes": nodes, "edges": edges, "next_cursor": page["next_cursor"], "limit": limit}

    def flow_detail(self, flow_id: int) -> Dict[str, Any]:
        row = self.db.get_flow(flow_id)
        if not row:
            raise ApiServiceError(404, "flow_not_found", f"Flow {flow_id} was not found")
        identities = self._flow_identity_summaries(
            [row], row.get("source"), row.get("capture_interface"), row.get("capture_session_id"),
        )
        row["src_identity"] = identities.get(self._identity_key(row, "src_ip"))
        row["dst_identity"] = identities.get(self._identity_key(row, "dst_ip"))
        metadata = self._safe_dict(row.get("l7_metadata"))
        row["l7_metadata"] = metadata
        row["process_attribution"] = metadata.get("process_attribution") or {
            "provenance": "unattributed",
            "confidence": 0.0,
        }
        findings = self.db.get_detection_findings(
            source=row.get("source"), interface=row.get("capture_interface"),
            capture_session_id=row.get("capture_session_id"), limit=250,
            sensor_node_id=row.get("sensor_node_id"),
        )
        row["findings"] = [
            item for item in findings
            if str(item.get("subject")) in {str(row.get("src_ip")), str(row.get("dst_ip"))}
            and str((item.get("evidence") or {}).get("dst_ip") or row.get("dst_ip")) == str(row.get("dst_ip"))
        ]
        row["risk"] = self.scoring_risk(
            row.get("src_ip"), row.get("source"), row.get("capture_interface"),
            row.get("capture_session_id"), sensor_node_id=row.get("sensor_node_id"),
        )
        return row

    def finding_detail(self, finding_id: int) -> Dict[str, Any]:
        finding = self.db.get_detection_finding(finding_id)
        if not finding:
            raise ApiServiceError(404, "finding_not_found", f"Finding {finding_id} was not found")
        finding["risk"] = self.scoring_risk(
            finding["subject"], finding.get("source"), finding.get("capture_interface"),
            finding.get("capture_session_id"), explain=True,
            sensor_node_id=finding.get("sensor_node_id"),
        )
        return finding

    def entities(self, source: Optional[str], search: Optional[str], limit: int,
                 sensor_node_id: Optional[str] = None) -> List[Dict[str, Any]]:
        key = (source or "", search or "", int(limit), sensor_node_id or "")

        def load():
            rows = self.db.get_all_entities(source=None)
            allowed_ips = None
            if sensor_node_id and hasattr(self.db, "node_endpoint_ips"):
                allowed_ips = set(self.db.node_endpoint_ips(sensor_node_id))
            needle = (search or "").casefold()
            result = []
            for row in rows:
                if not self._live_match(row, source):
                    continue
                if allowed_ips is not None and str(row.get("ip") or "") not in allowed_ips:
                    continue
                if needle and not any(
                    needle in str(row.get(field) or "").casefold()
                    for field in ("ip", "mac", "hostname", "username", "os", "vendor", "device_type", "asset_role")
                ):
                    continue
                result.append(dict(row))
            return result[:limit]

        return self._cached(self._entity_cache, key, 2.0, load)

    def evidence(self, source: Optional[str], entity: Optional[str]) -> List[Dict[str, Any]]:
        return self.db.get_carved_files(entity_ip=entity, source=source)

    def stats(self, source: str, interface: Optional[str],
              sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        return self._cached(
            self._stats_cache, (source, interface, sensor_node_id), 2.0,
            lambda: self._stats_uncached(source, interface, sensor_node_id),
        )

    def _stats_uncached(self, source: str, interface: Optional[str],
                        sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        effective_source = f"live_{interface}" if interface and source == "live" else source
        if sensor_node_id and hasattr(self.db, "_get_session"):
            return self._node_stats(sensor_node_id, interface)
        use_window = hasattr(self.db, "get_window_stats")
        raw = (
            self.db.get_window_stats(source=source, interface=interface, window_seconds=86400)
            if use_window else self.db.get_today_stats(source=effective_source)
        )
        alerts = self.alerts(source, interface, None, None, None, 10000)
        if use_window:
            cutoff = float(raw.get("window_start") or 0)
            alerts = [item for item in alerts if float(item.get("timestamp") or 0) >= cutoff]
        severities = {key: 0 for key in ("critical", "high", "medium", "low")}
        for alert in alerts:
            key = str(alert.get("severity") or "low").lower()
            severities[key if key in severities else "low"] += 1
        protocols = raw.get("protocol_distribution") or {}
        ports = raw.get("port_distribution") or {}
        total_protocol = sum(int(value or 0) for value in protocols.values()) or 1
        total_ports = sum(int(value or 0) for value in ports.values()) or 1
        timeline = []
        for value in (raw.get("traffic_timeline") or {}).values():
            timestamp = float(value.get("time") or 0)
            timeline.append({
                "timestamp": timestamp,
                "packets_per_sec": round(float(value.get("packets") or 0) / (300 if use_window else 1), 2),
                "bytes_per_sec": round(float(value.get("bytes") or 0) / (300 if use_window else 1), 2),
                "flows": 0,
            })
        timeline.sort(key=lambda item: item["timestamp"])
        return {
            "source": effective_source,
            "window_start": raw.get("window_start"),
            "window_end": raw.get("window_end"),
            "window_hours": 24,
            "total_packets": int(raw.get("total_packets") or 0),
            "total_bytes": int(raw.get("total_bytes") or 0),
            "total_flows": int(raw.get("total_flows") or 0),
            "active_hosts": int(
                raw["active_hosts"] if "active_hosts" in raw else len(self.entities(source, None, 10000))
            ),
            "alerts": severities,
            "protocols": [
                {"protocol": str(key), "count": int(value), "percentage": round(int(value) * 100 / total_protocol, 1)}
                for key, value in sorted(protocols.items(), key=lambda pair: int(pair[1]), reverse=True)
            ],
            "ports": [
                {"port": int(key), "service": "", "count": int(value), "percentage": round(int(value) * 100 / total_ports, 1)}
                for key, value in sorted(ports.items(), key=lambda pair: int(pair[1]), reverse=True)
                if str(key).isdigit()
            ],
            "timeline": timeline,
            "top_talkers": [
                {"ip": key, "bytes": int(value), "hostname": ""}
                for key, value in sorted((raw.get("top_talkers") or {}).items(), key=lambda pair: int(pair[1]), reverse=True)
            ],
        }

    def _node_stats(self, sensor_node_id: str, interface: Optional[str]) -> Dict[str, Any]:
        summary = self.db.node_flow_summary(sensor_node_id, interface=interface)
        cutoff = summary["cutoff"]
        protocol_rows = summary["protocol_rows"]
        port_rows = summary["port_rows"]
        timeline_rows = summary["timeline_rows"]
        talker_rows = summary["talker_rows"]
        alerts = self.alerts(None, interface, None, None, None, 10000, sensor_node_id=sensor_node_id)
        severities = {key: 0 for key in ("critical", "high", "medium", "low")}
        for alert in alerts:
            key = str(alert.get("severity") or "low").lower()
            severities[key if key in severities else "low"] += 1
        protocol_total = sum(int(row[1] or 0) for row in protocol_rows) or 1
        port_total = sum(int(row[1] or 0) for row in port_rows) or 1
        return {
            "source": f"node:{sensor_node_id}",
            "window_start": cutoff,
            "window_end": time.time(),
            "window_hours": 24,
            "total_packets": summary["total_packets"],
            "total_bytes": summary["total_bytes"],
            "total_flows": summary["total_flows"],
            "active_hosts": summary["active_hosts"],
            "alerts": severities,
            "protocols": [
                {"protocol": str(name or "OTHER"), "count": int(count), "percentage": round(int(count) * 100 / protocol_total, 1)}
                for name, count in sorted(protocol_rows, key=lambda row: int(row[1] or 0), reverse=True)
            ],
            "ports": [
                {"port": int(port), "service": "", "count": int(count), "percentage": round(int(count) * 100 / port_total, 1)}
                for port, count in port_rows
            ],
            "timeline": [
                {"timestamp": int(value) * 300, "packets_per_sec": round(int(packets) / 300, 2),
                 "bytes_per_sec": round(int(byte_count) / 300, 2), "flows": int(flow_count)}
                for value, packets, byte_count, flow_count in timeline_rows
            ],
            "top_talkers": [
                {"ip": str(ip), "bytes": int(byte_count), "hostname": ""}
                for ip, byte_count in talker_rows
            ],
        }

    def topology(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                 sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        return self._cached(
            self._topology_cache, (source, interface, session, sensor_node_id), 2.0,
            lambda: self._topology_uncached(source, interface, session, sensor_node_id),
        )

    def _topology_uncached(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                           sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        flows = self.flows(source, interface, session, None, None, None, 500, sensor_node_id=sensor_node_id)
        entities = {item["ip"]: item for item in self.entities(source, None, 10000)}
        priorities = {
            item["subject"]: item
            for item in self.scoring_entities(source, interface, session, limit=500, offset=0, sensor_node_id=sensor_node_id)["items"]
        }
        node_ids = {ip for flow in flows for ip in (flow.get("src_ip"), flow.get("dst_ip")) if ip}
        nodes = []
        for ip in sorted(node_ids):
            entity = entities.get(ip, {})
            nodes.append({"data": {
                "id": ip,
                "label": entity.get("hostname") or ip,
                "type": entity.get("asset_role") or entity.get("device_type") or "unknown",
                "risk": float(priorities.get(ip, {}).get("priority_score") or 0),
                "risk_level": priorities.get(ip, {}).get("risk_level", "LOW"),
                "assessment_confidence": float(priorities.get(ip, {}).get("assessment_confidence") or 0),
            }})
        edge_map: Dict[Any, int] = {}
        for flow in flows:
            key = (flow.get("src_ip"), flow.get("dst_ip"))
            edge_map[key] = edge_map.get(key, 0) + int(flow.get("byte_count") or 0)
        edges = [
            {"data": {"source": source_ip, "target": destination_ip, "weight": weight}}
            for (source_ip, destination_ip), weight in edge_map.items()
        ]
        return {"nodes": nodes, "edges": edges}

    def investigate(self, ip: str, source: Optional[str], sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        try:
            result = InvestigationService(self.db).investigate(
                ip, source=source, persist=True, sensor_node_id=sensor_node_id,
            ).to_dict()
            result["lookup"] = IpLookupService(self.db).lookup(
                ip, source=source, persist=True, sensor_node_id=sensor_node_id,
            )
            return result
        except ValueError as exc:
            raise ApiServiceError(400, "invalid_target", str(exc)) from exc

    def lookup(self, ip: str, source: Optional[str], sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        try:
            return IpLookupService(self.db).lookup(
                ip, source=source, persist=True, sensor_node_id=sensor_node_id,
            )
        except ValueError as exc:
            raise ApiServiceError(400, "invalid_target", str(exc)) from exc

    def enrichment_status(self, source: Optional[str], interface: Optional[str], session: Optional[str]) -> Dict[str, Any]:
        from core.intelligence.reindex import EnrichmentReindexer
        return EnrichmentReindexer(self.db).status(source=source, interface=interface, session_id=session)

    def rebuild_enrichment(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                           dry_run: bool) -> Dict[str, Any]:
        if self.daemon_status(force=True).get("interfaces"):
            raise ApiServiceError(409, "capture_active", "Stop all capture engines before rebuilding historical enrichment")
        from core.intelligence.reindex import EnrichmentReindexer
        try:
            return EnrichmentReindexer(self.db).rebuild(
                source=source, interface=interface, session_id=session, dry_run=dry_run,
            )
        except ValueError as exc:
            raise ApiServiceError(409, "enrichment_rebuild_unavailable", str(exc)) from exc

    def endpoint_identities(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                            limit: int = 1000, sensor_node_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.db.get_endpoint_identities(
            source=source, interface=interface, capture_session_id=session, limit=limit,
            sensor_node_id=sensor_node_id,
        )

    def endpoint_telemetry_status(self, sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        result = self.db.endpoint_telemetry_status(sensor_node_id)
        daemon_endpoint = self.daemon_status().get("endpoint_telemetry") or {}
        if daemon_endpoint:
            result.update({key: value for key, value in daemon_endpoint.items() if key not in {"observations", "coverage"}})
        return result

    def endpoint_processes(self, ip: Optional[str] = None, sensor_node_id: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.get_endpoint_process_observations(ip=ip, sensor_node_id=sensor_node_id, limit=limit)

    def mesh_status(self) -> Dict[str, Any]:
        result = self.mesh().status()
        from core.mesh.runtime import MeshRuntimeManager
        result["runtime"] = MeshRuntimeManager(str(self.db.data_dir)).controller_status()
        return result

    def mesh_initialize(self, host: str = "127.0.0.1") -> Dict[str, Any]:
        return self.mesh().initialize(host)

    def mesh_setup(self, mode: str, address: Optional[str], enrollment_port: int,
                   ingest_port: int, acknowledge_public_risk: bool) -> Dict[str, Any]:
        try:
            return self.mesh().setup(
                mode, address, enrollment_port, ingest_port, acknowledge_public_risk,
            )
        except ValueError as exc:
            raise ApiServiceError(422, "mesh_setup_rejected", str(exc)) from exc

    def mesh_lifecycle(self, action: str) -> Dict[str, Any]:
        from core.mesh.runtime import MeshRuntimeManager
        runtime = MeshRuntimeManager(str(self.db.data_dir))
        try:
            if action == "start":
                return runtime.start_controller()
            if action == "stop":
                return runtime.stop_controller()
            if action == "restart":
                return runtime.restart_controller()
            raise ValueError("Unsupported mesh lifecycle action")
        except (RuntimeError, ValueError) as exc:
            raise ApiServiceError(409, "mesh_lifecycle_failed", str(exc)) from exc

    def mesh_rotate_certificate(self) -> Dict[str, Any]:
        from core.mesh.runtime import MeshRuntimeManager
        if MeshRuntimeManager(str(self.db.data_dir)).controller_status().get("running"):
            raise ApiServiceError(409, "mesh_controller_running", "Stop the controller before rotating its listener certificate")
        return self.mesh().rotate_certificate()

    def mesh_enrollment(self, name: Optional[str], ttl_seconds: int, max_uses: int) -> Dict[str, Any]:
        return self.mesh().create_enrollment(name, ttl_seconds, max_uses)

    def mesh_nodes(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.list_sensor_nodes(limit)

    def fleet_summary(self) -> Dict[str, Any]:
        now = time.time()
        daemon = self.daemon_status()
        active_engine_sessions = {
            str(engine.get("session_id") or "")
            for engine in (daemon.get("engines") or {}).values()
            if engine.get("session_id")
        }
        nodes = []
        for raw in self.db.list_sensor_nodes(500):
            node = self.mesh()._health_view(raw)
            node_id = str(node["id"])
            counters = self.db.fleet_node_counters(node_id)
            health = dict(node.get("health") or {})
            metrics = dict(health.get("controller_metrics") or {})
            capabilities = dict(node.get("capabilities") or {})
            status = str(node.get("status") or "enrolling")
            if status in {"revoked", "decommissioned"}:
                readiness = "decommissioned"
            elif status == "local":
                readiness = "ready"
            elif not capabilities:
                readiness = "capability_sync"
            elif not health.get("captured_at"):
                readiness = "first_telemetry_sync"
            elif now - float(node.get("last_seen_at") or 0) > 60:
                readiness = "offline"
            else:
                readiness = "ready"
            if status == "local":
                node["last_seen_at"] = now
                health["captured_at"] = now
            nodes.append({
                **node,
                "readiness": readiness,
                "capture_active": bool(active_engine_sessions) if status == "local" else counters["active_sessions"] > 0,
                "active_sessions": len(active_engine_sessions) if status == "local" else counters["active_sessions"],
                "alert_count": counters["alert_count"],
                "urgent_alerts": counters["urgent_alerts"],
                "finding_count": counters["finding_count"],
                "priority_score": round(counters["priority_score"], 1),
                "ingestion_lag_seconds": metrics.get("ingestion_lag_seconds"),
                "spool_bytes": metrics.get("spool_bytes", 0),
                "spool_capacity_bytes": metrics.get("spool_capacity_bytes", 0),
                "clock_skew_seconds": metrics.get("clock_skew_seconds"),
                "certificate_expires_in_seconds": metrics.get("certificate_expires_in_seconds"),
            })
        return {
            "generated_at": now,
            "nodes": nodes,
            "totals": {
                "sensors": len(nodes),
                "ready": sum(1 for node in nodes if node["readiness"] == "ready"),
                "capturing": sum(1 for node in nodes if node["capture_active"]),
                "urgent_alerts": sum(int(node["urgent_alerts"]) for node in nodes),
                "deduplicated_findings": self.db.count_detection_fingerprints(),
            },
            "controller": self.mesh_status(),
        }

    def mesh_revoke(self, node_id: str, reason: str) -> Dict[str, Any]:
        if not self.mesh().revoke(node_id, reason):
            raise ApiServiceError(404, "mesh_node_not_found", "Mesh node was not found")
        return {"node_id": node_id, "status": "decommissioned", "historical_evidence_retained": True}

    def mesh_command(self, node_id: str, action: str, arguments: Dict[str, Any], ttl_seconds: int) -> Dict[str, Any]:
        try:
            return self.mesh().queue_command(node_id, action, arguments, ttl_seconds=ttl_seconds)
        except ValueError as exc:
            raise ApiServiceError(422, "mesh_command_rejected", str(exc)) from exc

    def graph_status(self) -> Dict[str, Any]:
        result = self.graph().status()
        if self.graph_worker is not None:
            result.update(self.graph_worker.status())
        return result

    def graph_materialize(self, limit: int = 250) -> Dict[str, Any]:
        result = self.graph().materialize(limit, owner="api-manual")
        if self.graph_worker is not None:
            self.graph_worker.wake()
            result.update(self.graph_worker.status())
        return result

    def graph_neighborhood(self, ip: str, node: Optional[str], depth: int, limit: int) -> Dict[str, Any]:
        try:
            return self.graph().neighborhood(ip, node, depth, limit)
        except RuntimeError as exc:
            raise ApiServiceError(503, "evidence_graph_unavailable", str(exc), self.graph().status()) from exc

    def graph_path(self, source_ip: str, target_ip: str, node: Optional[str]) -> Dict[str, Any]:
        try:
            return self.graph().shortest_path(source_ip, target_ip, node)
        except RuntimeError as exc:
            raise ApiServiceError(503, "evidence_graph_unavailable", str(exc), self.graph().status()) from exc

    def graph_timeline(self, ip: str, node: Optional[str], start: Optional[float], end: Optional[float], limit: int) -> Dict[str, Any]:
        try:
            return self.graph().timeline(ip, node, start, end, limit)
        except RuntimeError as exc:
            raise ApiServiceError(503, "evidence_graph_unavailable", str(exc), self.graph().status()) from exc

    def identity_status(self, source: Optional[str], interface: Optional[str], session: Optional[str]) -> Dict[str, Any]:
        from core.intelligence.reindex import EndpointIdentityReindexer
        result = EndpointIdentityReindexer(self.db).status(source=source, interface=interface, session_id=session)
        result["truth_model"] = {
            "confirmed": "A direct packet binding, DHCP lease, protocol identity, or approved live response",
            "probable": "Useful protocol/name/ownership evidence without a direct endpoint binding",
            "unconfirmed_target": "A target was queried or named, but no response binding was observed",
            "address_only": "Only an address was observed; no endpoint identity has been proven",
        }
        return result

    def identity_unconfirmed(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                             limit: int = 500) -> List[Dict[str, Any]]:
        return self.db.get_unconfirmed_identity_observations(
            source=source, interface=interface, capture_session_id=session, limit=limit,
        )

    def identity_explain(self, ip: str, source: Optional[str], interface: Optional[str],
                         session: Optional[str], sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        identity = self.db.get_endpoint_identity(
            ip, source=source, interface=interface, capture_session_id=session, sensor_node_id=sensor_node_id,
        )
        observations = self.db.get_identity_observations(
            subject_ip=ip, source=source, interface=interface, capture_session_id=session, limit=100,
        )
        profile = self.lookup(ip, source, sensor_node_id)
        return {
            "ip": ip, "identity": identity, "observations": observations,
            "lookup": profile, "known": bool(identity),
            "next_action": (identity or {}).get("next_action") or "Collect more evidence",
        }

    def identity_confirm(self, ips: List[str], source: Optional[str], interface: Optional[str],
                         session: Optional[str], dry_run: bool = False) -> Dict[str, Any]:
        if source and str(source).startswith("pcap"):
            raise ApiServiceError(409, "offline_confirmation_blocked", "Offline PCAP scopes cannot send network probes")
        from core.intelligence.confirmation import IdentityConfirmationService
        result = IdentityConfirmationService(self.db).confirm(
            ips=ips, source=source, interface=interface, session=session, dry_run=dry_run,
        )
        if result.get("confirmed") and not dry_run:
            try:
                from core.intelligence.reindex import EndpointIdentityReindexer
                result["identity_rebuild"] = EndpointIdentityReindexer(self.db).rebuild(
                    source=source, interface=interface, session_id=session, dry_run=False,
                )
            except ValueError:
                result["identity_rebuild"] = {"deferred": True, "reason": "rebuild waits for a complete capture session"}
        return result

    def identity_enrich(self, ips: List[str], source: Optional[str], session: Optional[str]) -> Dict[str, Any]:
        values = list(dict.fromkeys(str(item) for item in ips if item))[:100]
        if not values:
            values = [row["entity_ip"] for row in self.db.get_endpoint_identities(
                source=source, capture_session_id=session, limit=100,
            ) if row.get("identity_state") in {"address_only", "probable_endpoint"}]
        results = []
        for ip in values:
            try:
                address = ipaddress.ip_address(ip)
                if not address.is_global:
                    results.append({"ip": ip, "status": "skipped", "reason": "public enrichment is only for global addresses"})
                    continue
                profile = self.lookup(ip, source, persist=False)
                from core.intelligence.public_enrichment import fetch_rdap
                rdap = IpLookupService(self.db)._cached_public(ip, "rdap", lambda: fetch_rdap(ip)) or {}
                if rdap.get("name") and not profile.get("identity", {}).get("organization"):
                    profile["identity"]["organization"] = rdap["name"]
                    profile["identity"]["company"] = rdap["name"]
                profile.setdefault("enrichment", {})["rdap"] = rdap
                results.append({"ip": ip, "status": "complete", "identity": profile.get("identity"),
                                "enrichment": profile.get("enrichment"), "observed_names": profile.get("observed_names"),
                                "tls": profile.get("tls", {}), "certificates": profile.get("certificates", [])})
            except Exception as exc:
                results.append({"ip": ip, "status": "failed", "reason": str(exc)})
        return {"requested": len(values), "results": results, "cached": True}

    def rebuild_identities(self, source: Optional[str], interface: Optional[str], session: Optional[str],
                           dry_run: bool) -> Dict[str, Any]:
        if self.daemon_status(force=True).get("interfaces"):
            raise ApiServiceError(409, "capture_active", "Stop all capture engines before rebuilding endpoint identities")
        from core.intelligence.reindex import EndpointIdentityReindexer
        try:
            return EndpointIdentityReindexer(self.db).rebuild(
                source=source, interface=interface, session_id=session, dry_run=dry_run,
            )
        except ValueError as exc:
            raise ApiServiceError(409, "identity_rebuild_unavailable", str(exc)) from exc

    def start_capture(self, interface: str, backend: Optional[str], source_type: str) -> Dict[str, Any]:
        try:
            backend = backend_policy.capture_backend(
                source_type=source_type,
                requested_backend=backend,
            )
        except BackendPolicyError as exc:
            raise ApiServiceError(422, "invalid_backend", str(exc)) from exc
        if not self.daemon_status(force=True).get("running"):
            try:
                from core.daemon.manager import DaemonManager

                if not DaemonManager.ensure_running(silent=False):
                    raise RuntimeError("Daemon did not become ready; approve the administrator prompt and retry")
                if hasattr(self.daemon, "_timeout"):
                    self.daemon._timeout = 10.0
            except Exception as exc:
                raise ApiServiceError(503, "daemon_start_failed", str(exc)) from exc
        result = self.daemon.start_engine(interface, backend, source_type)
        self._daemon_cache = (0.0, {"running": False})
        if result.get("status") == "error":
            raise ApiServiceError(503, "daemon_error", result.get("message") or "Capture start failed", result)
        # Confirmation is deliberately detached from capture control. It is
        # bounded, local-subnet-only, and its responses become evidence only
        # after a reply is received.
        def confirm_pending_targets() -> None:
            try:
                from core.intelligence.confirmation import IdentityConfirmationService
                IdentityConfirmationService(self.db).confirm(interface=interface, source=None, dry_run=False)
            except Exception:
                # A missing adapter or interface must never make capture look
                # failed; health and the identity operation retain the reason.
                return
        threading.Thread(target=confirm_pending_targets, name="watchtower-identity-confirm", daemon=True).start()
        return result

    def stop_capture(self, interface: str) -> Dict[str, Any]:
        result = self.daemon.stop_engine(interface)
        self._daemon_cache = (0.0, {"running": False})
        if result.get("status") == "error":
            raise ApiServiceError(503, "daemon_error", result.get("message") or "Capture stop failed", result)
        return result

    def capture_session(self, session_id: str) -> Dict[str, Any]:
        if not hasattr(self.db, "get_capture_session"):
            rows = self.db.get_capture_sessions(limit=1000)
            row = next((item for item in rows if item.get("id") == session_id), None)
        else:
            row = self.db.get_capture_session(session_id)
        if not row:
            raise ApiServiceError(404, "capture_session_not_found", f"Capture session {session_id} was not found")
        engines = (self.daemon_status().get("engines") or {})
        return self._capture_session_projection(self._merge_live_session(row, engines))

    @staticmethod
    def _merge_live_session(row: Dict[str, Any], engines: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Overlay volatile daemon counters only onto their exact persisted session."""
        item = dict(row)
        engine = next(
            (
                metrics for metrics in engines.values()
                if str(metrics.get("session_id") or "") == str(item.get("id") or "")
            ),
            None,
        )
        if not engine:
            return item
        metric_fields = (
            "received_packets", "emitted_packets", "dropped_packets", "queue_full_events",
            "processed_packets", "detector_errors", "evidence_dropped", "snapshot_dropped",
            "pending_packets", "queue_depth", "queue_depth_high_watermark", "queue_lag_ms",
            "queue_lag_max_ms", "processing_state",
        )
        for field in metric_fields:
            if field in engine:
                item[field] = engine[field]
        # A live daemon engine is authoritative for this session.  Clear
        # stale terminal metadata left by an older daemon instance so health
        # and UI projections cannot describe an active session as orphaned.
        item["ended_at"] = None
        item["completion_reason"] = None
        item["error"] = None
        item["shutdown_stage"] = engine.get("shutdown_stage") or "capturing"
        item["worker_acknowledged"] = False
        item["evidence_acknowledged"] = False
        item["process_exit_outcome"] = None
        item["status"] = "DRAINING" if str(item.get("processing_state")).lower() == "draining" else "RUNNING"
        item["complete"] = False
        return item

    @staticmethod
    def _capture_session_projection(row: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(row)
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            try:
                metadata = json.loads(item.get("metadata_json") or "{}")
            except (TypeError, ValueError):
                metadata = {}
        item["metadata"] = metadata
        item.pop("metadata_json", None)
        if metadata.get("backend_version"):
            item["backend_version"] = str(metadata["backend_version"])
        emitted = int(item.get("emitted_packets") or 0)
        processed = int(item.get("processed_packets") or 0)
        item["pending_packets"] = int(item.get("pending_packets") or max(0, emitted - processed))
        state = str(item.get("processing_state") or "running").lower()
        item["processing_state"] = state
        item["complete"] = bool(item.get("complete") or state == "complete")
        item["completeness"] = "complete" if item["complete"] else state
        return item

    def request_capture_stop(self, session_id: str, reason: str = "operator_stop") -> Dict[str, Any]:
        session = self.capture_session(session_id)
        if session["processing_state"] in {"complete", "partial", "failed", "cancelled"}:
            return {"status": session["processing_state"], "session_id": session_id, "already_stopped": True}
        interface = session.get("interface") or session.get("device_id")
        if not interface:
            raise ApiServiceError(409, "capture_interface_unknown", "The session has no capture interface")
        with self._capture_stop_lock:
            existing = self._capture_stops.get(session_id)
            if existing and existing.get("state") == "draining":
                return {"status": "draining", "session_id": session_id, "interface": interface}
            self._capture_stops[session_id] = {"state": "draining", "interface": interface, "requested_at": time.time()}
        if hasattr(self.db, "update_capture_session_state"):
            self.db.update_capture_session_state(session_id, "draining", reason=reason)

        def drain_capture():
            try:
                result = self.daemon.stop_engine(interface)
                state = "failed" if result.get("status") == "error" else "stopped"
                with self._capture_stop_lock:
                    self._capture_stops[session_id] = {"state": state, "result": result, "finished_at": time.time()}
            except Exception as exc:
                with self._capture_stop_lock:
                    self._capture_stops[session_id] = {"state": "failed", "error": str(exc), "finished_at": time.time()}
            finally:
                self._daemon_cache = (0.0, {"running": False})

        threading.Thread(target=drain_capture, name=f"capture-drain-{session_id[:8]}", daemon=True).start()
        return {"status": "draining", "session_id": session_id, "interface": interface, "reason": reason}

    def pipeline_health(self) -> Dict[str, Any]:
        daemon = self.daemon_status(force=True)
        engines = daemon.get("engines") or {}
        sessions = [
            self._capture_session_projection(self._merge_live_session(row, engines))
            for row in self.db.get_capture_sessions(limit=100)
        ]
        active = [
            row for row in sessions
            if row["processing_state"] in {"running", "draining"}
            and str(row.get("status") or "RUNNING").upper() in {"RUNNING", "DRAINING"}
        ]
        pending = sum(int(row.get("pending_packets") or 0) for row in active)
        detector_failures = sum(int(row.get("detector_errors") or 0) for row in active)
        drops = {
            "capture": sum(int(row.get("dropped_packets") or 0) for row in active),
            "snapshot": sum(int(row.get("snapshot_dropped") or 0) for row in active),
            "evidence": sum(int(row.get("evidence_dropped") or 0) for row in active),
        }
        now = time.time()
        last_progress = max(
            [float(engine.get("last_packet_at") or 0) for engine in engines.values()]
            + [float(row.get("last_seen") or 0) for row in active]
            + [float(engine.get("last_packet_at") or 0) for engine in engines.values()]
            + [now if not active else 0.0]
        )
        queue_lag = max(
            [float(row.get("queue_lag_ms") or 0) for row in active]
            + [float(engine.get("queue_lag_ms") or 0) for engine in engines.values()]
            + [0.0]
        )
        queue_lag_max = max(
            [float(row.get("queue_lag_max_ms") or 0) for row in active]
            + [float(engine.get("queue_lag_max_ms") or 0) for engine in engines.values()]
            + [queue_lag]
        )
        stale_analytics = bool(active and now - last_progress > 120 and pending > 0)
        excessive_lag = queue_lag > 5000.0
        pool = self.db.pool_status() if hasattr(self.db, "pool_status") else {}
        return {
            "status": "degraded" if pending or detector_failures or any(drops.values()) or excessive_lag or stale_analytics else "ok",
            "generated_at": now,
            "active_sessions": len(active),
            "pending_packets": pending,
            "queue_lag_ms": queue_lag,
            "queue_lag_max_ms": queue_lag_max,
            "drop_stages": drops,
            "detector_failures": detector_failures,
            "stale_analytics": stale_analytics,
            "sessions": active,
            "engines": engines,
            "database_pool": pool,
            "shutdown_stages": {
                str(row.get("id")): {
                    "stage": row.get("shutdown_stage"),
                    "worker_acknowledged": bool(row.get("worker_acknowledged")),
                    "evidence_acknowledged": bool(row.get("evidence_acknowledged")),
                    "process_exit_outcome": row.get("process_exit_outcome"),
                }
                for row in sessions[:25]
            },
        }

    def run_hunt(self, source: Optional[str], interface: Optional[str], rule: Optional[str], persist: bool) -> Dict:
        from core.forensics.sigma_engine import SigmaEngine

        engine = SigmaEngine(db=self.db)
        matches = engine.run_hunt(source=source, interface=interface, specific_rule=rule, persist=persist)
        return {
            "matched": len(matches),
            "persisted": persist,
            "active_rules": len(engine.rules),
            "rejected_rules": len(engine.rejected),
        }

    def submit_pcap(self, path: str, filename: str, mode: str, backend: Optional[str]) -> Dict[str, Any]:
        try:
            backend = backend_policy.replay_backend(backend)
            return self.jobs.submit(path, filename, mode, backend)
        except (BackendPolicyError, ValueError) as exc:
            raise ApiServiceError(422, "invalid_pcap_job", str(exc)) from exc

    def pcap_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.jobs.list(limit)

    def pcap_cases(self, limit: int = 100) -> Dict[str, Any]:
        if not hasattr(self.db, "list_forensic_cases"):
            return {"items": [], "limit": limit}
        bounded = max(1, min(int(limit or 100), 500))
        return {"items": self.db.list_forensic_cases(bounded), "limit": bounded}

    def pcap_case(self, case_id: str) -> Dict[str, Any]:
        if not hasattr(self.db, "get_forensic_case"):
            raise ApiServiceError(404, "pcap_case_not_found", f"PCAP case {case_id} was not found")
        case = self.db.get_forensic_case(case_id)
        if not case:
            raise ApiServiceError(404, "pcap_case_not_found", f"PCAP case {case_id} was not found")
        case["custody"] = self.db.get_case_custody(case_id) if hasattr(self.db, "get_case_custody") else []
        return case

    def pcap_case_custody(self, case_id: str, limit: int = 250) -> Dict[str, Any]:
        # Resolve first so a missing case is not confused with an empty chain.
        self.pcap_case(case_id)
        items = self.db.get_case_custody(case_id, limit=limit) if hasattr(self.db, "get_case_custody") else []
        return {"items": items, "limit": max(1, min(int(limit or 250), 1000))}

    def pcap_case_flags(self, case_id: str, status: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        self.pcap_case(case_id)
        items = self.db.get_triage_flags(case_id, status=status, limit=limit) if hasattr(self.db, "get_triage_flags") else {"items": []}
        return items

    def create_pcap_case_flag(self, case_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.pcap_case(case_id)
        if not hasattr(self.db, "upsert_triage_flag"):
            raise ApiServiceError(501, "triage_unavailable", "Offline triage storage is unavailable")
        required = ("target_type", "target_id", "reason")
        missing = [field for field in required if not str(payload.get(field) or "").strip()]
        if missing:
            raise ApiServiceError(422, "invalid_triage_flag", f"Missing required field(s): {', '.join(missing)}")
        fingerprint = str(payload.get("fingerprint") or sha256(
            f"manual|{case_id}|{payload['target_type']}|{payload['target_id']}|{payload['reason']}".encode("utf-8")
        ).hexdigest())
        return self.db.upsert_triage_flag(case_id, {
            **payload,
            "fingerprint": fingerprint,
            "actor": str(payload.get("actor") or "analyst"),
            "confidence": max(0.0, min(1.0, float(payload.get("confidence") or 0.5))),
            "source": payload.get("source") or self.pcap_case(case_id).get("analysis_id"),
        })

    def pcap_progress(self, job_id: str) -> Dict[str, Any]:
        """Return the durable worker state without running forensic projections."""
        job = self.jobs.get(job_id)
        if not job:
            raise ApiServiceError(404, "pcap_job_not_found", f"PCAP analysis {job_id} was not found")
        return job

    def pcap_analysis(self, job_id: str) -> Dict[str, Any]:
        job = self.pcap_progress(job_id)
        source = job["source"]
        result = dict(job)
        if job.get("case_id") and hasattr(self.db, "get_forensic_case"):
            result["case"] = self.db.get_forensic_case(job["case_id"])
            if hasattr(self.db, "count_case_entities"):
                result["entity_count"] = self.db.count_case_entities(job["case_id"])
                result["case"]["entity_count"] = result["entity_count"]
        if not hasattr(self.db, "source_projection_summary"):
            return result
        projection = self.db.source_projection_summary(source)
        protocol_rows = projection.pop("protocol_rows")
        port_rows = projection.pop("port_rows")
        result.update(projection)
        protocol_total = sum(int(row[1] or 0) for row in protocol_rows) or 1
        port_total = sum(int(row[1] or 0) for row in port_rows) or 1
        result["protocols"] = [
            {"protocol": str(protocol or "OTHER"), "count": int(count), "percentage": round(int(count) * 100 / protocol_total, 1)}
            for protocol, count in protocol_rows
        ]
        result["ports"] = [
            {"port": int(port), "service": "", "count": int(count), "percentage": round(int(count) * 100 / port_total, 1)}
            for port, count in port_rows
        ]
        started = float(job.get("started_at") or job.get("created_at") or 0)
        ended = float(job.get("completed_at") or time.time())
        result["duration_seconds"] = max(0.0, ended - started)
        report_id = job.get("report_id")
        report = self.db.get_report(int(report_id)) if report_id else None
        result["report"] = report
        summary = dict(job.get("summary") or {})
        limitations = list(summary.get("visibility_limitations") or [])
        if str(job.get("status") or "").lower() != "complete":
            limitations.append(str(job.get("error") or f"Analysis state is {job.get('status')}"))
        if summary.get("stream_truncated_segments"):
            limitations.append(
                f"{summary['stream_truncated_segments']} stream segment(s) were truncated by configured evidence bounds"
            )
        result["visibility_limitations"] = list(dict.fromkeys(limitations))
        result["processing_completeness"] = (
            "complete"
            if str(job.get("status")).lower() == "complete"
            and not result["visibility_limitations"]
            else "partial"
        )
        return result

    def pcap_analysis_page(self, job_id: str, kind: str, limit: int = 100, cursor: Any = 0) -> Dict[str, Any]:
        analysis = self.pcap_analysis(job_id)
        source = analysis["source"]
        limit = max(1, min(int(limit), 500))
        case_id = str(analysis.get("case_id") or "")
        if kind == "entities" and case_id and hasattr(self.db, "get_case_entities"):
            return self.db.get_case_entities(case_id, limit, None if cursor in (None, "", 0, "0") else str(cursor))
        cursor = max(0, int(cursor or 0))
        if kind == "flows":
            return self.flow_page(source=source, limit=limit, cursor=cursor)
        if kind == "alerts":
            return self.alert_page(source=source, limit=limit, cursor=cursor)
        if not hasattr(self.db, "source_projection_page"):
            return self._offset_page([], cursor, limit)
        if kind not in {"entities", "findings", "artifacts", "evidence", "streams"}:
            raise ApiServiceError(404, "pcap_projection_not_found", f"Unknown PCAP projection: {kind}")
        items = self.db.source_projection_page(source, kind, limit=limit + 1, offset=cursor)
        if kind == "artifacts":
            for item in items:
                item["vt_results"] = self._safe_dict(item.get("vt_results"))
        elif kind == "streams":
            stream_items = []
            for row in items:
                identity = (
                    f"{row.get('src_ip')}:{row.get('src_port')}>"
                    f"{row.get('dst_ip')}:{row.get('dst_port')}/{row.get('protocol')}"
                )
                stream_items.append({
                    "id": row.get("id"),
                    "flow_id": format_flow_id(
                        row.get("src_ip"), row.get("src_port"), row.get("dst_ip"),
                        row.get("dst_port"), row.get("protocol"),
                    ),
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "src_port": int(row.get("src_port") or 0),
                    "dst_port": int(row.get("dst_port") or 0),
                    "protocol": row.get("protocol"),
                    "byte_count": int(row.get("byte_count") or 0),
                    "packet_count": int(row.get("packet_count") or 0),
                    "first_seen": row.get("start_time"),
                    "last_seen": row.get("last_seen"),
                    "evidence_hash": sha256(identity.encode("utf-8")).hexdigest(),
                    "payload_available": False,
                    "redacted": True,
                    "truncated": bool((self._safe_dict(row.get("l7_metadata"))).get("stream_truncated")),
                })
            items = stream_items
        return self._offset_page(items, cursor, limit)

    def pcap_topology(self, job_id: str, limit: int = 250, cursor: int = 0,
                      mode: str = "analyst") -> Dict[str, Any]:
        analysis = self.pcap_analysis(job_id)
        source = analysis["source"]
        mode = str(mode or "analyst").lower()
        if mode not in {"analyst", "conversations"}:
            raise ApiServiceError(422, "invalid_topology_mode", "Topology mode must be analyst or conversations")
        page = self._pcap_conversation_page(
            source,
            limit=max(1, min(5000, max(int(limit), 250) if mode == "analyst" else int(limit))),
            cursor=max(0, cursor),
            analysis_id=analysis.get("analysis_id"),
        )
        finding_targets = set()
        for finding in self.db.get_detection_findings(source=source, include_suppressed=False, limit=100000):
            for target in (finding.get("subject"), finding.get("target")):
                if target:
                    finding_targets.add(str(target))
        if mode == "analyst":
            def endpoint_local(value: Any) -> bool:
                try:
                    return not ipaddress.ip_address(str(value)).is_global
                except ValueError:
                    return False

            def edge_rank(conversation: Dict[str, Any]) -> tuple:
                endpoints = {str(conversation.get("src_ip") or ""), str(conversation.get("dst_ip") or "")}
                finding_hit = len(endpoints & finding_targets)
                local_anchor = any(endpoint_local(endpoint) for endpoint in endpoints)
                return (finding_hit, local_anchor, int(conversation.get("bytes") or 0), int(conversation.get("packets") or 0))

            total_conversations = len(page["items"])
            page["items"] = sorted(page["items"], key=edge_rank, reverse=True)[:max(1, min(int(limit), 250))]
            page["analyst_total_conversations"] = total_conversations
            page["analyst_omitted_conversations"] = max(0, total_conversations - len(page["items"]))
        identity_rows = []
        for conversation in page["items"]:
            identity_rows.extend((
                {
                    "src_ip": conversation["src_ip"],
                    "source": source,
                    "capture_interface": "",
                    "capture_session_id": "",
                },
                {
                    "src_ip": conversation["dst_ip"],
                    "source": source,
                    "capture_interface": "",
                    "capture_session_id": "",
                },
            ))
        identities = self._flow_identity_summaries(identity_rows, source, None, None)
        nodes: Dict[str, Dict[str, Any]] = {}
        edges = []
        for conversation in page["items"]:
            for endpoint in (conversation.get("src_ip"), conversation.get("dst_ip")):
                identity = identities.get((
                    str(endpoint or ""),
                    source,
                    "",
                    "",
                ))
                if endpoint and endpoint not in nodes:
                    nodes[endpoint] = {
                        "data": {
                            "id": endpoint,
                            "label": (identity or {}).get("identity_label") or endpoint,
                            "identity": identity,
                            "is_local": self._is_local_forensic_address(endpoint),
                            "finding": endpoint in finding_targets,
                        }
                    }
            edges.append({"data": {
                "id": f"conversation-{conversation['id']}",
                "source": conversation.get("src_ip"),
                "target": conversation.get("dst_ip"),
                "protocol": conversation.get("protocol"),
                "src_port": conversation.get("src_port"),
                "dst_port": conversation.get("dst_port"),
                "bytes": conversation.get("bytes"),
                "packets": conversation.get("packets"),
                "to_responder_bytes": conversation.get("to_responder_bytes"),
                "to_initiator_bytes": conversation.get("to_initiator_bytes"),
                "established": conversation.get("established"),
                "first_seen": conversation.get("first_seen"),
                "last_seen": conversation.get("last_seen"),
                "finding": bool({str(conversation.get("src_ip") or ""), str(conversation.get("dst_ip") or "")} & finding_targets),
            }})
        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "next_cursor": page["next_cursor"],
            "limit": page["limit"],
            "source": source,
            "truncated": page["truncated"],
            "directional_rows_scanned": page["directional_rows_scanned"],
            "mode": mode,
            "conversation_evidence_mode": page.get("mode"),
            "legacy_fallback": bool(page.get("legacy_fallback")),
            "visibility_limitations": list(
                page.get("visibility_limitations") or []
            ),
            "analyst_total_conversations": page.get("analyst_total_conversations", len(page["items"])),
            "analyst_omitted_conversations": page.get("analyst_omitted_conversations", 0),
        }

    @staticmethod
    def _is_local_forensic_address(value: Any) -> bool:
        try:
            return not ipaddress.ip_address(str(value)).is_global
        except ValueError:
            return False

    def _pcap_conversation_page(
        self,
        source: str,
        limit: int,
        cursor: int,
        *,
        analysis_id: str | None = None,
    ) -> Dict[str, Any]:
        """Read native revision evidence, reconstructing only legacy analyses."""
        if (
            analysis_id
            and hasattr(self.db, "get_forensic_evidence_components")
            and hasattr(self.db, "get_forensic_conversations")
        ):
            components = {
                item["component"]: item
                for item in self.db.get_forensic_evidence_components(analysis_id)
            }
            if "native_conversations" in components:
                native = self.db.get_forensic_conversations(
                    analysis_id,
                    limit=max(1, min(int(limit), 5000)),
                    offset=max(0, int(cursor)),
                )
                native["items"] = [
                    {
                        **item,
                        "src_ip": item["initiator_ip"],
                        "dst_ip": item["responder_ip"],
                        "src_port": int(item["initiator_port"]),
                        "dst_port": int(item["responder_port"]),
                        "bytes": int(item["to_responder_bytes"])
                        + int(item["to_initiator_bytes"]),
                        "packets": int(item["to_responder_packets"])
                        + int(item["to_initiator_packets"]),
                        "flow_refs": [],
                    }
                    for item in native["items"]
                ]
                native.update({
                    "truncated": False,
                    "directional_rows_scanned": 0,
                    "mode": "native",
                    "legacy_fallback": False,
                })
                return native
            if hasattr(self.db, "get_forensic_analysis_revision"):
                revision = self.db.get_forensic_analysis_revision(analysis_id)
                limitations = list(
                    (revision or {}).get("visibility_limitations") or []
                )
                if "native_conversations_unavailable" in limitations:
                    return {
                        **self._offset_page([], cursor, limit),
                        "truncated": False,
                        "directional_rows_scanned": 0,
                        "mode": "native_unavailable",
                        "legacy_fallback": False,
                        "visibility_limitations": limitations,
                    }
        if not hasattr(self.db, "source_conversation_rows"):
            return {
                **self._offset_page([], cursor, limit),
                "truncated": False,
                "directional_rows_scanned": 0,
                "mode": "legacy_reconstruction",
                "legacy_fallback": True,
            }
        limit = max(1, min(int(limit), 5000))
        cursor = max(0, int(cursor))
        maximum_rows = min(100_000, max(2 * (cursor + limit + 1), limit + 1))
        rows = self.db.source_conversation_rows(source, limit=maximum_rows + 1)
        truncated = len(rows) > maximum_rows
        rows = rows[:maximum_rows]
        conversations: Dict[tuple, Dict[str, Any]] = {}
        for row in rows:
            protocol = str(row.get("protocol") or "OTHER").upper()
            source_endpoint = (str(row.get("src_ip") or ""), int(row.get("src_port") or 0))
            target_endpoint = (str(row.get("dst_ip") or ""), int(row.get("dst_port") or 0))
            endpoint_a, endpoint_b = sorted((source_endpoint, target_endpoint))
            key = (protocol, endpoint_a, endpoint_b)
            metadata = self._safe_dict(row.get("l7_metadata"))
            initiator = (
                str(metadata.get("initiator_ip") or ""),
                int(metadata.get("initiator_port") or 0),
            )
            responder = (
                str(metadata.get("responder_ip") or ""),
                int(metadata.get("responder_port") or 0),
            )
            if {initiator, responder} != {endpoint_a, endpoint_b}:
                initiator, responder = source_endpoint, target_endpoint
            item = conversations.get(key)
            if item is None:
                identity = f"{source}|{protocol}|{endpoint_a[0]}:{endpoint_a[1]}|{endpoint_b[0]}:{endpoint_b[1]}"
                item = {
                    "id": sha256(identity.encode("utf-8")).hexdigest()[:24],
                    "src_ip": initiator[0],
                    "dst_ip": responder[0],
                    "src_port": initiator[1],
                    "dst_port": responder[1],
                    "protocol": protocol,
                    "first_seen": float(row.get("start_time") or 0),
                    "last_seen": float(row.get("last_seen") or row.get("start_time") or 0),
                    "bytes": 0,
                    "packets": 0,
                    "to_responder_bytes": 0,
                    "to_responder_packets": 0,
                    "to_initiator_bytes": 0,
                    "to_initiator_packets": 0,
                    "established": False,
                    "flow_refs": [],
                }
                conversations[key] = item
            byte_count = int(row.get("byte_count") or 0)
            packet_count = int(row.get("packet_count") or 0)
            item["first_seen"] = min(item["first_seen"], float(row.get("start_time") or 0))
            item["last_seen"] = max(
                item["last_seen"], float(row.get("last_seen") or row.get("start_time") or 0),
            )
            item["bytes"] += byte_count
            item["packets"] += packet_count
            if source_endpoint == (item["src_ip"], item["src_port"]):
                item["to_responder_bytes"] += byte_count
                item["to_responder_packets"] += packet_count
            else:
                item["to_initiator_bytes"] += byte_count
                item["to_initiator_packets"] += packet_count
            item["established"] = bool(
                item["established"]
                or metadata.get("conversation_established")
                or int(row.get("tcp_syn_count") or 0) > 1
            )
            if len(item["flow_refs"]) < 2:
                item["flow_refs"].append(int(row["id"]))
        ordered = sorted(conversations.values(), key=lambda item: (item["first_seen"], item["id"]))
        window = ordered[cursor:cursor + limit + 1]
        page = self._offset_page(window, cursor, limit)
        page["truncated"] = truncated
        page["directional_rows_scanned"] = len(rows)
        page["mode"] = "legacy_reconstruction"
        page["legacy_fallback"] = True
        return page

    def pcap_timeline(self, job_id: str, limit: int = 2000, cursor: int = 0) -> Dict[str, Any]:
        analysis = self.pcap_analysis(job_id)
        page = self._pcap_conversation_page(
            analysis["source"],
            limit=max(1, min(int(limit), 5000)),
            cursor=max(0, int(cursor)),
            analysis_id=analysis.get("analysis_id"),
        )
        items = page["items"]
        page["start_time"] = min((item["first_seen"] for item in items), default=None)
        page["end_time"] = max((item["last_seen"] for item in items), default=None)
        return page

    def pcap_deep_dissection(
        self, job_id: str, limit: int = 100, cursor: int = 0
    ) -> Dict[str, Any]:
        analysis = self.pcap_analysis(job_id)
        if not hasattr(self.db, "get_forensic_deep_dissection"):
            return {
                **self._offset_page([], cursor, limit),
                "component": "tshark_deep_dissection",
            }
        return self.db.get_forensic_deep_dissection(
            analysis["analysis_id"],
            limit=max(1, min(int(limit), 1_000)),
            offset=max(0, int(cursor)),
        )

    def pcap_job(self, job_id: str, include_results: bool = True) -> Dict[str, Any]:
        job = self.jobs.get(job_id)
        if not job:
            raise ApiServiceError(404, "pcap_job_not_found", f"PCAP job {job_id} was not found")
        if not include_results or job["status"] not in {"complete", "partial", "cancelled"}:
            return job

        source = job["source"]
        flows = self.flows(source, None, None, None, None, None, 5000)
        alerts = self.alerts(source, None, None, None, None, 1000)
        entities = self.entities(source, None, 5000)
        protocol_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}
        for flow in flows:
            packets = int(flow.get("packet_count") or 0)
            protocol = str(flow.get("protocol") or "OTHER")
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + packets
            port = int(flow.get("dst_port") or 0)
            if port:
                port_counts[port] = port_counts.get(port, 0) + packets
        total_protocols = sum(protocol_counts.values()) or 1
        total_ports = sum(port_counts.values()) or 1
        started_at = float(job.get("started_at") or job["created_at"])
        completed_at = float(job.get("completed_at") or time.time())
        return {
            **job,
            "duration_seconds": max(0.0, completed_at - started_at),
            "packet_count": sum(int(flow.get("packet_count") or 0) for flow in flows),
            "flow_count": len(flows),
            "entity_count": len(entities),
            "alert_count": len(alerts),
            "flows": flows,
            "entities": entities,
            "alerts": alerts,
            "protocols": [
                {"protocol": key, "count": value, "percentage": round(value * 100 / total_protocols, 1)}
                for key, value in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
            ],
            "ports": [
                {"port": key, "service": "", "count": value, "percentage": round(value * 100 / total_ports, 1)}
                for key, value in sorted(port_counts.items(), key=lambda item: item[1], reverse=True)
            ],
        }

    def cancel_pcap(self, job_id: str) -> Dict[str, Any]:
        job = self.jobs.cancel(job_id)
        if not job:
            raise ApiServiceError(404, "pcap_job_not_found", f"PCAP job {job_id} was not found")
        return job

    def forensic_reports(self) -> List[Dict[str, Any]]:
        return self.db.get_reports()

    def run_survey(self, duration_seconds: int, active: str, backend: Optional[str]) -> Dict[str, Any]:
        """Run the bounded, directly-connected local network survey.

        This is deliberately a narrow adapter rather than a general command
        runner: the agent can only request the same constrained survey modes
        exposed by WatchTower itself.
        """
        from core.survey.runner import SurveyConfig, SurveyRunner

        duration_seconds = int(duration_seconds)
        if not 0 <= duration_seconds <= 3600:
            raise ApiServiceError(422, "invalid_survey_duration", "Survey duration must be between 0 and 3600 seconds")
        if active not in {"none", "safe", "deep"}:
            raise ApiServiceError(422, "invalid_survey_mode", "Survey mode must be none, safe, or deep")
        try:
            backend = backend_policy.capture_backend(requested_backend=backend)
        except BackendPolicyError as exc:
            raise ApiServiceError(422, "invalid_survey_backend", str(exc)) from exc
        report = SurveyRunner(self.db, data_dir=str(getattr(self.db, "data_dir", context.data_dir))).run(
            SurveyConfig(duration_seconds=duration_seconds, active=active, capture_backend=backend),
            capture=duration_seconds > 0,
        )
        return {
            "id": report.id,
            "devices": len(report.devices),
            "services": len(report.services),
            "probe_count": report.probe_count,
            "case_path": report.case_path,
            "visibility_limitations": report.visibility_limitations,
        }

    # ------------------------------------------------------------------
    # Local agentic analyst API. All user-visible errors remain stable
    # API envelopes through ApiServiceError.
    # ------------------------------------------------------------------

    @staticmethod
    def _ai_scope(scope: Dict[str, Any]) -> ScopedContext:
        return ScopedContext.from_dict(scope)

    def ai_status(self) -> Dict[str, Any]:
        result = self.ai.status()
        try:
            result["providers"] = self.ai_providers.inventory()
        except Exception as exc:
            result["provider_inventory_error"] = str(exc)
        return result

    def ai_provider_connect(self, name: str, secret: Optional[str], model: Optional[str],
                            base_url: Optional[str]) -> Dict[str, Any]:
        try:
            result = self.ai_providers.connect(name, secret, model, base_url)
            self.ai.reload_config()
            return result
        except ProviderUnavailable as exc:
            raise ApiServiceError(503, "ai_provider_unavailable", str(exc)) from exc

    def ai_provider_test(self, name: str) -> Dict[str, Any]:
        try:
            return self.ai_providers.test(name)
        except ProviderUnavailable as exc:
            raise ApiServiceError(503, "ai_provider_unavailable", str(exc)) from exc

    def ai_provider_disconnect(self, name: str) -> Dict[str, Any]:
        try:
            result = self.ai_providers.disconnect(name)
            self.ai.reload_config()
            return result
        except ProviderUnavailable as exc:
            raise ApiServiceError(422, "ai_provider_invalid", str(exc)) from exc

    def ai_provider_models(self, name: str, refresh: bool = False) -> Dict[str, Any]:
        try:
            return self.ai_providers.models(name, refresh)
        except ProviderUnavailable as exc:
            raise ApiServiceError(503, "ai_provider_unavailable", str(exc)) from exc

    def ai_provider_set_model(self, name: str, model: str) -> Dict[str, Any]:
        try:
            result = self.ai_providers.set_model(name, model)
            self.ai.reload_config()
            return result
        except ProviderUnavailable as exc:
            raise ApiServiceError(422, "ai_model_invalid", str(exc)) from exc

    def ai_conversations(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.ai.conversations(limit)

    def ai_conversation(self, conversation_id: str) -> Dict[str, Any]:
        result = self.ai.conversation(conversation_id)
        if not result:
            raise ApiServiceError(404, "ai_conversation_not_found", "AI conversation was not found")
        return result

    def ai_create_conversation(self, title: str, provider: str, scope: Dict[str, Any]) -> Dict[str, Any]:
        return self.ai.create_conversation(title, provider, self._ai_scope(scope))

    def ai_delete_conversation(self, conversation_id: str) -> Dict[str, Any]:
        if not self.ai.delete_conversation(conversation_id):
            raise ApiServiceError(404, "ai_conversation_not_found", "AI conversation was not found")
        return {"status": "deleted", "conversation_id": conversation_id}

    def ai_start_run(self, prompt: str, conversation_id: Optional[str], provider: str, scope: Dict[str, Any],
                     research_mode: str, operator_session_id: Optional[str] = None, mode: str = "auto") -> Dict[str, Any]:
        try:
            return self.ai.start(
                prompt,
                conversation_id,
                self._ai_scope(scope),
                provider,
                research_mode,
                background=True,
                operator_session_id=operator_session_id,
                mode=mode,
            )
        except (ValueError, PermissionError) as exc:
            raise ApiServiceError(422, "ai_invalid_run", str(exc)) from exc

    def ai_run(self, run_id: str) -> Dict[str, Any]:
        result = self.ai.run(run_id)
        if not result:
            raise ApiServiceError(404, "ai_run_not_found", "AI run was not found")
        return result

    def ai_events(self, run_id: str, after: int = 0) -> List[Dict[str, Any]]:
        self.ai_run(run_id)
        return self.ai.events(run_id, after)

    def ai_approve(self, approval_id: str, confirmation: str) -> Dict[str, Any]:
        try:
            return self.ai.approve(approval_id, confirmation, background=True)
        except ValueError as exc:
            raise ApiServiceError(422, "ai_approval_invalid", str(exc)) from exc

    def ai_reject(self, approval_id: str, reason: str) -> Dict[str, Any]:
        try:
            return self.ai.reject(approval_id, reason)
        except ValueError as exc:
            raise ApiServiceError(422, "ai_approval_invalid", str(exc)) from exc

    def ai_set_credential(self, reference: str, secret: str) -> Dict[str, Any]:
        try:
            CredentialStore().set(reference, secret)
            config = AIConfig.load()
            for name in ("openai", "brave", "virustotal", "abuseipdb", "taxii"):
                provider = getattr(config, name)
                if provider.credential_ref == reference:
                    provider.enabled = True
            config.save()
            self.ai.reload_config()
        except Exception as exc:
            raise ApiServiceError(503, "credential_store_unavailable", str(exc)) from exc
        return {"status": "stored", "reference": reference}

    def ai_delete_credential(self, reference: str) -> Dict[str, Any]:
        try:
            deleted = CredentialStore().delete(reference)
        except Exception as exc:
            raise ApiServiceError(503, "credential_store_unavailable", str(exc)) from exc
        return {"status": "deleted" if deleted else "not_found", "reference": reference}

    def close(self) -> None:
        if self._graph is not None:
            self._graph.close()
        self.ai.close()
        self.jobs.shutdown()

    def reset_database(self, confirmation: str, mode: str = "operational") -> Dict[str, Any]:
        if mode not in {"operational", "factory"}:
            raise ApiServiceError(422, "invalid_reset_mode", "mode must be operational or factory")
        expected = "FACTORY RESET WATCHTOWER" if mode == "factory" else "RESET WATCHTOWER"
        if confirmation != expected:
            raise ApiServiceError(409, "confirmation_required", f"Enter {expected} to confirm database reset")
        daemon = self.daemon_status(force=True)
        if daemon.get("interfaces"):
            raise ApiServiceError(409, "capture_active", "Stop all capture engines before resetting the database")
        try:
            deleted = self.db.reset_all(mode=mode)
        except TypeError as exc:
            if mode != "operational" or "unexpected keyword argument" not in str(exc):
                raise
            deleted = self.db.reset_all()
        with self._read_cache_lock:
            self._entity_cache.clear()
            self._stats_cache.clear()
            self._topology_cache.clear()
        return {"status": "reset", "mode": mode, "deleted": deleted}

    def plugin_inventory(self) -> Dict[str, Any]:
        from core.forensics.plugin_loader import PluginLoader

        loader = PluginLoader()
        plugins = list(loader.list_plugins().values())
        return {
            "parsers": [item for item in plugins if item["type"] == "parser"],
            "detectors": [item for item in plugins if item["type"] == "detector"],
            "hardware": self.registry.list_sources(),
        }

    @staticmethod
    def _calibration_error(exc: Exception) -> ApiServiceError:
        message = str(exc) or "Calibration operation failed"
        status = 404 if "does not exist" in message or "no calibration targets" in message else 422
        return ApiServiceError(status, "calibration_error", message)

    @staticmethod
    def _report_summary(report: Dict[str, Any], report_path: Optional[str] = None) -> Dict[str, Any]:
        metrics = dict(report.get("metrics") or {})
        allowed_metrics = {
            "positive_cases", "benign_cases", "true_positive", "false_positive",
            "true_negative", "false_negative", "precision", "recall",
            "false_alert_rate", "evidence_completeness", "execution_seconds",
            "peak_memory_bytes", "backend_parity", "deterministic",
            "secrets_redacted", "state_within_limit",
        }
        return {
            "report_path": report_path or report.get("report_path") or "",
            "digest": report.get("digest") or "",
            "created_at": float(report.get("created_at") or 0),
            "backend_selection": report.get("backend_selection") or "",
            "passed": bool(report.get("passed")),
            "awarded_level": report.get("awarded_level") or "UNCALIBRATED",
            "failures": list(report.get("failures") or []),
            "field_failures": list(report.get("field_failures") or []),
            "metrics": {key: metrics.get(key) for key in allowed_metrics if key in metrics},
            "target": dict(report.get("target") or {}),
            "runner_peak_memory_bytes": int(report.get("runner_peak_memory_bytes") or 0),
        }

    def _latest_calibration_report(self, detector_id: str, finding_type: str) -> Optional[Dict[str, Any]]:
        data_dir = Path(getattr(self.db, "data_dir", context.data_dir))
        report_dir = data_dir / "calibration" / "reports"
        if not report_dir.exists():
            return None
        pattern = f"{detector_id}__{finding_type}__*.json"
        latest: Optional[Dict[str, Any]] = None
        for path in sorted(report_dir.glob(pattern), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            summary = self._report_summary(report, str(path))
            if latest is None or summary["created_at"] > latest["created_at"]:
                latest = summary
        return latest

    @staticmethod
    def _calibration_corpus_info(detector_id: str, finding_type: str) -> Dict[str, Any]:
        project_root = Path(__file__).resolve().parents[2]
        path = project_root / "calibration" / "corpus" / f"{detector_id}.yaml"
        if not path.is_file():
            return {"corpus_available": False, "corpus_case_count": 0, "corpus_error": ""}
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            defaults = data.get("defaults") or {}
            cases = data.get("cases") or []
            count = sum(
                1 for item in cases
                if str((item or {}).get("finding_type") or defaults.get("finding_type") or "") == finding_type
            )
            return {"corpus_available": count > 0, "corpus_case_count": count, "corpus_error": ""}
        except Exception as exc:
            return {"corpus_available": False, "corpus_case_count": 0, "corpus_error": str(exc)}

    def plugin_calibration_status(self, detector_id: Optional[str] = None) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        try:
            status = CalibrationService(data_dir=Path(getattr(self.db, "data_dir", context.data_dir))).status(detector_id)
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc
        targets = []
        for target in status.get("targets") or []:
            item = dict(target)
            item.update(self._calibration_corpus_info(
                str(item.get("detector_id") or ""),
                str(item.get("finding_type") or ""),
            ))
            item["latest_report"] = self._latest_calibration_report(
                str(item.get("detector_id") or ""),
                str(item.get("finding_type") or ""),
            )
            targets.append(item)
        status["targets"] = targets
        return status

    def plugin_calibration_run(self, detector_id: str, finding_type: Optional[str], backend: str) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        try:
            result = CalibrationService(data_dir=Path(getattr(self.db, "data_dir", context.data_dir))).run(
                detector_id, finding_type=finding_type, backend=backend,
            )
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc
        return {
            "detector_id": result.get("detector_id") or detector_id,
            "passed": bool(result.get("passed")),
            "reports": [self._report_summary(report) for report in result.get("reports") or []],
        }

    def plugin_scaffold_detector(
        self, detector_id: str, finding_type: str, input_kind: str, description: str = ""
    ) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        try:
            result = CalibrationService(
                data_dir=Path(getattr(self.db, "data_dir", context.data_dir))
            ).scaffold(detector_id, finding_type, input_kind, description=description)
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc
        return {
            **result,
            "detector_id": detector_id,
            "finding_type": finding_type,
            "status": "scaffolded_uncalibrated",
            "next_action": f"Run calibration for {detector_id} after implementing its evidence logic and corpus.",
        }

    def plugin_create_threshold_detector(self, **values) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        try:
            result = CalibrationService(
                data_dir=Path(getattr(self.db, "data_dir", context.data_dir))
            ).create_threshold_detector(**values)
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc
        return {
            **result,
            "detector_id": values["detector_id"],
            "finding_type": values["finding_type"],
            "status": "created_uncalibrated",
            "next_action": (
                f"Review the generated detector and run calibration for {values['detector_id']}. "
                "Future/custom detectors still require field evidence for full scoring trust."
            ),
        }

    def plugin_calibration_promote(self, report_path: str, reviewer: str, reason: str) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        service = CalibrationService(data_dir=Path(getattr(self.db, "data_dir", context.data_dir)))
        try:
            result = service.promote(report_path, reviewer, reason)
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc
        target = result.get("target") or {}
        detector_id = str(target.get("detector_id") or "")
        return {
            **result,
            "status": self.plugin_calibration_status(detector_id) if detector_id else self.plugin_calibration_status(),
        }

    def plugin_calibration_verify(self) -> Dict[str, Any]:
        from core.calibration.service import CalibrationError, CalibrationService

        try:
            return CalibrationService(data_dir=Path(getattr(self.db, "data_dir", context.data_dir))).verify()
        except CalibrationError as exc:
            raise self._calibration_error(exc) from exc

    def scoring_findings(self, subject=None, source=None, interface=None, session=None,
                         finding_type=None, include_suppressed=False, limit=250, sensor_node_id=None):
        if not hasattr(self.db, "get_detection_findings"):
            return []
        return self.db.get_detection_findings(
            subject=subject, source=source, interface=interface,
            capture_session_id=session, finding_type=finding_type,
            include_suppressed=include_suppressed, limit=limit, sensor_node_id=sensor_node_id,
        )

    def scoring_status(self):
        from core.detection.operations import ScoringOperations
        return ScoringOperations(self.db).status()

    def scoring_entities(self, source=None, interface=None, session=None, limit=100, offset=0, sensor_node_id=None):
        from core.detection.scoring import ScoringConfig

        position = self._decode_cursor(offset)
        rows = self.db.get_risk_snapshots(
            source, interface, session, limit=limit + 1,
            offset=int(position.get("offset") or 0), sensor_node_id=sensor_node_id,
            after_priority=position.get("priority_score"),
            after_subject=position.get("subject"),
        ) \
            if hasattr(self.db, "get_risk_snapshots") else []
        has_more = len(rows) > limit
        data_dir = getattr(self.db, "data_dir", None)
        override = data_dir / "config" / "scoring.yaml" if data_dir is not None else None
        config = ScoringConfig(override_path=str(override) if override and override.exists() else None)
        now = time.time()
        refreshed = []
        for row in rows[:limit]:
            if (
                row.get("config_hash") != config.config_hash
                or now - float(row.get("computed_at") or 0) > 300
            ):
                self.db.recompute_risk(
                    row["subject"], source=source, interface=interface,
                    capture_session_id=session, as_of=now, persist=True, sensor_node_id=sensor_node_id,
                )
                row = self.db.get_risk_snapshot(row["subject"], source, interface, session, sensor_node_id) or row
            refreshed.append(row)
        rows = refreshed
        entity_by_ip = self.db.get_entities_by_ips([str(row.get("subject") or "") for row in rows]) \
            if hasattr(self.db, "get_entities_by_ips") else {}
        baselines = self.db.get_feature_baselines(source=source, interface=interface) \
            if hasattr(self.db, "get_feature_baselines") else []
        maturity_by_subject: Dict[str, Dict[str, Any]] = {}
        for baseline in baselines:
            subject = str(baseline.get("subject") or "")
            current = maturity_by_subject.setdefault(subject, {"state": "cold", "sample_count": 0})
            current["sample_count"] = max(current["sample_count"], int(baseline.get("sample_count") or 0))
            maturity = baseline.get("maturity") or {}
            if isinstance(maturity, dict) and maturity.get("mature"):
                current["state"] = "mature"
        items = []
        for row in rows:
            subject = str(row.get("subject") or "")
            item = {**dict(entity_by_ip.get(subject) or {}), **dict(row)}
            item["ip"] = subject
            item["scope"] = {"type": item.get("scope_type"), "id": item.get("scope_id")}
            item["baseline_maturity"] = maturity_by_subject.get(item.get("subject"), {"state": "cold", "sample_count": 0})
            item["processing_completeness"] = "complete"
            if item.get("capture_session_id"):
                try:
                    item["processing_completeness"] = self.capture_session(item["capture_session_id"])["completeness"]
                except ApiServiceError:
                    item["processing_completeness"] = "unknown"
            items.append(item)
        last = rows[min(limit, len(rows)) - 1] if rows else None
        next_cursor = self._encode_cursor({
            "priority_score": float(last.get("priority_score") or 0.0),
            "subject": str(last.get("subject") or ""),
        }) if has_more and last else None
        return {"items": items, "next_cursor": next_cursor, "limit": limit}

    def dashboard_summary(self, source="live", interface=None, session=None, sensor_node_id=None):
        stats = self.stats(source, interface, sensor_node_id)
        priorities = self.scoring_entities(
            source, interface, session, limit=10, offset=None, sensor_node_id=sensor_node_id,
        )
        alerts = self.alert_page(
            source, interface, session, None, None, limit=10,
            cursor=None, sensor_node_id=sensor_node_id,
        )
        daemon = self.daemon_status()
        return {
            "generated_at": time.time(),
            "scope": {
                "source": source, "interface": interface,
                "session": session, "node": sensor_node_id,
            },
            "traffic": {
                "packets": stats.get("total_packets", 0),
                "bytes": stats.get("total_bytes", 0),
                "flows": stats.get("total_flows", 0),
                "active_hosts": stats.get("active_hosts", 0),
                "protocols": (stats.get("protocols") or [])[:8],
                "timeline": (stats.get("timeline") or [])[-24:],
            },
            "risk": priorities,
            "alerts": alerts,
            "capture": {
                "running": bool(daemon.get("running")),
                "interfaces": daemon.get("interfaces") or [],
            },
            "pipeline": self.pipeline_health(),
        }

    def scoring_risk(self, subject, source=None, interface=None, session=None, explain=False, sensor_node_id=None):
        from core.detection.operations import ScoringOperations
        if not explain and hasattr(self.db, "get_risk_snapshot"):
            snapshot = self.db.get_risk_snapshot(subject, source, interface, session, sensor_node_id)
            if snapshot:
                snapshot["baseline_maturity"] = ScoringOperations(self.db).explain(
                    subject, source, interface, session, persist=False, sensor_node_id=sensor_node_id,
                )["baseline_maturity"]
                return snapshot
        return ScoringOperations(self.db).explain(subject, source, interface, session, persist=False, sensor_node_id=sensor_node_id)

    def scoring_disposition(self, finding_id, verdict, reason, actor="local-analyst", scope="finding"):
        try:
            return self.db.set_finding_disposition(
                finding_id, verdict, reason, actor=actor, scope=scope,
            )
        except ValueError as exc:
            message = str(exc)
            status = 404 if "does not exist" in message else 422
            raise ApiServiceError(status, "invalid_disposition", message) from exc

    def scoring_recompute(self, source=None, interface=None, session=None, as_of=None, dry_run=False, sensor_node_id=None):
        from core.detection.operations import ScoringOperations
        return ScoringOperations(self.db).recompute(source, interface, session, as_of, dry_run, sensor_node_id)

    def sigma_rules(self) -> List[Dict[str, Any]]:
        from core.forensics.sigma_sync import SigmaRuleManager

        return SigmaRuleManager().list_rules()

    def sigma_status(self) -> Dict[str, Any]:
        from core.forensics.sigma_sync import SigmaCorpusManager

        return SigmaCorpusManager().status()

    def sigma_preview(self, url: str) -> Dict[str, Any]:
        from core.forensics.sigma_sync import SigmaRuleManager

        try:
            return SigmaRuleManager().preview_url(url)
        except Exception as exc:
            raise ApiServiceError(422, "sigma_preview_failed", str(exc)) from exc

    def sigma_install(self, url: str, expected_sha256: str) -> Dict[str, Any]:
        from core.forensics.sigma_sync import SigmaRuleManager

        try:
            return SigmaRuleManager().install_url(url, expected_sha256)
        except Exception as exc:
            raise ApiServiceError(422, "sigma_install_failed", str(exc)) from exc

    def sigma_sync(self) -> Dict[str, Any]:
        from dataclasses import asdict
        from core.forensics.sigma_sync import SigmaCorpusManager

        try:
            return asdict(SigmaCorpusManager().sync())
        except Exception as exc:
            raise ApiServiceError(422, "sigma_sync_failed", str(exc)) from exc

    def sigma_rollback(self) -> Dict[str, Any]:
        from dataclasses import asdict
        from core.forensics.sigma_sync import SigmaCorpusManager

        try:
            return asdict(SigmaCorpusManager().rollback())
        except Exception as exc:
            raise ApiServiceError(409, "sigma_rollback_failed", str(exc)) from exc
