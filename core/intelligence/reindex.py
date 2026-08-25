"""Safe, evidence-backed repair of historical IP enrichment."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import or_

from core.intelligence.evidence import CaptureEvidence, ip_scope
from core.intelligence.local_assets import LocalAssetProfiler
from core.storage.models import CaptureSession, Entity, Flow


DERIVED_REMOTE_ROLES = {
    "Web Server", "Client / Workstation", "Multi-service Host", "Remote Administration Host",
}


class EnrichmentReindexer:
    """Repairs derived identity fields without deleting captured flow evidence."""

    def __init__(self, db):
        self.db = db

    def _flow_query(self, session, source: Optional[str], interface: Optional[str], session_id: Optional[str]):
        query = session.query(Flow)
        if source:
            if source == "live":
                query = query.filter(Flow.source.like("live%"))
            elif source.startswith("live_") and "#" not in source:
                query = query.filter(Flow.source.like(f"{source}#%"))
            else:
                query = query.filter(Flow.source == source)
        if interface:
            query = query.filter(Flow.capture_interface == interface)
        if session_id:
            query = query.filter(Flow.capture_session_id == session_id)
        return query

    @staticmethod
    def _flow_dict(row: Flow) -> Dict[str, Any]:
        metadata = {}
        try:
            metadata = json.loads(row.l7_metadata) if row.l7_metadata else {}
        except (TypeError, ValueError):
            metadata = {}
        return {
            "id": row.id, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "src_port": row.src_port, "dst_port": row.dst_port, "protocol": row.protocol,
            "l7_metadata": metadata, "source": row.source,
            "start_time": row.start_time, "last_seen": row.last_seen,
            "capture_interface": row.capture_interface, "capture_session_id": row.capture_session_id,
        }

    def _backup(self, reason: str = "evidence-backed enrichment reindex") -> Dict[str, str]:
        backup_dir = Path(self.db.data_dir) / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        tag = "identity" if "identity" in reason.lower() else "enrichment"
        destination = backup_dir / f"watchtower-pre-{tag}-reindex-{stamp}.db"
        with sqlite3.connect(str(self.db.db_path)) as source, sqlite3.connect(str(destination)) as target:
            source.backup(target)
        with sqlite3.connect(str(destination)) as verify:
            state = str(verify.execute("PRAGMA quick_check").fetchone()[0]).lower()
        if state != "ok":
            destination.unlink(missing_ok=True)
            raise RuntimeError(f"backup verification failed: {state}")
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        manifest = destination.with_suffix(".manifest.json")
        manifest.write_text(json.dumps({
            "created_at": time.time(), "database": str(destination), "sha256": digest,
            "reason": reason,
        }, indent=2), encoding="utf-8")
        return {"database": str(destination), "manifest": str(manifest), "sha256": digest}

    @staticmethod
    def _trusted_mac(context: CaptureEvidence, ip: str) -> Optional[str]:
        value = context.endpoint(ip).get("mac") or {}
        return value.get("mac") or None

    def status(self, source: Optional[str] = None, interface: Optional[str] = None,
               session_id: Optional[str] = None) -> Dict[str, Any]:
        with self.db.session_scope() as session:
            rows = [
                self._flow_dict(row)
                for row in self._flow_query(session, source, interface, session_id).all()
            ]
        evidence = CaptureEvidence(rows)
        ips = {str(flow[key]) for flow in rows for key in ("src_ip", "dst_ip") if flow.get(key)}
        remote = [ip for ip in ips if ip_scope(ip) == "global" and not evidence.endpoint(ip)["is_local_endpoint"]]
        return {
            "flows": len(rows), "ips": len(ips),
            "public_endpoints": len(remote),
            "public_with_capture_geo": sum(bool(evidence.endpoint(ip)["geoip"]) for ip in remote),
            "trusted_mac_bindings": len(evidence.trusted_macs),
            "flow_context_version": "evidence-v1",
        }

    def rebuild(self, source: Optional[str] = None, interface: Optional[str] = None,
                session_id: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        if session_id:
            capture = self.db.get_capture_session(session_id)
            if capture and not capture.get("complete"):
                raise ValueError("enrichment rebuild requires a complete capture session")

        # The backup is a pre-change snapshot. ORM mutations commit only after
        # the SQLite copy passes its integrity check.
        backup = None if dry_run else self._backup()
        with self.db.session_scope(write=not dry_run) as session:
            rows = self._flow_query(session, source, interface, session_id).all()
            flow_dicts = [self._flow_dict(row) for row in rows]
            evidence = CaptureEvidence(flow_dicts)
            ip_set = {
                str(flow[key])
                for flow in flow_dicts
                for key in ("src_ip", "dst_ip")
                if flow.get(key)
            }
            changed_flows = 0
            changed_entities = 0
            removed_untrusted_macs = 0

            for row, flow in zip(rows, flow_dicts):
                metadata = dict(flow["l7_metadata"])
                trusted = self._trusted_mac(evidence, str(row.src_ip))
                if metadata.get("mac") and metadata.get("mac").lower() != (trusted or "").lower():
                    metadata.pop("mac", None)
                    metadata.pop("vendor", None)
                    removed_untrusted_macs += 1
                context = evidence.flow_context(flow)
                if metadata.get("watchtower_intel_v1") != context:
                    metadata["watchtower_intel_v1"] = context
                    changed_flows += 1
                if not dry_run:
                    row.l7_metadata = json.dumps(metadata, sort_keys=True)

            entity_rows = session.query(Entity).filter(Entity.ip.in_(ip_set)).all() if ip_set else []
            for entity in entity_rows:
                endpoint = evidence.endpoint(str(entity.ip))
                trusted = (endpoint.get("mac") or {}).get("mac")
                remote = endpoint["scope"] == "global" and not endpoint["is_local_endpoint"]
                should_clear_role = remote and entity.asset_role in DERIVED_REMOTE_ROLES
                if entity.mac != trusted or (not trusted and entity.vendor) or should_clear_role:
                    changed_entities += 1
                    if not dry_run:
                        entity.mac = trusted
                        if not trusted:
                            entity.vendor = None
                        if should_clear_role:
                            entity.asset_role = None

            sources = {row.source for row in rows if row.source}
            if session_id and len(sources) == 1 and not dry_run:
                capture = session.query(CaptureSession).filter_by(id=session_id).first()
                if capture and capture.source != next(iter(sources)):
                    capture.source = next(iter(sources))

        if not dry_run:
            profiler = LocalAssetProfiler(self.db)
            for ip in sorted(ip_set):
                profiler.build(ip, source=next(iter(sources)) if len(sources) == 1 else source, persist=True)

        return {
            "flows": len(rows), "ips": len(ip_set), "changed_flows": changed_flows,
            "changed_entities": changed_entities, "removed_untrusted_macs": removed_untrusted_macs,
            "public_with_capture_geo": sum(
                bool(evidence.endpoint(ip)["geoip"])
                for ip in ip_set
                if ip_scope(ip) == "global" and not evidence.endpoint(ip)["is_local_endpoint"]
            ),
            "backup": backup, "dry_run": dry_run,
        }


class EndpointIdentityReindexer:
    """Back up and rebuild endpoint identity cards from stored evidence."""

    def __init__(self, db, inventory_factory=None):
        self.db = db
        self._enrichment = EnrichmentReindexer(db)
        self.inventory_factory = inventory_factory

    def _groups(self, source: Optional[str], interface: Optional[str], session_id: Optional[str]):
        groups: Dict[tuple, list] = {}
        with self.db.session_scope() as session:
            rows = self._enrichment._flow_query(session, source, interface, session_id).all()
            for row in rows:
                key = (row.source, row.capture_interface, row.capture_session_id)
                groups.setdefault(key, []).append(self._enrichment._flow_dict(row))
        return groups

    @staticmethod
    def _records(groups, inventory, observations_by_scope=None):
        from core.intelligence.endpoint_identity import EndpointIdentityResolver

        records = []
        for (source, interface, session_id), flows in groups.items():
            resolver = EndpointIdentityResolver(
                flows, inventory=inventory,
                observations=(observations_by_scope or {}).get((source, interface, session_id), []),
            )
            records.extend(record.to_dict() for record in resolver.resolve(source, interface, session_id))
        return records

    def _observation_groups(self, source, interface, session_id):
        values = self.db.get_identity_observations(
            source=source, interface=interface, capture_session_id=session_id, limit=5000,
        )
        grouped = {}
        for item in values:
            key = (item.get("source"), item.get("capture_interface"), item.get("capture_session_id"))
            grouped.setdefault(key, []).append(item)
        return grouped

    @staticmethod
    def _observations(groups):
        """Extract immutable identity facts without promoting requests to devices."""
        observations = []
        for (source, interface, session_id), flows in groups.items():
            for flow in flows:
                metadata = flow.get("l7_metadata") or {}
                if not isinstance(metadata, dict):
                    continue
                base = {
                    "source": source,
                    "capture_interface": interface,
                    "capture_session_id": session_id,
                    "sensor_node_id": flow.get("sensor_node_id"),
                    "first_seen": flow.get("start_time"),
                    "last_seen": flow.get("last_seen") or flow.get("start_time"),
                    "evidence_ref": f"flow:{flow.get('id')}",
                }
                target = metadata.get("arp_target_ip") or metadata.get("ndp_target_ip")
                if target:
                    kind = "arp_target" if metadata.get("arp_target_ip") else "ndp_target"
                    observations.append({
                        **base, "subject_ip": str(target), "observation_type": kind,
                        "confidence": 0.2, "value": {"requester": flow.get("src_ip"), "confirmation_required": True},
                    })
                sender_ip = metadata.get("arp_sender_ip") or metadata.get("ndp_sender_ip")
                sender_mac = metadata.get("arp_sender_mac") or metadata.get("ndp_sender_mac")
                if sender_ip and sender_mac:
                    kind = "arp_binding" if metadata.get("arp_sender_ip") else "ndp_binding"
                    observations.append({
                        **base, "subject_ip": str(sender_ip), "observation_type": kind,
                        "confidence": 0.98, "value": {"mac": str(sender_mac)},
                    })
                geo = metadata.get("geoip")
                if isinstance(geo, dict) and (geo.get("asn") or geo.get("org") or geo.get("isp")):
                    subject = str(flow.get("dst_ip") or "")
                    if subject:
                        observations.append({
                            **base, "subject_ip": subject, "observation_type": "public_ownership",
                            "confidence": 0.9, "value": {key: geo.get(key) for key in ("asn", "org", "isp", "country", "city") if geo.get(key)},
                        })
                service = CaptureEvidence._service_observation(
                    metadata, str(flow.get("protocol") or "OTHER").upper(),
                    int(flow.get("src_port") or 0), int(flow.get("dst_port") or 0),
                )
                parser_confirmed = any(metadata.get(key) for key in {
                    "application_protocol", "tls_sni", "http_host", "server_name", "ssh_banner", "smb_dialect", "mqtt_client_id",
                })
                if service and flow.get("dst_ip") and (service.get("basis") == "application_parser" or parser_confirmed):
                    observations.append({
                        **base, "subject_ip": str(flow["dst_ip"]), "observation_type": "service_identity",
                        "confidence": 0.78, "value": service,
                    })
                for answer in metadata.get("dns_answers") or []:
                    if not isinstance(answer, dict) or not answer.get("address") or not answer.get("name"):
                        continue
                    observations.append({
                        **base, "subject_ip": str(answer["address"]), "observation_type": "dns_name",
                        "confidence": 0.88, "value": {"name": str(answer["name"]).rstrip(".").lower()},
                    })
        for item in observations:
            item["fingerprint"] = hashlib.sha256(json.dumps({
                key: item.get(key) for key in ("subject_ip", "source", "capture_interface", "capture_session_id", "observation_type", "evidence_ref")
            }, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return observations

    @staticmethod
    def _coverage(records):
        from core.intelligence.endpoint_identity import EndpointIdentityRecord, EndpointIdentityResolver

        return EndpointIdentityResolver.coverage(EndpointIdentityRecord(**record) for record in records)

    def status(self, source: Optional[str] = None, interface: Optional[str] = None,
               session_id: Optional[str] = None) -> Dict[str, Any]:
        groups = self._groups(source, interface, session_id)
        inventory = self.inventory_factory() if self.inventory_factory else None
        records = self._records(groups, inventory, self._observation_groups(source, interface, session_id))
        stored = self.db.get_endpoint_identities(
            source=source, interface=interface, capture_session_id=session_id, limit=10000,
        )
        stored_keys = {
            (row["entity_ip"], row["source"], row.get("capture_interface") or "", row.get("capture_session_id") or "")
            for row in stored
        }
        expected_keys = {
            (row["entity_ip"], row["source"], row.get("capture_interface") or "", row.get("capture_session_id") or "")
            for row in records
        }
        return {
            "flows": sum(len(rows) for rows in groups.values()),
            "stored_identities": len(stored),
            "missing_identities": len(expected_keys - stored_keys),
            **self._coverage(records),
            "identity_model_version": "endpoint-identity-v2",
            "observations": len(self._observations(groups)),
        }

    def rebuild(self, source: Optional[str] = None, interface: Optional[str] = None,
                session_id: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        if session_id:
            capture = self.db.get_capture_session(session_id)
            if capture and not capture.get("complete"):
                raise ValueError("identity rebuild requires a complete capture session")
        groups = self._groups(source, interface, session_id)
        inventory = self.inventory_factory() if self.inventory_factory else None
        records = self._records(groups, inventory, self._observation_groups(source, interface, session_id))
        observations = self._observations(groups)
        counts = {}
        for observation in observations:
            counts[observation["subject_ip"]] = counts.get(observation["subject_ip"], 0) + 1
        for record in records:
            record["observation_count"] = counts.get(record["entity_ip"], 0)
        existing = {
            (row["entity_ip"], row["source"], row.get("capture_interface") or "", row.get("capture_session_id") or ""): row
            for row in self.db.get_endpoint_identities(
                source=source, interface=interface, capture_session_id=session_id, limit=10000,
            )
        }
        changed = 0
        for record in records:
            key = (
                record["entity_ip"], record["source"], record.get("capture_interface") or "",
                record.get("capture_session_id") or "",
            )
            prior = existing.get(key)
            if not prior or any(
                prior.get(field) != record.get(field)
            for field in ("identity_type", "identity_label", "confidence", "verification", "identity_state", "next_action", "evidence")
            ):
                changed += 1
        backup = None if dry_run else self._enrichment._backup("endpoint identity reindex")
        if not dry_run:
            self.db.upsert_endpoint_identities(records)
            self.db.upsert_identity_observations(observations)
        return {
            "flows": sum(len(rows) for rows in groups.values()),
            "identities": len(records), "changed_identities": changed,
            **self._coverage(records),
            "backup": backup, "dry_run": dry_run,
            "identity_model_version": "endpoint-identity-v2",
            "observations": len(observations),
        }
