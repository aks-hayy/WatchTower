"""Materialize SQLite evidence into a bounded Neo4j investigation graph."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, Iterable, List, Optional
import uuid

import yaml


@dataclass(frozen=True)
class GraphConfig:
    enabled: bool = False
    uri: str = "bolt://127.0.0.1:7687"
    username: str = "neo4j"
    password: str = ""
    database: str = "neo4j"

    @classmethod
    def load(cls, data_dir: str) -> "GraphConfig":
        path = Path(data_dir) / "config" / "evidence_graph.yaml"
        value: Dict[str, Any] = {}
        if path.exists():
            try:
                value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                value = {}
        graph = dict(value.get("neo4j") or value)
        password_file = os.getenv("WATCHTOWER_NEO4J_PASSWORD_FILE")
        password = str(os.getenv("WATCHTOWER_NEO4J_PASSWORD") or graph.get("password") or "")
        if password_file and not password:
            try:
                password = Path(password_file).read_text(encoding="utf-8").strip()
            except OSError:
                password = ""
        configured_enabled = os.getenv("WATCHTOWER_NEO4J_ENABLED")
        return cls(
            enabled=(configured_enabled.strip().lower() in {"1", "true", "yes", "on"}
                     if configured_enabled is not None else bool(graph.get("enabled", False))),
            uri=str(os.getenv("WATCHTOWER_NEO4J_URI") or graph.get("uri") or "bolt://127.0.0.1:7687"),
            username=str(os.getenv("WATCHTOWER_NEO4J_USERNAME") or graph.get("username") or "neo4j"),
            password=password,
            database=str(graph.get("database") or "neo4j"),
        )


class EvidenceGraphService:
    def __init__(self, db, config: Optional[GraphConfig] = None):
        self.db = db
        self.config = config or GraphConfig.load(str(getattr(db, "data_dir", ".")))
        self._driver = None
        self._last_error: Optional[str] = None

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def status(self) -> Dict[str, Any]:
        outbox = self.db.graph_outbox_status()
        available = False
        reason = "Neo4j evidence graph is disabled. Configure data/config/evidence_graph.yaml to enable it."
        if self.config.enabled:
            try:
                self._get_driver().verify_connectivity()
                available, reason, self._last_error = True, "", None
            except Exception as exc:
                self._last_error = str(exc)[:500]
                reason = self._last_error
        return {
            "enabled": self.config.enabled, "available": available, "uri": self.config.uri if self.config.enabled else None,
            "database": self.config.database if self.config.enabled else None, "reason": reason,
            "freshness": "current" if available and not outbox["pending"] else "stale" if outbox["pending"] else "unavailable",
            **outbox,
        }

    def materialize(self, limit: int = 250, owner: Optional[str] = None) -> Dict[str, Any]:
        status = self.status()
        if not status["available"]:
            return {**status, "materialized": 0}
        delivered = 0
        events = self.db.claim_graph_events(owner or f"graph-{uuid.uuid4()}", limit)
        for event in events:
            try:
                self._apply(str(event["operation"]), dict(event.get("payload") or {}))
                self.db.mark_graph_event(event["id"], True)
                delivered += 1
            except Exception as exc:
                self.db.mark_graph_event(event["id"], False, str(exc))
                self._last_error = str(exc)[:500]
                break
        return {**self.status(), "materialized": delivered}

    def neighborhood(self, ip: str, sensor_node_id: Optional[str] = None, depth: int = 2, limit: int = 100) -> Dict[str, Any]:
        self._require_available()
        node_id = sensor_node_id or self.db.local_sensor_node_id()
        root_id = self._endpoint_id(node_id, ip)
        depth = max(1, min(int(depth), 3))
        limit = max(1, min(int(limit), 250))
        query = f"""
            MATCH (root {{id: $root_id}})-[relationships*1..{depth}]-(related)
            WITH collect(DISTINCT root) + collect(DISTINCT related) AS nodes,
                 relationships
            UNWIND nodes AS node
            WITH collect(DISTINCT {{id: node.id, labels: labels(node), properties: properties(node)}}) AS node_rows, relationships
            UNWIND relationships AS relationship_list
            UNWIND relationship_list AS relationship
            RETURN node_rows, collect(DISTINCT {{id: elementId(relationship), type: type(relationship), source: startNode(relationship).id, target: endNode(relationship).id, properties: properties(relationship)}})[..$limit] AS edge_rows
        """
        records = self._run(query, {"root_id": root_id, "limit": limit})
        if not records:
            return {"root": root_id, "nodes": [], "edges": [], "truncated": False}
        record = records[0]
        return {"root": root_id, "nodes": record.get("node_rows") or [], "edges": record.get("edge_rows") or [], "truncated": len(record.get("edge_rows") or []) >= limit}

    def shortest_path(self, source_ip: str, target_ip: str, sensor_node_id: Optional[str] = None) -> Dict[str, Any]:
        self._require_available()
        node = sensor_node_id or self.db.local_sensor_node_id()
        query = """
            MATCH (source {id: $source_id}), (target {id: $target_id}), path = shortestPath((source)-[*..6]-(target))
            RETURN [item IN nodes(path) | {id: item.id, labels: labels(item), properties: properties(item)}] AS nodes,
                   [item IN relationships(path) | {id: elementId(item), type: type(item), source: startNode(item).id, target: endNode(item).id, properties: properties(item)}] AS edges
            LIMIT 1
        """
        rows = self._run(query, {"source_id": self._endpoint_id(node, source_ip), "target_id": self._endpoint_id(node, target_ip)})
        return rows[0] if rows else {"nodes": [], "edges": []}

    def timeline(self, ip: str, sensor_node_id: Optional[str] = None, start: Optional[float] = None,
                 end: Optional[float] = None, limit: int = 200) -> Dict[str, Any]:
        self._require_available()
        node = sensor_node_id or self.db.local_sensor_node_id()
        rows = self._run("""
            MATCH (endpoint {id: $endpoint_id})-[relationship]-()
            WHERE coalesce(relationship.last_seen, relationship.observed_at, 0.0) >= $start
              AND coalesce(relationship.first_seen, relationship.observed_at, 0.0) <= $end
            RETURN type(relationship) AS type, startNode(relationship).id AS source, endNode(relationship).id AS target,
                   properties(relationship) AS properties
            ORDER BY coalesce(relationship.last_seen, relationship.observed_at, 0.0) DESC
            LIMIT $limit
        """, {
            "endpoint_id": self._endpoint_id(node, ip), "start": float(start or 0.0), "end": float(end or time.time()),
            "limit": max(1, min(int(limit), 500)),
        })
        return {"items": rows, "truncated": len(rows) >= int(limit)}

    def _apply(self, operation: str, payload: Dict[str, Any]) -> None:
        if operation == "flow":
            self._apply_flow(payload)
        elif operation == "process_observation":
            self._apply_process(payload)
        elif operation == "finding":
            self._apply_finding(payload)
        elif operation == "identity":
            self._apply_identity(payload)
        elif operation == "artifact":
            self._apply_artifact(payload)
        elif operation == "hardware_observation":
            self._apply_hardware_observation(payload)
        elif operation == "case":
            self._apply_case(payload)
        else:
            raise ValueError(f"Unsupported graph operation: {operation}")

    def _apply_flow(self, flow: Dict[str, Any]) -> None:
        node = str(flow.get("sensor_node_id") or self.db.local_sensor_node_id())
        src_ip, dst_ip = str(flow.get("src_ip") or ""), str(flow.get("dst_ip") or "")
        if not src_ip or not dst_ip:
            raise ValueError("Flow graph event is missing endpoint IPs")
        bucket = int(float(flow.get("last_seen") or time.time()) // 300) * 300
        edge_key = f"{node}:{src_ip}:{flow.get('src_port')}:{dst_ip}:{flow.get('dst_port')}:{flow.get('protocol')}:{bucket}"
        interface = str(flow.get("capture_interface") or "")
        conversation_id = f"conversation:{edge_key}"
        params = {
            "node": node, "src_id": self._endpoint_id(node, src_ip), "dst_id": self._endpoint_id(node, dst_ip),
            "src_ip": src_ip, "dst_ip": dst_ip, "edge_key": edge_key, "bucket": bucket,
            "conversation_id": conversation_id, "interface_id": f"interface:{node}:{interface}" if interface else "",
            "protocol": str(flow.get("protocol") or ""), "src_port": int(flow.get("src_port") or 0), "dst_port": int(flow.get("dst_port") or 0),
            "bytes": int(flow.get("byte_count") or 0), "packets": int(flow.get("packet_count") or 0),
            "first_seen": float(flow.get("start_time") or 0.0), "last_seen": float(flow.get("last_seen") or 0.0),
            "source": str(flow.get("source") or ""), "session": str(flow.get("capture_session_id") or ""),
            "interface": interface,
        }
        self._run_write("""
            MERGE (sensor:SensorNode {id: $node})
            MERGE (src:Endpoint {id: $src_id}) SET src.ip = $src_ip, src.sensor_node_id = $node
            MERGE (dst:Endpoint {id: $dst_id}) SET dst.ip = $dst_ip, dst.sensor_node_id = $node
            MERGE (sensor)-[:OBSERVED_ON]->(src)
            MERGE (sensor)-[:OBSERVED_ON]->(dst)
            MERGE (conversation:FlowConversation {id: $conversation_id})
            SET conversation.sensor_node_id = $node, conversation.bucket = $bucket, conversation.protocol = $protocol,
                conversation.src_port = $src_port, conversation.dst_port = $dst_port, conversation.bytes = $bytes,
                conversation.packets = $packets, conversation.first_seen = $first_seen, conversation.last_seen = $last_seen,
                conversation.source = $source, conversation.session = $session, conversation.interface = $interface
            MERGE (src)-[:PARTICIPATED_IN]->(conversation)
            MERGE (conversation)-[:PARTICIPATED_IN]->(dst)
            MERGE (src)-[edge:COMMUNICATED_WITH {key: $edge_key}]->(dst)
            SET edge.bucket = $bucket, edge.protocol = $protocol, edge.src_port = $src_port, edge.dst_port = $dst_port,
                edge.bytes = $bytes, edge.packets = $packets, edge.first_seen = $first_seen, edge.last_seen = $last_seen,
                edge.source = $source, edge.session = $session, edge.interface = $interface
            WITH sensor
            FOREACH (_ IN CASE WHEN $interface = '' THEN [] ELSE [1] END |
              MERGE (iface:Interface {id: $interface_id}) SET iface.name = $interface, iface.sensor_node_id = $node
              MERGE (sensor)-[:HAS_INTERFACE]->(iface)
            )
            FOREACH (_ IN CASE WHEN $session = '' THEN [] ELSE [1] END |
              MERGE (capture:CaptureSession {id: $node + ':' + $session}) SET capture.session_id = $session, capture.sensor_node_id = $node
              MERGE (sensor)-[:CAPTURED]->(capture)
            )
        """, params)
        metadata = flow.get("l7_metadata") or {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (TypeError, ValueError):
                metadata = {}
        tls = metadata.get("tls") if isinstance(metadata.get("tls"), dict) else {}
        geo = metadata.get("geoip") if isinstance(metadata.get("geoip"), dict) else {}
        domain = str(
            metadata.get("server_name") or metadata.get("domain") or metadata.get("hostname")
            or tls.get("server_name") or tls.get("sni") or ""
        ).strip().lower()[:253]
        certificate = str(
            metadata.get("certificate_sha256") or metadata.get("cert_sha256")
            or tls.get("certificate_sha256") or tls.get("cert_sha256") or ""
        ).strip().lower()[:128]
        asn = str(geo.get("asn") or metadata.get("asn") or "").strip()[:64]
        if domain or certificate or asn:
            self._run_write("""
                MATCH (endpoint:Endpoint {id: $endpoint_id})
                FOREACH (_ IN CASE WHEN $domain = '' THEN [] ELSE [1] END |
                  MERGE (domain:Domain {id: $domain_id}) SET domain.name = $domain
                  MERGE (domain)-[:RESOLVES_TO]->(endpoint)
                )
                FOREACH (_ IN CASE WHEN $certificate = '' THEN [] ELSE [1] END |
                  MERGE (certificate:Certificate {id: $certificate_id}) SET certificate.sha256 = $certificate
                  MERGE (endpoint)-[:PRESENTED_CERTIFICATE]->(certificate)
                )
                FOREACH (_ IN CASE WHEN $asn = '' THEN [] ELSE [1] END |
                  MERGE (asn:ASN {id: $asn_id}) SET asn.value = $asn
                  MERGE (endpoint)-[:ANNOUNCED_BY]->(asn)
                )
            """, {
                "endpoint_id": self._endpoint_id(node, dst_ip), "domain": domain, "domain_id": f"domain:{domain}",
                "certificate": certificate, "certificate_id": f"certificate:{certificate}", "asn": asn, "asn_id": f"asn:{asn}",
            })

    def _apply_process(self, observation: Dict[str, Any]) -> None:
        node = str(observation.get("sensor_node_id") or self.db.local_sensor_node_id())
        local_ip = str(observation.get("local_ip") or "")
        if not local_ip:
            return
        identity = str(observation.get("process_guid") or observation.get("pid") or observation.get("id"))
        process_id = f"process:{node}:{identity}"
        params = {
            "node": node, "endpoint_id": self._endpoint_id(node, local_ip), "local_ip": local_ip, "process_id": process_id,
            "pid": observation.get("pid"), "image": observation.get("image"), "user_name": observation.get("user_name"),
            "observed_at": float(observation.get("observed_at") or 0.0), "evidence_ref": observation.get("evidence_ref"),
            "services": list(observation.get("service_names") or [])[:16],
        }
        self._run_write("""
            MERGE (sensor:SensorNode {id: $node})
            MERGE (endpoint:Endpoint {id: $endpoint_id}) SET endpoint.ip = $local_ip, endpoint.sensor_node_id = $node
            MERGE (process:Process {id: $process_id}) SET process.pid = $pid, process.image = $image, process.user_name = $user_name, process.sensor_node_id = $node
            MERGE (sensor)-[:OBSERVED_ON]->(endpoint)
            MERGE (endpoint)-[relationship:USED_PROCESS {evidence_ref: $evidence_ref}]->(process)
            SET relationship.observed_at = $observed_at, relationship.confidence = 0.98
            WITH process
            UNWIND $services AS service_name
            MERGE (service:WindowsService {id: $node + ':' + service_name}) SET service.name = service_name, service.sensor_node_id = $node
            MERGE (process)-[:RUNS_SERVICE]->(service)
        """, params)

    def _apply_finding(self, finding: Dict[str, Any]) -> None:
        node = str(finding.get("sensor_node_id") or self.db.local_sensor_node_id())
        subject = str(finding.get("subject") or "")
        if not subject:
            return
        finding_id = f"finding:{node}:{finding.get('id') or finding.get('fingerprint')}"
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        rule_id = str(evidence.get("rule_id") or evidence.get("sigma_rule_id") or "")[:256]
        self._run_write("""
            MERGE (endpoint:Endpoint {id: $endpoint_id}) SET endpoint.ip = $subject, endpoint.sensor_node_id = $node
            MERGE (finding:Finding {id: $finding_id})
            SET finding.finding_type = $finding_type, finding.category = $category, finding.impact = $impact,
                finding.confidence = $confidence, finding.first_seen = $first_seen, finding.last_seen = $last_seen,
                finding.fingerprint = $fingerprint, finding.sensor_node_id = $node
            MERGE (endpoint)-[relationship:TRIGGERED {finding_id: $finding_id}]->(finding)
            SET relationship.first_seen = $first_seen, relationship.last_seen = $last_seen
            MERGE (evidence:EvidenceReference {id: $evidence_id})
            SET evidence.reference = $evidence_reference, evidence.sensor_node_id = $node
            MERGE (finding)-[:EVIDENCED_BY]->(evidence)
            FOREACH (_ IN CASE WHEN $rule_id = '' THEN [] ELSE [1] END |
              MERGE (rule:SigmaRule {id: $rule_id}) SET rule.rule_id = $rule_id
              MERGE (rule)-[:TRIGGERED]->(finding)
            )
        """, {
            "node": node, "endpoint_id": self._endpoint_id(node, subject), "subject": subject, "finding_id": finding_id,
            "finding_type": finding.get("finding_type"), "category": finding.get("category"), "impact": finding.get("impact"),
            "confidence": float(finding.get("confidence") or 0.0), "first_seen": float(finding.get("first_seen") or 0.0),
            "last_seen": float(finding.get("last_seen") or 0.0), "fingerprint": finding.get("fingerprint"),
            "evidence_id": f"evidence:{finding_id}",
            "evidence_reference": str((finding.get("evidence_refs") or [finding_id])[0])[:512],
            "rule_id": rule_id,
        })

    def _apply_identity(self, identity: Dict[str, Any]) -> None:
        node = str(identity.get("sensor_node_id") or self.db.local_sensor_node_id())
        ip = str(identity.get("entity_ip") or "")
        if not ip:
            return
        identity_id = "identity:{node}:{ip}:{kind}:{label}:{model}".format(
            node=node, ip=ip, kind=str(identity.get("identity_type") or "unknown"),
            label=str(identity.get("identity_label") or "unknown")[:256], model=str(identity.get("model_version") or "v1"),
        )
        self._run_write("""
            MERGE (endpoint:Endpoint {id: $endpoint_id}) SET endpoint.ip = $ip, endpoint.sensor_node_id = $node
            MERGE (identity:Identity {id: $identity_id})
            SET identity.kind = $kind, identity.label = $label, identity.confidence = $confidence,
                identity.verification = $verification, identity.first_seen = $first_seen, identity.last_seen = $last_seen,
                identity.sensor_node_id = $node
            MERGE (endpoint)-[:HAS_IDENTITY]->(identity)
        """, {
            "endpoint_id": self._endpoint_id(node, ip), "ip": ip, "node": node, "identity_id": identity_id,
            "kind": str(identity.get("identity_type") or "unknown"), "label": str(identity.get("identity_label") or "unknown")[:512],
            "confidence": float(identity.get("confidence") or 0.0), "verification": str(identity.get("verification") or "observed"),
            "first_seen": float(identity.get("first_seen") or 0.0), "last_seen": float(identity.get("last_seen") or 0.0),
        })

    def _apply_artifact(self, artifact: Dict[str, Any]) -> None:
        node = str(artifact.get("sensor_node_id") or self.db.local_sensor_node_id())
        sha256 = str(artifact.get("sha256") or "")
        ip = str(artifact.get("entity_ip") or "")
        if not sha256 or not ip:
            return
        self._run_write("""
            MERGE (endpoint:Endpoint {id: $endpoint_id}) SET endpoint.ip = $ip, endpoint.sensor_node_id = $node
            MERGE (artifact:Artifact {id: $artifact_id})
            SET artifact.sha256 = $sha256, artifact.filename = $filename, artifact.extension = $extension,
                artifact.size = $size, artifact.timestamp = $timestamp, artifact.sensor_node_id = $node
            MERGE (endpoint)-[:EVIDENCED_BY]->(artifact)
        """, {
            "endpoint_id": self._endpoint_id(node, ip), "ip": ip, "node": node, "artifact_id": f"artifact:{node}:{sha256}",
            "sha256": sha256, "filename": str(artifact.get("filename") or "")[:512],
            "extension": str(artifact.get("extension") or "")[:64], "size": int(artifact.get("size") or 0),
            "timestamp": float(artifact.get("timestamp") or 0.0),
        })

    def _apply_hardware_observation(self, observation: Dict[str, Any]) -> None:
        node = str(observation.get("sensor_node_id") or self.db.local_sensor_node_id())
        subject = str(observation.get("subject") or "")
        if not subject:
            return
        observation_id = f"hardware:{node}:{observation.get('id') or subject}:{int(float(observation.get('timestamp') or 0))}"
        self._run_write("""
            MERGE (sensor:SensorNode {id: $node})
            MERGE (hardware:HardwareObservation {id: $observation_id})
            SET hardware.subject = $subject, hardware.peer = $peer, hardware.source_type = $source_type,
                hardware.observation_type = $observation_type, hardware.timestamp = $timestamp, hardware.sensor_node_id = $node
            MERGE (sensor)-[:OBSERVED_ON]->(hardware)
        """, {
            "node": node, "observation_id": observation_id, "subject": subject,
            "peer": str(observation.get("peer") or "")[:512], "source_type": str(observation.get("source_type") or "unknown")[:64],
            "observation_type": str(observation.get("observation_type") or "unknown")[:128],
            "timestamp": float(observation.get("timestamp") or 0.0),
        })

    def _apply_case(self, case: Dict[str, Any]) -> None:
        node = str(case.get("sensor_node_id") or self.db.local_sensor_node_id())
        case_id = str(case.get("id") or "")
        if not case_id:
            return
        target = str(case.get("target") or "")
        self._run_write("""
            MERGE (sensor:SensorNode {id: $node})
            MERGE (case:Case {id: $case_id})
            SET case.sensor_node_id = $node, case.source = $source, case.generated_at = $generated_at,
                case.manifest_sha256 = $manifest_sha256
            MERGE (sensor)-[:OBSERVED_ON]->(case)
            FOREACH (_ IN CASE WHEN $target = '' THEN [] ELSE [1] END |
              MERGE (endpoint:Endpoint {id: $endpoint_id}) SET endpoint.ip = $target, endpoint.sensor_node_id = $node
              MERGE (case)-[:EVIDENCED_BY]->(endpoint)
            )
        """, {
            "node": node, "case_id": f"case:{node}:{case_id}", "source": str(case.get("source") or ""),
            "generated_at": float(case.get("generated_at") or 0.0),
            "manifest_sha256": str(case.get("manifest_sha256") or ""), "target": target,
            "endpoint_id": self._endpoint_id(node, target),
        })

    def _get_driver(self):
        if self._driver is None:
            if not self.config.password:
                raise RuntimeError("WATCHTOWER_NEO4J_PASSWORD or graph password configuration is required")
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(self.config.uri, auth=(self.config.username, self.config.password))
        return self._driver

    def _run(self, query: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        with self._get_driver().session(database=self.config.database) as session:
            return [record.data() for record in session.run(query, parameters)]

    def _run_write(self, query: str, parameters: Dict[str, Any]) -> None:
        with self._get_driver().session(database=self.config.database) as session:
            session.run(query, parameters).consume()

    def _require_available(self) -> None:
        status = self.status()
        if not status["available"]:
            raise RuntimeError(status["reason"])

    @staticmethod
    def _endpoint_id(node_id: str, ip: str) -> str:
        return f"endpoint:{node_id}:{ip}"
