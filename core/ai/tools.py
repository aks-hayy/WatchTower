"""Typed WatchTower tools exposed to the local analyst orchestrator."""

from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from core.ai.contracts import EvidenceCitation, EvidenceFact, ScopedContext, ToolManifest, ToolResult
from core.backend_policy import backend_policy
from core.ai.redaction import redact_text, redact_value
from core.forensics.sigma_engine import SigmaEngine
from core.intelligence.local_assets import LocalAssetProfiler
from core.investigation.export import CaseExporter
from core.investigation.service import InvestigationService


def _scope(scope: ScopedContext) -> Dict[str, Any]:
    return scope.to_dict()


def _citations(rows: Iterable[Dict], kind: str, scope: ScopedContext, source: str = "watchtower") -> List[EvidenceCitation]:
    citations = []
    for index, row in enumerate(rows):
        stable = row.get("id") or row.get("flow_id") or row.get("finding_id")
        if stable is not None:
            reference = f"{kind}:{stable}"
        else:
            digest = hashlib.sha256(
                f"{kind}:{row.get('ip') or row.get('entity_ip') or index}:{scope.session_id or scope.source or ''}".encode("utf-8")
            ).hexdigest()[:20]
            reference = f"{kind}:{digest}"
        citations.append(EvidenceCitation(
            reference, row.get("source") or source, f"Stored WatchTower {kind} record",
            row.get("timestamp") or row.get("last_seen"), kind="watchtower", scope=_scope(scope),
        ))
    return citations


_FACT_KEYS = {
    "ip", "entity_ip", "src_ip", "dst_ip", "hostname", "domain", "ptr", "asn", "organization",
    "country", "role", "service", "protocol", "flow_count", "packet_count", "byte_count", "alert_count",
    "finding_count", "confirmed_endpoints", "probable_endpoints", "unconfirmed_targets", "observed_addresses",
    "evidence_backed_identities", "actionable_identities", "risk_level", "priority_score", "confidence",
}


def _facts(value: Any, citations: List[EvidenceCitation], scope: ScopedContext, tool: str) -> List[EvidenceFact]:
    """Extract bounded scalar facts; never persist arbitrary payload excerpts."""
    rows = value if isinstance(value, list) else [value]
    facts: List[EvidenceFact] = []
    for row in rows[:500]:
        if not isinstance(row, dict):
            continue
        subject = str(row.get("ip") or row.get("entity_ip") or row.get("src_ip") or row.get("indicator") or tool)
        for key, raw in row.items():
            if key not in _FACT_KEYS or isinstance(raw, (dict, list, tuple, bytes)) or raw is None:
                continue
            if isinstance(raw, float) and (raw != raw or raw in {float("inf"), float("-inf")}):
                continue
            facts.append(EvidenceFact.create(
                subject, key, raw, confidence=float(row.get("confidence", 1.0) or 1.0),
                completeness="partial" if row.get("truncated") else "complete",
                freshness=row.get("last_seen") or row.get("retrieved_at"), scope=scope.to_dict(),
                citations=citations[:2],
            ))
            if len(facts) >= 1000:
                return facts
    return facts


def _result(name: str, value: Any, citations: List[EvidenceCitation], truncated: bool = False, summary: str = "") -> ToolResult:
    safe = redact_value(value)
    if not summary:
        # A mapping is one structured result, not one result per field.
        count = len(value) if isinstance(value, (list, tuple)) else 1
        summary = f"{count} redacted {name} result(s) returned."
    fact_scope = ScopedContext.from_dict(citations[0].scope) if citations and citations[0].scope else ScopedContext()
    facts = _facts(safe, citations, fact_scope, name)
    return ToolResult(name, safe, citations, truncated, summary=redact_text(summary, 1000), redacted=True, facts=facts)


class AITool(ABC):
    manifest: ToolManifest

    @property
    def name(self) -> str:
        return self.manifest.name

    @abstractmethod
    def execute(self, scope: ScopedContext, **arguments) -> ToolResult:
        pass


class ReadOnlyTool(AITool):
    """Compatibility name for existing safe tool implementations."""


class CallableTool(AITool):
    def __init__(self, manifest: ToolManifest, handler: Callable[..., Any], citation_kind: str = "record"):
        self.manifest, self.handler, self.citation_kind = manifest, handler, citation_kind

    def execute(self, scope: ScopedContext, **arguments) -> ToolResult:
        value = self.handler(scope, **arguments)
        rows = value if isinstance(value, list) else [value]
        return _result(self.name, value, _citations([row for row in rows if isinstance(row, dict)], self.citation_kind, scope))


class FlowTool(ReadOnlyTool):
    manifest = ToolManifest(
        "flows", "Read bounded stored flows in the selected WatchTower scope.",
        {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}}},
        requires_scope=True,
    )

    def __init__(self, db):
        self.db = db

    def execute(self, scope, **arguments):
        limit = min(max(1, int(arguments.get("limit", scope.max_records))), scope.max_records)
        kwargs = {"source": scope.source, "interface": scope.interface,
                  "capture_session_id": scope.session_id, "limit": limit}
        if scope.node_id:
            kwargs["sensor_node_id"] = scope.node_id
        rows = self.db.get_flows(**kwargs)
        if scope.target_ips:
            rows = [row for row in rows if row.get("src_ip") in scope.target_ips or row.get("dst_ip") in scope.target_ips]
        return _result(self.name, rows, _citations(rows, "flow", scope), len(rows) == limit,
                       f"{len(rows)} stored flow(s) in the selected capture scope.")


class AlertTool(ReadOnlyTool):
    manifest = ToolManifest(
        "alerts", "Read bounded stored alerts in the selected WatchTower scope.",
        {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}}},
        requires_scope=True,
    )

    def __init__(self, db):
        self.db = db

    def execute(self, scope, **arguments):
        limit = min(max(1, int(arguments.get("limit", scope.max_records))), scope.max_records)
        kwargs = {"source": scope.source, "limit": limit, "interface": scope.interface,
                  "capture_session_id": scope.session_id}
        if scope.node_id:
            kwargs["sensor_node_id"] = scope.node_id
        rows = self.db.get_alerts(**kwargs)
        if scope.target_ips:
            rows = [row for row in rows if row.get("entity_ip") in scope.target_ips]
        return _result(self.name, rows, _citations(rows, "alert", scope), len(rows) == limit,
                       f"{len(rows)} stored alert(s) in the selected capture scope.")


class AssetTool(ReadOnlyTool):
    manifest = ToolManifest(
        "assets", "Build a passive, evidence-backed asset profile without persisting changes.",
        {"type": "object", "properties": {"ips": {"type": "array", "items": {"type": "string"}}}},
    )

    def __init__(self, db):
        self.db, self.profiler = db, LocalAssetProfiler(db)

    def execute(self, scope, **arguments):
        ips = arguments.get("ips") or scope.target_ips
        if not ips:
            flow_kwargs = {"source": scope.source, "interface": scope.interface,
                           "capture_session_id": scope.session_id, "limit": scope.max_records}
            if scope.node_id:
                flow_kwargs["sensor_node_id"] = scope.node_id
            ips = sorted({
                ip for row in self.db.get_flows(**flow_kwargs)
                for ip in (row.get("src_ip"), row.get("dst_ip")) if ip
            })
        rows = [
            self.profiler.build(str(ip), source=scope.source, persist=False, sensor_node_id=scope.node_id).to_dict()
            for ip in list(ips)[:scope.max_records]
        ]
        citations = [EvidenceCitation(f"entity:{row['ip']}", scope.source or "watchtower", "Stored passive asset profile",
                                     kind="watchtower", scope=_scope(scope)) for row in rows]
        return _result(self.name, rows, citations, summary=f"{len(rows)} passive asset profile(s) built from stored evidence.")


class TimelineTool(ReadOnlyTool):
    manifest = ToolManifest("timeline", "Read bounded traffic timeline statistics for the selected scope.",
                            {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}}})

    def __init__(self, db):
        self.db = db

    def execute(self, scope, **arguments):
        limit = min(scope.max_records, max(1, int(arguments.get("limit", 60))))
        if scope.node_id or scope.interface or scope.session_id:
            flow_kwargs = {"source": scope.source, "interface": scope.interface,
                           "capture_session_id": scope.session_id, "limit": scope.max_records}
            if scope.node_id:
                flow_kwargs["sensor_node_id"] = scope.node_id
            buckets: Dict[int, Dict[str, Any]] = {}
            for flow in self.db.get_flows(**flow_kwargs):
                timestamp = int(float(flow.get("last_seen") or flow.get("start_time") or 0) // 300 * 300)
                bucket = buckets.setdefault(timestamp, {"timestamp": timestamp, "packets": 0, "bytes": 0})
                bucket["packets"] += int(flow.get("packet_count") or 0)
                bucket["bytes"] += int(flow.get("byte_count") or 0)
            rows = sorted(buckets.values(), key=lambda item: item["timestamp"], reverse=True)[:limit]
        else:
            rows = self.db.get_timeline(limit=limit, source=scope.source or "live")
        return _result(self.name, rows, _citations(rows, "timeline", scope), len(rows) == limit)


class SigmaPreviewTool(ReadOnlyTool):
    manifest = ToolManifest("sigma_hunt_preview", "Evaluate active Sigma rules against stored historical traffic without persisting alerts.",
                            {"type": "object", "properties": {"rule": {"type": "string"}}}, requires_scope=True)

    def __init__(self, db):
        self.engine = SigmaEngine(db=db)

    def execute(self, scope, **arguments):
        alerts = self.engine.run_hunt(scope.source, arguments.get("rule"), scope.interface, persist=False)
        rows = [{"type": alert.type, "severity": alert.severity, "explanation": alert.explanation,
                 "evidence": alert.evidence} for alert in alerts]
        citations = [EvidenceCitation(str(row["evidence"].get("record_id") or index), scope.source or "historical",
                                     row["explanation"], kind="watchtower", scope=_scope(scope)) for index, row in enumerate(rows)]
        return _result(self.name, rows, citations, summary=f"Historical Sigma preview found {len(rows)} match(es).")


class StreamTool(ReadOnlyTool):
    """Redacted successor to the legacy base64 stream preview."""

    manifest = ToolManifest(
        "streams", "Inspect bounded stream metadata and a redacted text excerpt; never returns raw packet bytes.",
        {"type": "object", "properties": {"flow_id": {"type": "array", "minItems": 5, "maxItems": 5},
                                                 "max_bytes": {"type": "integer", "minimum": 1, "maximum": 65536}}},
        requires_scope=True,
    )

    def __init__(self, engine, report=None):
        self.engine, self.report = engine, report

    def execute(self, scope, **arguments):
        raw_flow_id = arguments["flow_id"]
        flow_id = (raw_flow_id[0], raw_flow_id[1], int(raw_flow_id[2]), int(raw_flow_id[3]), raw_flow_id[4])
        maximum = min(max(1, int(arguments.get("max_bytes", 4096))), 65536)
        directions = self.engine.load_stream(flow_id, self.report)
        data = {}
        for direction, payload in directions.items():
            bounded = payload[:maximum]
            decoded = redact_text(bounded.decode("utf-8", errors="replace"), maximum)
            printable = "".join(character if character.isprintable() or character in "\r\n\t" else " " for character in decoded)
            data[direction] = {
                "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                "excerpt": printable, "truncated": len(payload) > maximum,
            }
        reference = f"stream:{flow_id[0]}:{flow_id[2]}->{flow_id[1]}:{flow_id[3]}/{flow_id[4]}"
        return _result(self.name, data, [EvidenceCitation(reference, scope.source or "watchtower", "Redacted stored TCP stream evidence",
                                                           kind="watchtower", scope=_scope(scope))],
                       any(item["truncated"] for item in data.values()), "Redacted stream metadata returned.")


class EvidenceExcerptTool(ReadOnlyTool):
    """Persistent evidence view used when raw offline stream state is unavailable."""

    manifest = ToolManifest(
        "evidence_excerpt",
        "Inspect bounded, redacted flow and application metadata; never returns payload bytes.",
        {"type": "object", "properties": {
            "flow_id": {"anyOf": [
                {"type": "array", "minItems": 5, "maxItems": 5},
                {"type": "string", "maxLength": 512},
            ]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        }},
        requires_scope=True,
    )

    def __init__(self, db):
        self.db = db

    def execute(self, scope, **arguments):
        limit = min(scope.max_records, max(1, int(arguments.get("limit", 20))), 100)
        flow_kwargs = {"source": scope.source, "interface": scope.interface,
                       "capture_session_id": scope.session_id, "limit": limit}
        if scope.node_id:
            flow_kwargs["sensor_node_id"] = scope.node_id
        rows = self.db.get_flows(**flow_kwargs)
        flow_id = arguments.get("flow_id")
        query_warning = None
        if isinstance(flow_id, list) and len(flow_id) == 5:
            needle = (str(flow_id[0]), str(flow_id[1]), int(flow_id[2]), int(flow_id[3]), str(flow_id[4]))
            rows = [row for row in rows if (
                str(row.get("src_ip")), str(row.get("dst_ip")), int(row.get("src_port") or 0),
                int(row.get("dst_port") or 0), str(row.get("protocol")),
            ) == needle]
        elif flow_id:
            # Some local models confuse a session ID with a flow selector. Keep
            # the request scoped and useful by returning the bounded page while
            # making the ignored selector explicit to the analyst.
            query_warning = "flow selector was not a canonical five-field flow key; returned the bounded scoped page"
        evidence = []
        citations = []
        for row in rows[:limit]:
            flow_key = f"{row.get('src_ip')}:{row.get('src_port')}->{row.get('dst_ip')}:{row.get('dst_port')}/{row.get('protocol')}"
            metadata = row.get("l7_metadata") or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except ValueError:
                    metadata = {}
            evidence.append({
                "flow_id": flow_key,
                "direction": f"{row.get('src_ip')} -> {row.get('dst_ip')}",
                "protocol": row.get("protocol"),
                "packet_count": int(row.get("packet_count") or 0),
                "byte_count": int(row.get("byte_count") or 0),
                "metadata": redact_value(metadata),
                "payload": "[NOT_RETAINED]",
                "truncated": bool(row.get("stream_truncated") or False),
                "evidence_hash": hashlib.sha256(flow_key.encode("utf-8")).hexdigest(),
            })
            citations.append(EvidenceCitation(f"flow:{row.get('id')}", row.get("source") or "watchtower",
                                              "Redacted flow evidence metadata", kind="watchtower", scope=_scope(scope)))
        data = {"items": evidence}
        if query_warning:
            data["query_warning"] = query_warning
        return _result(self.name, data, citations, len(rows) > limit,
                       f"{len(evidence)} redacted evidence excerpt(s) returned without packet payloads.")


class CaseExportTool(AITool):
    manifest = ToolManifest(
        "case_export", "Export a hashed WatchTower case bundle for an IP.",
        {"type": "object", "properties": {"ip": {"type": "string"}, "case_name": {"type": "string"}}, "required": ["ip"]},
        risk_tier="confirm", active=True,
    )

    def __init__(self, db, output_dir):
        self.service, self.exporter = InvestigationService(db), CaseExporter(output_dir)

    def execute(self, scope, **arguments):
        ip = arguments["ip"]
        investigation = self.service.investigate(
            ip, source=scope.source, persist=False, sensor_node_id=scope.node_id,
        )
        path = self.exporter.export(investigation, arguments.get("case_name"))
        return _result(self.name, {"path": str(path)}, [EvidenceCitation(f"case:{path.name}", scope.source or "watchtower",
                                                                            "Hashed case export", kind="watchtower", scope=_scope(scope))])


class ResearchTool(AITool):
    manifest = ToolManifest(
        "research", "Research public indicators using controlled authoritative, threat-intelligence, and web sources.",
        {"type": "object", "properties": {"indicators": {"type": "array", "items": {"type": "string"}},
                                                 "query": {"type": "string"}, "include_web": {"type": "boolean"},
                                                 "web_provider": {"type": "string", "enum": ["brave", "openai"]}}},
        allows_external_network=True,
    )

    def __init__(self, broker):
        self.broker = broker

    def execute(self, scope, **arguments):
        documents = self.broker.research(arguments.get("indicators") or (), str(arguments.get("query") or ""),
                                         bool(arguments.get("include_web", True)), str(arguments.get("web_provider") or "brave"))
        citations = [item.citation() for item in documents]
        rows = [{"source": item.source_kind, "url": item.canonical_url, "title": item.title,
                 "summary": item.summary, "content_hash": item.content_hash, "retrieved_at": item.retrieved_at,
                 "facts": item.facts} for item in documents]
        facts = []
        for document, citation in zip(documents, citations):
            for item in document.facts:
                facts.append(EvidenceFact.create(
                    str(item.get("subject") or "indicator"), str(item.get("predicate") or "external_observation"),
                    redact_value(item.get("value")), confidence=float(item.get("confidence", 0.5) or 0.0),
                    freshness=document.retrieved_at, citations=[citation], scope=scope.to_dict(),
                ))
        result = _result(self.name, rows, citations, summary=f"{len(rows)} external research source(s) returned.")
        result.facts = facts
        return result


class ToolRegistry:
    def __init__(self, tools: Iterable[AITool] = ()): 
        self.tools: Dict[str, AITool] = {}
        for tool in tools:
            if tool.name in self.tools:
                raise ValueError(f"Duplicate AI tool: {tool.name}")
            self.tools[tool.name] = tool

    def manifests(self) -> List[ToolManifest]:
        return [tool.manifest for _, tool in sorted(self.tools.items())]

    def manifests_for_prompt(self, prompt: str, allowed: Iterable[str] = (), mode: str = "investigate") -> List[ToolManifest]:
        """Expose a small intent-matched tool set while retaining policy control."""
        text = str(prompt or "").casefold()
        if mode == "general":
            return []
        allowed_set = set(allowed or self.tools)
        groups = {
            "identity": {"identity_coverage", "identities", "lookup", "investigate", "endpoint_processes"},
            "finding": {"finding_summary", "findings", "alerts", "risk_explain", "sigma_hunt_preview"},
            "traffic": {"session_summary", "top_conversations", "flows", "timeline", "topology", "evidence_excerpt"},
            "health": {"visibility_limits", "pipeline_health", "pcap_jobs", "reports", "mesh_nodes"},
            "research": {"lookup", "research", "evidence", "graph_neighborhood", "graph_timeline"},
            "plugin": {"plugins", "calibration_status", "plugin_scaffold_detector", "plugin_create_threshold_detector"},
        }
        selected = set()
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in ("identity", "ip", "host", "device", "endpoint", "enrich")):
            selected |= groups["identity"]
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in ("alert", "finding", "detector", "sigma", "score", "risk", "suspicious")):
            selected |= groups["finding"]
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in ("flow", "traffic", "conversation", "timeline", "topology", "pcap", "packet")):
            selected |= groups["traffic"]
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in ("health", "complete", "drop", "sensor", "session")):
            selected |= groups["health"]
        if any(word in text for word in ("research", "who owns", "asn", "organization", "lookup")):
            selected |= groups["research"]
        if any(word in text for word in ("plugin", "calibrat", "create a detector")):
            selected |= groups["plugin"]
        selected &= allowed_set
        if not selected:
            selected = {name for name in ("session_summary", "identity_coverage", "finding_summary", "visibility_limits") if name in allowed_set}
        ordered = sorted(name for name in selected if name in self.tools)
        # Keep an explicitly requested opening tool available even when the
        # intent router has more than ten relevant candidates.
        first_match = re.search(r"\bfirst\s+(?:use|call|run)\s+([a-z][a-z0-9_]*)\b", text)
        requested_first = first_match.group(1) if first_match else None
        if requested_first in ordered and requested_first not in ordered[:10]:
            ordered = [requested_first] + [name for name in ordered if name != requested_first][:9]
        return [self.tools[name].manifest for name in ordered[:10]]

    def get(self, name: str) -> AITool:
        if name not in self.tools:
            raise KeyError(f"Unknown AI tool: {name}")
        return self.tools[name]

    def execute(self, name, scope, **arguments):
        return self.get(name).execute(scope, **arguments)


def build_native_tools(db, service=None, stream_engine=None, research_broker=None) -> ToolRegistry:
    """Create the complete read-only native inventory plus safe action adapters."""
    tools: List[AITool] = [
        FlowTool(db), AlertTool(db), AssetTool(db), TimelineTool(db), SigmaPreviewTool(db), EvidenceExcerptTool(db),
    ]
    if stream_engine is not None:
        tools.append(StreamTool(stream_engine))
    if research_broker is not None:
        tools.append(ResearchTool(research_broker))
    if service is None:
        return ToolRegistry(tools)

    tools.extend([
        CallableTool(ToolManifest("session_summary", "Summarize the selected capture session and its visibility state.", {"type": "object", "properties": {}}, requires_scope=True),
                     lambda scope, **args: _session_summary(db, scope), "session"),
        CallableTool(ToolManifest("identity_coverage", "Return truthful identity state counts for the selected scope.", {"type": "object", "properties": {}}, requires_scope=True),
                     lambda scope, **args: service.identity_status(scope.source, scope.interface, scope.session_id), "identity"),
        CallableTool(ToolManifest("top_conversations", "Return the highest-volume conversations in the selected scope.", {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}}}, requires_scope=True),
                     lambda scope, **args: _top_conversations(db, scope, int(args.get("limit", 10))), "flow"),
        CallableTool(ToolManifest("finding_summary", "Summarize canonical findings in the selected scope.", {"type": "object", "properties": {}}, requires_scope=True),
                     lambda scope, **args: service.scoring_findings(source=scope.source, interface=scope.interface, session=scope.session_id, limit=scope.max_records, sensor_node_id=scope.node_id), "finding"),
        CallableTool(ToolManifest("visibility_limits", "Report capture completeness, processing limits, and pipeline health.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.pipeline_health(), "pipeline"),
        CallableTool(ToolManifest("findings", "Read V2 canonical detection findings.", {"type": "object", "properties": {"finding_type": {"type": "string"}}}, requires_scope=True),
                     lambda scope, **args: service.scoring_findings(source=scope.source, interface=scope.interface, session=scope.session_id,
                                                                       finding_type=args.get("finding_type"), limit=scope.max_records,
                                                                       sensor_node_id=scope.node_id), "finding"),
        CallableTool(ToolManifest("risk_explain", "Explain a V2 investigation-priority score for an endpoint.", {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}, requires_scope=True),
                     lambda scope, **args: service.scoring_risk(args["ip"], scope.source, scope.interface, scope.session_id, explain=True, sensor_node_id=scope.node_id), "risk"),
        CallableTool(ToolManifest("identities", "Read evidence-backed endpoint identity cards.", {"type": "object", "properties": {"limit": {"type": "integer"}}}, requires_scope=True),
                     lambda scope, **args: service.endpoint_identities(scope.source, scope.interface, scope.session_id, min(scope.max_records, int(args.get("limit", scope.max_records))), scope.node_id), "identity"),
        CallableTool(ToolManifest("lookup", "Look up one endpoint using WatchTower's local evidence and enrichment.", {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}, requires_scope=True),
                     lambda scope, **args: service.lookup(args["ip"], scope.source, scope.node_id), "lookup"),
        CallableTool(ToolManifest("investigate", "Build a scoped WatchTower investigation for an endpoint.", {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}, requires_scope=True),
                     lambda scope, **args: service.investigate(args["ip"], scope.source, scope.node_id), "investigation"),
        CallableTool(ToolManifest("topology", "Read the bounded network topology from stored flows.", {"type": "object", "properties": {}}, requires_scope=True),
                     lambda scope, **args: service.topology(scope.source, scope.interface, scope.session_id, scope.node_id), "topology"),
        CallableTool(ToolManifest("mesh_nodes", "Read registered sensor nodes and mesh health.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.mesh_status(), "mesh-node"),
        CallableTool(ToolManifest(
            "endpoint_processes", "Read redacted Sysmon process and Windows-service observations.",
            {"type": "object", "properties": {
                "ip": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            }}, requires_scope=True),
                     lambda scope, **args: service.endpoint_processes(args.get("ip"), scope.node_id, min(scope.max_records, int(args.get("limit", 50)))), "endpoint-process"),
        CallableTool(ToolManifest("graph_status", "Read Neo4j evidence graph availability and freshness.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.graph_status(), "graph"),
        CallableTool(ToolManifest("graph_neighborhood", "Read a bounded evidence graph neighborhood for one endpoint.", {"type": "object", "properties": {"ip": {"type": "string"}, "depth": {"type": "integer", "minimum": 1, "maximum": 3}}, "required": ["ip"]}, requires_scope=True),
                     lambda scope, **args: service.graph_neighborhood(args["ip"], scope.node_id, int(args.get("depth", 2)), scope.max_records), "graph"),
        CallableTool(ToolManifest("graph_path", "Find a bounded evidence path between two endpoint IPs.", {"type": "object", "properties": {"source_ip": {"type": "string"}, "target_ip": {"type": "string"}}, "required": ["source_ip", "target_ip"]}, requires_scope=True),
                     lambda scope, **args: service.graph_path(args["source_ip"], args["target_ip"], scope.node_id), "graph"),
        CallableTool(ToolManifest("graph_timeline", "Read a bounded evidence timeline for one endpoint.", {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}, requires_scope=True),
                     lambda scope, **args: service.graph_timeline(args["ip"], scope.node_id, scope.time_start, scope.time_end, scope.max_records), "graph"),
        CallableTool(ToolManifest("pipeline_health", "Read capture and analytics health telemetry.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.pipeline_health(), "pipeline"),
        CallableTool(ToolManifest("reports", "List completed and partial PCAP analysis reports.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.forensic_reports(), "report"),
        CallableTool(ToolManifest("pcap_jobs", "Read bounded offline PCAP analysis job state and reports.",
                                  {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}}}),
                     lambda scope, **args: service.pcap_jobs(min(100, max(1, int(args.get("limit", 25))))), "pcap-job"),
        CallableTool(ToolManifest("plugins", "Read parser, detector, and hardware plugin inventory.", {"type": "object", "properties": {}}),
                     lambda scope, **args: service.plugin_inventory(), "plugin"),
        CallableTool(ToolManifest("calibration_status", "Read detector calibration and attestation state.", {"type": "object", "properties": {"detector_id": {"type": "string"}}}),
                     lambda scope, **args: service.plugin_calibration_status(args.get("detector_id")), "calibration"),
        CallableTool(ToolManifest("evidence", "List carved evidence metadata without raw file contents.", {"type": "object", "properties": {"ip": {"type": "string"}}}),
                     lambda scope, **args: service.evidence(scope.source, args.get("ip")), "evidence"),
        CallableTool(ToolManifest(
            "capture_start", "Start a selected WatchTower capture source after operator confirmation.",
            {"type": "object", "properties": {"interface": {"type": "string"}, "backend": {"type": "string", "enum": ["python", "rust"]},
                                                     "source_type": {"type": "string", "enum": ["network", "bluetooth"]}}, "required": ["interface"]},
            risk_tier="confirm", active=True, idempotent=False,
        ), lambda scope, **args: service.start_capture(
            str(args["interface"]),
            backend_policy.capture_backend(
                source_type=str(args.get("source_type") or "network"),
                requested_backend=args.get("backend"),
            ),
            str(args.get("source_type") or "network"),
        ), "action"),
        CallableTool(ToolManifest(
            "capture_stop", "Drain and stop a selected WatchTower capture interface after operator confirmation.",
            {"type": "object", "properties": {"interface": {"type": "string"}}, "required": ["interface"]},
            risk_tier="confirm", active=True, idempotent=True,
        ), lambda scope, **args: service.stop_capture(str(args["interface"])), "action"),
        CallableTool(ToolManifest(
            "pcap_cancel", "Cancel a selected offline PCAP analysis job after operator confirmation.",
            {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]},
            risk_tier="confirm", active=True, idempotent=True,
        ), lambda scope, **args: service.cancel_pcap(str(args["job_id"])), "action"),
        CallableTool(ToolManifest(
            "network_survey", "Run WatchTower's bounded survey against directly connected private networks.",
            {"type": "object", "properties": {
                "duration_seconds": {"type": "integer", "minimum": 0, "maximum": 3600},
                "active": {"type": "string", "enum": ["none", "safe", "deep"]},
                "backend": {"type": "string", "enum": ["python", "rust"]},
            }},
            risk_tier="confirm", active=True, idempotent=False,
        ), lambda scope, **args: service.run_survey(
            int(args.get("duration_seconds", 0)),
            str(args.get("active") or "safe"),
            args.get("backend"),
        ), "action"),
        CallableTool(ToolManifest(
            "sigma_hunt_persist", "Run an active Sigma hunt against stored traffic and persist resulting findings.",
            {"type": "object", "properties": {"rule": {"type": "string"}}},
            risk_tier="confirm", active=True, requires_scope=True,
        ), lambda scope, **args: service.run_hunt(scope.source, scope.interface, args.get("rule"), True), "action"),
        CallableTool(ToolManifest(
            "scoring_recompute", "Deterministically recompute behavioral-priority snapshots.",
            {"type": "object", "properties": {"dry_run": {"type": "boolean"}}},
            risk_tier="confirm", active=True, requires_scope=True,
        ), lambda scope, **args: service.scoring_recompute(scope.source, scope.interface, scope.session_id, None, bool(args.get("dry_run", False))), "action"),
        CallableTool(ToolManifest(
            "finding_disposition", "Apply an analyst disposition to one canonical finding.",
            {"type": "object", "properties": {"finding_id": {"type": "integer"}, "verdict": {"type": "string"},
                                                     "reason": {"type": "string"}}, "required": ["finding_id", "verdict", "reason"]},
            risk_tier="confirm", active=True,
        ), lambda scope, **args: service.scoring_disposition(int(args["finding_id"]), str(args["verdict"]), str(args["reason"]), "ai-operator"), "action"),
        CallableTool(ToolManifest(
            "enrichment_rebuild", "Rebuild evidence-backed IP enrichment after capture has stopped.",
            {"type": "object", "properties": {"dry_run": {"type": "boolean"}}},
            risk_tier="confirm", active=True, requires_scope=True,
        ), lambda scope, **args: service.rebuild_enrichment(scope.source, scope.interface, scope.session_id, bool(args.get("dry_run", False))), "action"),
        CallableTool(ToolManifest(
            "identity_rebuild", "Rebuild scoped endpoint identities after capture has stopped.",
            {"type": "object", "properties": {"dry_run": {"type": "boolean"}}},
            risk_tier="confirm", active=True, requires_scope=True,
        ), lambda scope, **args: service.rebuild_identities(scope.source, scope.interface, scope.session_id, bool(args.get("dry_run", False))), "action"),
        CallableTool(ToolManifest(
            "plugin_scaffold_detector", "Create an uncalibrated detector, focused test, and declarative corpus skeleton after operator confirmation.",
            {"type": "object", "properties": {
                "detector_id": {"type": "string"},
                "finding_type": {"type": "string"},
                "input_kind": {"type": "string", "enum": ["packet", "flow", "stream", "session", "metadata"]},
                "description": {"type": "string"},
            }, "required": ["detector_id", "finding_type", "input_kind", "description"]},
            risk_tier="confirm", active=True, idempotent=False,
        ), lambda scope, **args: service.plugin_scaffold_detector(
            str(args["detector_id"]), str(args["finding_type"]),
            str(args["input_kind"]), str(args["description"]),
        ), "plugin"),
        CallableTool(ToolManifest(
            "plugin_create_threshold_detector",
            "Create working bounded flow-threshold detector code, tests, and corpus from a fixed safe template.",
            {"type": "object", "properties": {
                "detector_id": {"type": "string"},
                "finding_type": {"type": "string"},
                "description": {"type": "string"},
                "metric": {"type": "string", "enum": ["byte_count", "packet_count", "tcp_syn_count"]},
                "operator": {"type": "string", "enum": ["gte", "lte"]},
                "threshold": {"type": "integer", "minimum": 1, "maximum": 1073741824},
                "category": {"type": "string", "enum": ["THREAT", "ANOMALY", "EXPOSURE", "POLICY_VIOLATION"]},
                "impact": {"type": "string", "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "confidence_percent": {"type": "integer", "minimum": 1, "maximum": 100},
            }, "required": [
                "detector_id", "finding_type", "description", "metric", "operator",
                "threshold", "category", "impact", "confidence_percent",
            ]},
            risk_tier="confirm", active=True, idempotent=False,
        ), lambda scope, **args: service.plugin_create_threshold_detector(**args), "plugin"),
        CallableTool(ToolManifest(
            "calibration_run", "Run a deterministic detector calibration corpus.",
            {"type": "object", "properties": {"detector_id": {"type": "string"}, "finding_type": {"type": "string"},
                                                     "backend": {"type": "string", "enum": ["all", "python", "rust"]}}, "required": ["detector_id"]},
            risk_tier="confirm", active=True,
        ), lambda scope, **args: service.plugin_calibration_run(str(args["detector_id"]), args.get("finding_type"), str(args.get("backend") or "all")), "action"),
        CallableTool(ToolManifest(
            "calibration_promote", "Promote a reviewed detector calibration report.",
            {"type": "object", "properties": {"report_path": {"type": "string"}, "reviewer": {"type": "string"},
                                                     "reason": {"type": "string"}}, "required": ["report_path", "reviewer", "reason"]},
            risk_tier="typed", active=True, confirmation_phrase="PROMOTE CALIBRATION",
        ), lambda scope, **args: service.plugin_calibration_promote(str(args["report_path"]), str(args["reviewer"]), str(args["reason"])), "action"),
        CallableTool(ToolManifest(
            "sigma_install", "Install a reviewed remote Sigma rule after its preview hash has been confirmed.",
            {"type": "object", "properties": {"url": {"type": "string"}, "sha256": {"type": "string"}}, "required": ["url", "sha256"]},
            risk_tier="confirm", active=True, allows_external_network=True,
        ), lambda scope, **args: service.sigma_install(str(args["url"]), str(args["sha256"])), "action"),
        CallableTool(ToolManifest("sigma_sync", "Synchronize compatible SigmaHQ rules.", {"type": "object", "properties": {}},
                                  risk_tier="confirm", active=True, allows_external_network=True),
                     lambda scope, **args: service.sigma_sync(), "action"),
        CallableTool(ToolManifest("sigma_rollback", "Restore the previously active Sigma corpus.", {"type": "object", "properties": {}},
                                  risk_tier="confirm", active=True),
                     lambda scope, **args: service.sigma_rollback(), "action"),
        CallableTool(ToolManifest(
            "database_reset", "Delete WatchTower data after a typed destructive confirmation.",
            {"type": "object", "properties": {"confirmation": {"type": "string"}}, "required": ["confirmation"]},
            risk_tier="typed", active=True, idempotent=False, confirmation_phrase="RESET WATCHTOWER",
        ), lambda scope, **args: service.reset_database(str(args["confirmation"])), "action"),
    ])
    tools.append(CaseExportTool(db, Path(getattr(db, "data_dir", ".")) / "cases"))
    return ToolRegistry(tools)


def _scoped_flow_rows(db, scope: ScopedContext) -> List[Dict[str, Any]]:
    kwargs = {"source": scope.source, "interface": scope.interface,
              "capture_session_id": scope.session_id, "limit": min(scope.max_records, 5000)}
    if scope.node_id:
        kwargs["sensor_node_id"] = scope.node_id
    return db.get_flows(**kwargs)


def _session_summary(db, scope: ScopedContext) -> Dict[str, Any]:
    rows = _scoped_flow_rows(db, scope)
    aggregate = db.summarize_flows(
        source=scope.source, interface=scope.interface,
        capture_session_id=scope.session_id, sensor_node_id=scope.node_id,
    ) if hasattr(db, "summarize_flows") else None
    protocols: Dict[str, int] = {}
    for row in rows:
        protocol = str(row.get("protocol") or "OTHER").upper()
        protocols[protocol] = protocols.get(protocol, 0) + 1
    values = aggregate or {
        "flow_count": len(rows), "packet_count": sum(int(row.get("packet_count") or 0) for row in rows),
        "byte_count": sum(int(row.get("byte_count") or 0) for row in rows),
        "protocols": protocols,
        "first_seen": min((row.get("start_time") for row in rows if row.get("start_time") is not None), default=None),
        "last_seen": max((row.get("last_seen") for row in rows if row.get("last_seen") is not None), default=None),
        "partial_flows": sum(1 for row in rows if row.get("partial")),
    }
    values["protocols"] = dict(sorted(values.get("protocols", protocols).items(), key=lambda item: (-item[1], item[0]))[:12])
    values["complete"] = int(values.get("partial_flows") or 0) == 0
    return {"scope": scope.to_dict(), **values, "bounded_rows": len(rows), "rows_limited": len(rows) < int(values.get("flow_count") or 0)}


def _top_conversations(db, scope: ScopedContext, limit: int = 10) -> List[Dict[str, Any]]:
    rows = _scoped_flow_rows(db, scope)
    return sorted(rows, key=lambda row: (-int(row.get("byte_count") or 0), -int(row.get("packet_count") or 0)))[:max(1, min(limit, 50))]
