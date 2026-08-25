from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Dict, List, Optional
import uuid


@dataclass(frozen=True)
class EvidenceCitation:
    reference: str
    source: str
    summary: str
    timestamp: Optional[float] = None
    kind: str = "watchtower"
    url: Optional[str] = None
    retrieved_at: Optional[float] = None
    content_hash: Optional[str] = None
    scope: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceFact:
    """A small, typed claim that the analyst may cite.

    Fact IDs are content addressed.  A provider can only make a concrete
    claim from facts returned by WatchTower or a research adapter; free-form
    model prose is never treated as evidence by itself.
    """

    fact_id: str
    subject: str
    predicate: str
    value: Any
    confidence: float = 1.0
    completeness: str = "complete"
    freshness: Optional[float] = None
    scope: Dict[str, Any] = field(default_factory=dict)
    citations: List[EvidenceCitation] = field(default_factory=list)

    @classmethod
    def create(cls, subject: str, predicate: str, value: Any, *, confidence: float = 1.0,
               completeness: str = "complete", freshness: Optional[float] = None,
               scope: Optional[Dict[str, Any]] = None,
               citations: Optional[List[EvidenceCitation]] = None) -> "EvidenceFact":
        normalized = {
            "subject": str(subject), "predicate": str(predicate),
            "value": value, "scope": scope or {},
        }
        digest = sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        return cls(
            fact_id=f"fact:{digest[:24]}", subject=str(subject), predicate=str(predicate), value=value,
            confidence=max(0.0, min(1.0, float(confidence))), completeness=str(completeness or "complete"),
            freshness=freshness, scope=dict(scope or {}), citations=list(citations or []),
        )


@dataclass(frozen=True)
class ScopedContext:
    source: Optional[str] = None
    interface: Optional[str] = None
    session_id: Optional[str] = None
    node_id: Optional[str] = None
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    case_id: Optional[str] = None
    target_ips: tuple = ()
    max_records: int = 500

    def has_scope(self) -> bool:
        return bool(self.source or self.interface or self.session_id or self.node_id or self.case_id or self.target_ips)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "interface": self.interface,
            "session_id": self.session_id,
            "node_id": self.node_id,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "case_id": self.case_id,
            "target_ips": list(self.target_ips),
            "max_records": self.max_records,
        }

    @classmethod
    def from_dict(cls, value: Optional[Dict[str, Any]]) -> "ScopedContext":
        value = value or {}
        return cls(
            source=value.get("source"),
            interface=value.get("interface"),
            session_id=value.get("session_id"),
            node_id=value.get("node_id"),
            time_start=float(value["time_start"]) if value.get("time_start") is not None else None,
            time_end=float(value["time_end"]) if value.get("time_end") is not None else None,
            case_id=value.get("case_id"),
            target_ips=tuple(str(item) for item in value.get("target_ips", ()) if item),
            max_records=max(1, min(int(value.get("max_records", 500)), 500)),
        )


@dataclass(frozen=True)
class RunPolicy:
    allowed_tools: tuple
    max_tool_calls: int = 20
    read_only: bool = True
    allow_external_network: bool = False
    allow_active_actions: bool = False
    allow_sensitive_external: bool = False
    mode: str = "investigate"


@dataclass(frozen=True)
class ToolManifest:
    """Static contract for one agent tool. The model never supplies this data."""

    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=lambda: {
        "type": "object",
        "properties": {
            "tool": {"type": "string"},
            "data": {},
            "citations": {"type": "array"},
            "truncated": {"type": "boolean"},
            "summary": {"type": "string"},
            "redacted": {"type": "boolean"},
            "facts": {"type": "array"},
        },
    })
    risk_tier: str = "read"
    requires_scope: bool = False
    allows_external_network: bool = False
    active: bool = False
    idempotent: bool = True
    confirmation_phrase: Optional[str] = None


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    call_id: Optional[str] = None


@dataclass
class ToolResult:
    tool: str
    data: Any
    citations: List[EvidenceCitation] = field(default_factory=list)
    truncated: bool = False
    summary: str = ""
    redacted: bool = True
    facts: List[EvidenceFact] = field(default_factory=list)


@dataclass
class ProviderTurn:
    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    citations: List[EvidenceCitation] = field(default_factory=list)
    text_tool_calls: bool = False


@dataclass
class AIRunRecord:
    scope: ScopedContext
    policy: RunPolicy
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "RUNNING"
    turns: List[ProviderTurn] = field(default_factory=list)
    tool_results: List[ToolResult] = field(default_factory=list)
    final_text: str = ""
    conversation_id: Optional[str] = None
    provider: str = ""


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    prompt: str
    expected_citations: tuple = ()
    expected_tools: tuple = ()


@dataclass(frozen=True)
class EvaluationResult:
    case: str
    passed: bool
    citation_recall: float
    tools_used: tuple
    errors: tuple = ()
