"""Deterministic capability planning for Rust offline aggregate analysis."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any

AGGREGATE_EXECUTION_MODE = "aggregate-v1"
COMPATIBILITY_EXECUTION_MODE = "compatibility-v1"
RUST_PLAN_SCHEMA_VERSION = 1
AGGREGATE_SOURCE_TYPES = frozenset({"network"})
AGGREGATE_LINK_TYPES = frozenset({"ethernet", "raw-ip"})

_PACKET_VIEWS = frozenset({"none", "fast-v1", "deep-scapy-v1"})
_PACKET_FLOW_VIEWS = frozenset({"none", "scalar-v1"})
_FLOW_INPUTS = frozenset({"none", "full-flow-v1"})
_STREAM_INPUTS = frozenset({"none", "reassembled-stream-v1"})
_CONVERSATION_INPUTS = frozenset({"none", "delta-v2"})
_SELECTOR_OPCODES = frozenset({
    "always",
    "link-class-in",
    "ethertype-in",
    "ip-protocol-in",
    "either-port-in",
    "source-port-in",
    "destination-port-in",
    "tcp-flags",
    "icmp-type-in",
    "payload-minimum-length",
    "payload-prefix-in",
    "payload-contains-any",
    "payload-byte-mask",
    "payload-diversity",
    "frame-window-contains-any",
})


@dataclass(frozen=True)
class SelectorClause:
    opcode: str
    values: tuple[Any, ...] = ()


@dataclass(frozen=True)
class SelectorProgram:
    candidate_mode: str
    clauses: tuple[SelectorClause, ...]


@dataclass(frozen=True)
class OfflineCapability:
    contract: str = AGGREGATE_EXECUTION_MODE
    packet_view: str = "none"
    packet_flow_view: str = "none"
    selector_programs: tuple[SelectorProgram, ...] = ()
    flow_input: str = "none"
    stream_input: str = "none"
    conversation_input: str = "none"


@dataclass(frozen=True)
class CompiledSelectorProgram:
    program_id: int
    candidate_mode: str
    clauses: tuple[SelectorClause, ...]


@dataclass(frozen=True)
class PluginPlanEntry:
    plugin_type: str
    name: str
    detector_id: str
    api_version: int
    contract_version: int
    detector_semantic_version: str
    supported_link_types: tuple[str, ...]
    supported_capture_sources: tuple[str, ...]
    capability: OfflineCapability | None
    capability_state: str
    capability_errors: tuple[str, ...]
    applicable: bool
    selector_program_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class RustAnalysisPlan:
    schema_version: int
    source_type: str
    link_type: str
    execution_mode: str
    semantic_plugin_digest: str
    execution_plan_digest: str
    plugins: tuple[PluginPlanEntry, ...]
    selector_programs: tuple[CompiledSelectorProgram, ...]
    incompatibilities: tuple[str, ...]

    @property
    def plugin_semantic_digest(self) -> str:
        return self.semantic_plugin_digest


class AggregateCapabilityError(ValueError):
    def __init__(self, incompatibilities: Iterable[str]):
        self.incompatibilities = tuple(incompatibilities)
        detail = "; ".join(self.incompatibilities)
        super().__init__(f"strict aggregate-v1 request is incompatible: {detail}")


class RustPlanIntegrityError(ValueError):
    pass


class RustPlanDriftError(ValueError):
    pass


def _clause(opcode: str, *values: Any) -> SelectorClause:
    return SelectorClause(opcode=opcode, values=tuple(values))


def _program(candidate_mode: str, *clauses: SelectorClause) -> SelectorProgram:
    return SelectorProgram(candidate_mode=candidate_mode, clauses=tuple(clauses))


def _capability(
    packet_view: str = "none",
    *programs: SelectorProgram,
    packet_flow_view: str = "none",
    flow_input: str = "none",
    stream_input: str = "none",
    conversation_input: str = "none",
) -> OfflineCapability:
    return OfflineCapability(
        packet_view=packet_view,
        packet_flow_view=packet_flow_view,
        selector_programs=tuple(programs),
        flow_input=flow_input,
        stream_input=stream_input,
        conversation_input=conversation_input,
    )


def _ports(mode: str, *ports: int) -> SelectorProgram:
    return _program(mode, _clause("either-port-in", *ports))


def _prefixes(mode: str, *prefixes: bytes) -> SelectorProgram:
    return _program(mode, _clause("payload-prefix-in", *prefixes))


_ARP = _program("fast-v1", _clause("ethertype-in", 0x0806))
_NDP = _program("fast-v1", _clause("ip-protocol-in", 58))
_ICMP = _program("fast-v1", _clause("ip-protocol-in", 1, 58))
_HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"HTTP/",
)
_AUTH_MARKERS = (
    b"password",
    b"passwd",
    b"authorization: basic",
    b"user ",
    b" pass ",
    b"authentication failed",
    b"login failed",
    b"invalid password",
    b"535 authentication",
    b"authentication successful",
    b"login successful",
    b"230 login successful",
    b"SSH-",
    b"RFB ",
    b"\x03\x00",
)


# This registry is intentionally separate from detector source modules. These
# declarations describe transport requirements and do not alter detector
# semantics or calibration dependencies.
_BUILTIN_CAPABILITIES: Mapping[str, OfflineCapability] = {
    # Parsers requiring a full Scapy graph.
    "core.forensics.plugins.parsers.bluetooth_hci_parser.BluetoothHCIParser":
        _capability("deep-scapy-v1", _program("deep-scapy-v1", _clause("always"))),
    "core.forensics.plugins.parsers.dhcp_parser.DHCPParser":
        _capability("deep-scapy-v1", _ports("deep-scapy-v1", 67, 68)),
    "core.forensics.plugins.parsers.discovery_parser.DiscoveryParser":
        _capability("deep-scapy-v1", _ports("deep-scapy-v1", 53, 137, 1900, 5353)),
    "core.forensics.plugins.parsers.dns_parser.DNSParser":
        _capability("deep-scapy-v1", _ports("deep-scapy-v1", 53)),

    # Fast packet parsers.
    "core.forensics.plugins.parsers.enterprise_protocol_parser.SSHParser":
        _capability("fast-v1", _prefixes("fast-v1", b"SSH-")),
    "core.forensics.plugins.parsers.enterprise_protocol_parser.LDAPParser":
        _capability("fast-v1", _ports("fast-v1", 389, 636, 3268, 3269)),
    "core.forensics.plugins.parsers.enterprise_protocol_parser.RDPParser":
        _capability("fast-v1", _ports("fast-v1", 3389)),
    "core.forensics.plugins.parsers.enterprise_protocol_parser.MailProtocolParser":
        _capability("fast-v1", _ports("fast-v1", 25, 110, 143, 465, 587, 993, 995)),
    "core.forensics.plugins.parsers.enterprise_protocol_parser.SNMPParser":
        _capability("fast-v1", _ports("fast-v1", 161, 162)),
    "core.forensics.plugins.parsers.enterprise_protocol_parser.NTPParser":
        _capability(),
    "core.forensics.plugins.parsers.ftp_parser.FTPParser":
        _capability("fast-v1", _ports("fast-v1", 21)),
    "core.forensics.plugins.parsers.fullname_parser.FullNameParser":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause("payload-contains-any", b"\x06\x03\x55\x04\x03", b"\x00 \x00"),
            ),
        ),
    "core.forensics.plugins.parsers.http_parser.HTTPParser":
        _capability("fast-v1", _prefixes("fast-v1", *_HTTP_PREFIXES)),
    "core.forensics.plugins.parsers.infrastructure_parser.InfrastructureParser":
        _capability(),
    "core.forensics.plugins.parsers.iot_ot_parser.MQTTParser":
        _capability("fast-v1", _ports("fast-v1", 1883, 8883)),
    "core.forensics.plugins.parsers.iot_ot_parser.CoAPParser":
        _capability("fast-v1", _ports("fast-v1", 5683, 5684)),
    "core.forensics.plugins.parsers.iot_ot_parser.ModbusParser":
        _capability("fast-v1", _ports("fast-v1", 502)),
    "core.forensics.plugins.parsers.kerberos_parser.KerberosParser":
        _capability("fast-v1", _ports("fast-v1", 88)),
    "core.forensics.plugins.parsers.nbns_parser.NBNSParser":
        _capability("fast-v1", _ports("fast-v1", 137)),
    "core.forensics.plugins.parsers.network_foundation_parser.ARPNDPParser":
        _capability("fast-v1", _ARP, _NDP),
    "core.forensics.plugins.parsers.network_foundation_parser.ICMPMetadataParser":
        _capability("fast-v1", _ICMP),
    "core.forensics.plugins.parsers.network_foundation_parser.DHCPv6Parser":
        _capability("fast-v1", _ports("fast-v1", 546, 547)),
    "core.forensics.plugins.parsers.network_foundation_parser.LinkDiscoveryParser":
        _capability(
            "fast-v1",
            _program("fast-v1", _clause("ethertype-in", 0x88CC)),
            _program(
                "fast-v1",
                _clause(
                    "frame-window-contains-any",
                    0,
                    32,
                    b"\x01\x00\x0c\xcc\xcc\xcc",
                ),
            ),
        ),
    "core.forensics.plugins.parsers.network_foundation_parser.QUICMetadataParser":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 17),
                _clause("either-port-in", 443),
                _clause("payload-byte-mask", 0, 0x80, 0x80),
            ),
        ),
    "core.forensics.plugins.parsers.ntlm_parser.NTLMParser":
        _capability(
            "fast-v1",
            _program("fast-v1", _clause("payload-contains-any", b"NTLMSSP")),
        ),
    "core.forensics.plugins.parsers.smb_parser.SMBParser":
        _capability("fast-v1", _ports("fast-v1", 445)),
    "core.forensics.plugins.parsers.tls_parser.TLSParser":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause("either-port-in", 443),
                _clause("payload-minimum-length", 6),
                _clause("payload-prefix-in", b"\x16\x03"),
                _clause("payload-byte-mask", 5, 0xFF, 0x01),
            ),
        ),

    # Packet, flow, stream, and conversation detectors.
    "core.forensics.plugins.detectors.beaconing_detector.BeaconingDetector":
        _capability(flow_input="full-flow-v1"),
    "core.forensics.plugins.detectors.coverage_detector.LANTrustDetector":
        _capability("fast-v1", _ARP, _NDP, _ports("fast-v1", 67, 68)),
    "core.forensics.plugins.detectors.coverage_detector.ReconLateralDetector":
        _capability(
            "fast-v1",
            _program("fast-v1", _clause("ip-protocol-in", 6)),
            packet_flow_view="scalar-v1",
            flow_input="full-flow-v1",
        ),
    "core.forensics.plugins.detectors.coverage_detector.ApplicationAbuseDetector":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 1, 58),
                _clause("payload-diversity", 256, 16),
            ),
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 6),
                _clause("payload-contains-any", *_AUTH_MARKERS),
            ),
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 6),
                _clause("either-port-in", 443),
                _clause("tcp-flags", 0x02, 0x10),
            ),
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 6),
                _clause("either-port-in", 443),
                _clause("payload-minimum-length", 1),
            ),
            packet_flow_view="scalar-v1",
            stream_input="reassembled-stream-v1",
        ),
    "core.forensics.plugins.detectors.coverage_detector.IoTOTSafetyDetector":
        _capability("fast-v1", _ports("fast-v1", 502, 1883)),
    "core.forensics.plugins.detectors.dns_detector.DNSDetector":
        _capability("deep-scapy-v1", _ports("deep-scapy-v1", 53)),
    "core.forensics.plugins.detectors.exfiltration_detector.ExfiltrationDetector":
        _capability(flow_input="full-flow-v1"),
    "core.forensics.plugins.detectors.file_detector.FileTransferDetector":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause(
                    "payload-contains-any",
                    b"MZ",
                    b"This program cannot be run in DOS mode",
                ),
            ),
            stream_input="reassembled-stream-v1",
        ),
    "core.forensics.plugins.detectors.ftp_detector.FTPDetector":
        _capability(
            "fast-v1",
            _program(
                "fast-v1",
                _clause("ip-protocol-in", 6),
                _clause("payload-contains-any", b"USER ", b"PASS "),
            ),
            stream_input="reassembled-stream-v1",
        ),
    "core.forensics.plugins.detectors.os_detector.OSDetector":
        _capability(),
    "core.forensics.plugins.detectors.stateful_behavior_detector.UnifiedStatefulBehaviorDetector":
        _capability(conversation_input="delta-v2"),
}


def _plugin_key(plugin: Any) -> str:
    plugin_type = type(plugin)
    return f"{plugin_type.__module__}.{plugin_type.__qualname__}"


def offline_capability_for(plugin: Any) -> OfflineCapability | None:
    declaration = getattr(plugin, "offline_capability", None)
    if declaration is not None:
        return declaration
    return _BUILTIN_CAPABILITIES.get(_plugin_key(plugin))


def _canonical_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, tuple):
        return [_canonical_value(item) for item in value]
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise TypeError(f"unsupported canonical plan value: {type(value).__name__}")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _canonical_clause(clause: SelectorClause) -> dict[str, Any]:
    return {"opcode": clause.opcode, "values": list(clause.values)}


def _sorted_unique(values: tuple[Any, ...]) -> tuple[Any, ...]:
    by_json = {_canonical_json(value): value for value in values}
    return tuple(by_json[key] for key in sorted(by_json))


def _normalized_clause(clause: SelectorClause) -> SelectorClause:
    set_opcodes = {
        "link-class-in",
        "ethertype-in",
        "ip-protocol-in",
        "either-port-in",
        "source-port-in",
        "destination-port-in",
        "icmp-type-in",
        "payload-prefix-in",
        "payload-contains-any",
    }
    if clause.opcode in set_opcodes:
        return replace(clause, values=_sorted_unique(clause.values))
    if clause.opcode == "frame-window-contains-any" and len(clause.values) >= 2:
        return replace(
            clause,
            values=(*clause.values[:2], *_sorted_unique(clause.values[2:])),
        )
    return clause


def _normalized_program(program: SelectorProgram) -> SelectorProgram:
    clauses = tuple(
        sorted(
            (_normalized_clause(clause) for clause in program.clauses),
            key=lambda clause: _canonical_json(_canonical_clause(clause)),
        )
    )
    return SelectorProgram(candidate_mode=program.candidate_mode, clauses=clauses)


def _canonical_program(program: SelectorProgram | CompiledSelectorProgram) -> dict[str, Any]:
    result = {
        "candidate_mode": program.candidate_mode,
        "clauses": [
            _canonical_clause(clause)
            for clause in _normalized_program(
                SelectorProgram(program.candidate_mode, program.clauses)
            ).clauses
        ],
    }
    if isinstance(program, CompiledSelectorProgram):
        result["program_id"] = program.program_id
    return result


def _normalized_capability(capability: OfflineCapability) -> OfflineCapability:
    programs_by_json = {
        _canonical_json(_canonical_program(_normalized_program(program))):
            _normalized_program(program)
        for program in capability.selector_programs
    }
    return replace(
        capability,
        selector_programs=tuple(
            programs_by_json[key] for key in sorted(programs_by_json)
        ),
    )


def _canonical_capability(
    capability: OfflineCapability | None,
) -> dict[str, Any] | None:
    if capability is None:
        return None
    capability = _normalized_capability(capability)
    return {
        "contract": capability.contract,
        "packet_view": capability.packet_view,
        "packet_flow_view": capability.packet_flow_view,
        "selector_programs": [
            _canonical_program(program)
            for program in capability.selector_programs
        ],
        "flow_input": capability.flow_input,
        "stream_input": capability.stream_input,
        "conversation_input": capability.conversation_input,
    }


def _validate_int_set(
    opcode: str,
    values: tuple[Any, ...],
    *,
    maximum: int,
    limit: int,
) -> list[str]:
    if not values:
        return [f"{opcode} requires at least one value"]
    if len(values) > limit:
        return [f"{opcode} exceeds {limit} values"]
    if any(not isinstance(value, int) or not 0 <= value <= maximum for value in values):
        return [f"{opcode} values must be integers from 0 to {maximum}"]
    return []


def _validate_literals(opcode: str, values: tuple[Any, ...]) -> list[str]:
    if not values:
        return [f"{opcode} requires at least one literal"]
    if len(values) > 32:
        return [f"{opcode} exceeds 32 literals"]
    if any(not isinstance(value, bytes) or not value for value in values):
        return [f"{opcode} literals must be non-empty bytes"]
    if any(len(value) > 256 for value in values):
        return [f"{opcode} literal exceeds 256 bytes"]
    return []


def _validate_clause(clause: SelectorClause) -> list[str]:
    if not isinstance(clause, SelectorClause):
        return ["selector clause must be SelectorClause"]
    opcode = clause.opcode
    values = clause.values
    if opcode not in _SELECTOR_OPCODES:
        return [f"unknown selector opcode: {opcode}"]
    if opcode == "always":
        return [] if not values else ["always selector does not accept values"]
    if opcode == "link-class-in":
        if not values or any(value not in AGGREGATE_LINK_TYPES for value in values):
            return ["link-class-in values must be ethernet or raw-ip"]
        return []
    if opcode == "ethertype-in":
        return _validate_int_set(opcode, values, maximum=0xFFFF, limit=255)
    if opcode in {"ip-protocol-in", "icmp-type-in"}:
        return _validate_int_set(opcode, values, maximum=0xFF, limit=255)
    if opcode in {"either-port-in", "source-port-in", "destination-port-in"}:
        return _validate_int_set(opcode, values, maximum=0xFFFF, limit=512)
    if opcode == "tcp-flags":
        if (
            len(values) != 2
            or any(not isinstance(value, int) or not 0 <= value <= 0xFFFF for value in values)
        ):
            return ["tcp-flags requires required and forbidden u16 values"]
        return []
    if opcode == "payload-minimum-length":
        if len(values) != 1 or not isinstance(values[0], int) or not 0 <= values[0] <= 0xFFFFFFFF:
            return ["payload-minimum-length requires one u32 value"]
        return []
    if opcode in {"payload-prefix-in", "payload-contains-any"}:
        return _validate_literals(opcode, values)
    if opcode == "payload-byte-mask":
        if (
            len(values) != 3
            or not isinstance(values[0], int)
            or not 0 <= values[0] <= 0xFFFF
            or any(not isinstance(value, int) or not 0 <= value <= 0xFF for value in values[1:])
        ):
            return ["payload-byte-mask requires u16 offset, u8 mask, and u8 expected"]
        return []
    if opcode == "payload-diversity":
        if (
            len(values) != 2
            or any(not isinstance(value, int) or not 0 <= value <= 0xFFFF for value in values)
            or values[1] > values[0]
        ):
            return ["payload-diversity requires sample and minimum_distinct u16 values"]
        return []
    if opcode == "frame-window-contains-any":
        if (
            len(values) < 3
            or any(not isinstance(value, int) for value in values[:2])
            or not 0 <= values[0] <= values[1] <= 0xFFFF
        ):
            return ["frame-window-contains-any requires a valid u16 start/end window"]
        return _validate_literals(opcode, values[2:])
    return []


def validate_offline_capability(capability: OfflineCapability) -> tuple[str, ...]:
    if not isinstance(capability, OfflineCapability):
        return ("offline capability must be an OfflineCapability declaration",)
    errors: list[str] = []
    if capability.contract != AGGREGATE_EXECUTION_MODE:
        errors.append(f"unsupported offline capability contract: {capability.contract}")
    if capability.packet_view not in _PACKET_VIEWS:
        errors.append(f"unsupported packet_view: {capability.packet_view}")
    if capability.packet_flow_view not in _PACKET_FLOW_VIEWS:
        errors.append(f"unsupported packet_flow_view: {capability.packet_flow_view}")
    if capability.flow_input not in _FLOW_INPUTS:
        errors.append(f"unsupported flow_input: {capability.flow_input}")
    if capability.stream_input not in _STREAM_INPUTS:
        errors.append(f"unsupported stream_input: {capability.stream_input}")
    if capability.conversation_input not in _CONVERSATION_INPUTS:
        errors.append(
            f"unsupported conversation_input: {capability.conversation_input}"
        )
    if capability.packet_view == "none" and capability.selector_programs:
        errors.append("packet_view none cannot declare selector programs")
    if capability.packet_view != "none" and not capability.selector_programs:
        errors.append(f"packet_view {capability.packet_view} requires a selector program")
    if capability.packet_flow_view != "none" and capability.packet_view == "none":
        errors.append("packet_flow_view requires a packet_view")
    if len(capability.selector_programs) > 64:
        errors.append("offline capability exceeds 64 selector programs")

    literal_bytes = 0
    for index, program in enumerate(capability.selector_programs):
        if not isinstance(program, SelectorProgram):
            errors.append(f"selector program {index} must be SelectorProgram")
            continue
        if program.candidate_mode not in {"fast-v1", "deep-scapy-v1"}:
            errors.append(
                f"selector program {index} has unsupported candidate_mode: "
                f"{program.candidate_mode}"
            )
        if program.candidate_mode != capability.packet_view:
            errors.append(
                f"selector program {index} candidate_mode does not match packet_view"
            )
        if not 1 <= len(program.clauses) <= 16:
            errors.append(f"selector program {index} must contain 1..16 clauses")
        for clause in program.clauses:
            errors.extend(
                f"selector program {index}: {error}"
                for error in _validate_clause(clause)
            )
            if isinstance(clause, SelectorClause):
                literal_bytes += sum(
                    len(value) for value in clause.values if isinstance(value, bytes)
                )
    if literal_bytes > 64 * 1024:
        errors.append("offline capability exceeds 64 KiB of selector literals")
    return tuple(errors)


def _plugin_metadata(
    plugin: Any,
    plugin_type: str,
) -> tuple[str, int, str, tuple[str, ...], tuple[str, ...]]:
    manifest = getattr(plugin, "manifest", None)
    detector_id = str(getattr(manifest, "detector_id", "") or "")
    contract_version = int(getattr(manifest, "contract_version", 1) or 1)
    semantic_version = str(getattr(manifest, "version", "") or "")
    links = getattr(
        manifest,
        "supported_link_types",
        getattr(plugin, "supported_link_types", ()),
    )
    sources = getattr(
        manifest,
        "supported_capture_sources",
        getattr(plugin, "supported_capture_sources", ()),
    )
    return (
        detector_id,
        contract_version,
        semantic_version,
        tuple(sorted({str(value) for value in links})),
        tuple(sorted({str(value) for value in sources})),
    )


def _collect_plugins(
    parsers: Sequence[Any],
    detectors: Sequence[Any],
    *,
    source_type: str,
    link_type: str,
) -> tuple[list[PluginPlanEntry], list[str]]:
    entries: list[PluginPlanEntry] = []
    incompatibilities: list[str] = []
    for plugin_type, plugins in (("parser", parsers), ("detector", detectors)):
        for plugin in plugins:
            if not bool(getattr(plugin, "enabled", True)):
                continue
            name = str(getattr(plugin, "name", type(plugin).__name__))
            detector_id, contract_version, semantic_version, links, sources = (
                _plugin_metadata(plugin, plugin_type)
            )
            declaration = offline_capability_for(plugin)
            capability_errors = (
                validate_offline_capability(declaration)
                if declaration is not None
                else ()
            )
            if declaration is None:
                capability = None
                capability_state = "missing"
            elif capability_errors:
                capability = None
                capability_state = "invalid"
            else:
                capability = _normalized_capability(declaration)
                capability_state = "declared"
            applicable = source_type in sources and link_type in links
            entry = PluginPlanEntry(
                plugin_type=plugin_type,
                name=name,
                detector_id=detector_id,
                api_version=int(getattr(plugin, "api_version", 1) or 1),
                contract_version=contract_version,
                detector_semantic_version=semantic_version,
                supported_link_types=links,
                supported_capture_sources=sources,
                capability=capability,
                capability_state=capability_state,
                capability_errors=capability_errors,
                applicable=applicable,
            )
            entries.append(entry)
            if not applicable:
                continue
            if declaration is None:
                incompatibilities.append(
                    f"{plugin_type} {name}: missing aggregate-v1 offline "
                    "capability declaration"
                )
                continue
            incompatibilities.extend(
                f"{plugin_type} {name}: {error}" for error in capability_errors
            )

    entries.sort(
        key=lambda entry: (
            entry.plugin_type,
            entry.detector_id,
            entry.name,
            entry.api_version,
        )
    )
    return entries, sorted(set(incompatibilities))


def _semantic_entry(entry: PluginPlanEntry) -> dict[str, Any]:
    return {
        "plugin_type": entry.plugin_type,
        "detector_id": entry.detector_id,
        "name": entry.name,
        "api_version": entry.api_version,
        "contract_version": entry.contract_version,
        "detector_semantic_version": entry.detector_semantic_version,
        "supported_link_types": list(entry.supported_link_types),
        "supported_capture_sources": list(entry.supported_capture_sources),
        "capability_state": entry.capability_state,
        "capability_errors": list(entry.capability_errors),
        "capability": _canonical_capability(entry.capability),
    }


def _semantic_digest(entries: Sequence[PluginPlanEntry]) -> str:
    payload = [_semantic_entry(entry) for entry in entries]
    return sha256(_canonical_json(payload).encode("ascii")).hexdigest()


def _compile_selectors(
    entries: Sequence[PluginPlanEntry],
) -> tuple[tuple[PluginPlanEntry, ...], tuple[CompiledSelectorProgram, ...], list[str]]:
    programs_by_json: dict[str, SelectorProgram] = {}
    for entry in entries:
        if (
            not entry.applicable
            or not isinstance(entry.capability, OfflineCapability)
            or validate_offline_capability(entry.capability)
        ):
            continue
        for program in entry.capability.selector_programs:
            normalized = _normalized_program(program)
            programs_by_json[_canonical_json(_canonical_program(normalized))] = normalized

    errors = []
    if len(programs_by_json) > 64:
        errors.append(
            f"aggregate selector plan requires {len(programs_by_json)} programs; maximum is 64"
        )
        programs_by_json = {}
    program_ids = {
        canonical: index for index, canonical in enumerate(sorted(programs_by_json))
    }
    compiled = tuple(
        CompiledSelectorProgram(
            program_id=program_ids[canonical],
            candidate_mode=programs_by_json[canonical].candidate_mode,
            clauses=programs_by_json[canonical].clauses,
        )
        for canonical in sorted(programs_by_json)
    )
    planned_entries = []
    for entry in entries:
        ids = ()
        if (
            entry.applicable
            and isinstance(entry.capability, OfflineCapability)
            and not validate_offline_capability(entry.capability)
            and program_ids
        ):
            ids = tuple(
                sorted({
                    program_ids[_canonical_json(_canonical_program(program))]
                    for program in entry.capability.selector_programs
                })
            )
        planned_entries.append(replace(entry, selector_program_ids=ids))
    return tuple(planned_entries), compiled, errors


def _execution_payload(plan: RustAnalysisPlan) -> dict[str, Any]:
    return {
        "schema_version": plan.schema_version,
        "source_type": plan.source_type,
        "link_type": plan.link_type,
        "execution_mode": plan.execution_mode,
        "semantic_plugin_digest": plan.semantic_plugin_digest,
        "plugins": [
            {
                "plugin_type": entry.plugin_type,
                "detector_id": entry.detector_id,
                "name": entry.name,
                "applicable": entry.applicable,
                "capability_state": entry.capability_state,
                "selector_program_ids": list(entry.selector_program_ids),
            }
            for entry in plan.plugins
        ],
        "selector_programs": [
            _canonical_program(program) for program in plan.selector_programs
        ],
        "incompatibilities": list(plan.incompatibilities),
    }


def _execution_digest(plan: RustAnalysisPlan) -> str:
    return sha256(
        _canonical_json(_execution_payload(plan)).encode("ascii")
    ).hexdigest()


def build_rust_analysis_plan(
    parsers: Sequence[Any],
    detectors: Sequence[Any],
    *,
    source_type: str = "network",
    link_type: str = "ethernet",
    strict_aggregate: bool = False,
    requested_mode: str | None = None,
) -> RustAnalysisPlan:
    if requested_mode not in {
        None,
        "auto",
        AGGREGATE_EXECUTION_MODE,
        COMPATIBILITY_EXECUTION_MODE,
    }:
        raise ValueError(
            "requested_mode must be auto, aggregate-v1, or compatibility-v1"
        )
    if strict_aggregate and requested_mode == COMPATIBILITY_EXECUTION_MODE:
        raise ValueError(
            "strict_aggregate cannot request compatibility-v1 execution"
        )

    source_type = str(source_type)
    link_type = str(link_type)
    entries, incompatibilities = _collect_plugins(
        parsers,
        detectors,
        source_type=source_type,
        link_type=link_type,
    )
    if source_type not in AGGREGATE_SOURCE_TYPES:
        incompatibilities.append(
            f"source_type {source_type} is not supported by aggregate-v1"
        )
    if link_type not in AGGREGATE_LINK_TYPES:
        incompatibilities.append(
            f"link_type {link_type} is not supported by aggregate-v1"
        )

    planned_entries, selector_programs, selector_errors = _compile_selectors(entries)
    incompatibilities = sorted({*incompatibilities, *selector_errors})
    semantic_digest = _semantic_digest(planned_entries)
    aggregate_required = strict_aggregate or requested_mode == AGGREGATE_EXECUTION_MODE
    if aggregate_required and incompatibilities:
        raise AggregateCapabilityError(incompatibilities)
    if requested_mode == COMPATIBILITY_EXECUTION_MODE:
        execution_mode = COMPATIBILITY_EXECUTION_MODE
    else:
        execution_mode = (
            AGGREGATE_EXECUTION_MODE
            if not incompatibilities
            else COMPATIBILITY_EXECUTION_MODE
        )

    plan = RustAnalysisPlan(
        schema_version=RUST_PLAN_SCHEMA_VERSION,
        source_type=source_type,
        link_type=link_type,
        execution_mode=execution_mode,
        semantic_plugin_digest=semantic_digest,
        execution_plan_digest="",
        plugins=planned_entries,
        selector_programs=selector_programs,
        incompatibilities=tuple(incompatibilities),
    )
    return replace(plan, execution_plan_digest=_execution_digest(plan))


def verify_rust_analysis_plan(
    queued_plan: RustAnalysisPlan,
    parsers: Sequence[Any],
    detectors: Sequence[Any],
) -> RustAnalysisPlan:
    if _semantic_digest(queued_plan.plugins) != queued_plan.semantic_plugin_digest:
        raise RustPlanIntegrityError("semantic plugin digest mismatch")
    if _execution_digest(queued_plan) != queued_plan.execution_plan_digest:
        raise RustPlanIntegrityError("execution-plan digest mismatch")

    current = build_rust_analysis_plan(
        parsers,
        detectors,
        source_type=queued_plan.source_type,
        link_type=queued_plan.link_type,
        requested_mode=queued_plan.execution_mode,
    )
    if (
        current.semantic_plugin_digest != queued_plan.semantic_plugin_digest
        or current.execution_plan_digest != queued_plan.execution_plan_digest
    ):
        raise RustPlanDriftError(
            "queued plugin inventory changed before replay "
            f"(queued semantic {queued_plan.semantic_plugin_digest}, "
            f"current semantic {current.semantic_plugin_digest})"
        )
    return queued_plan
