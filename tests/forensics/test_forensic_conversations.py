import os
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
import scapy.all as scapy

from core.api.pcap_jobs import PcapJobManager
from core.api.service import WatchtowerApiService
from core.forensics.engine import ForensicsEngine
from core.forensics.tshark_adapter import TSharkDissector, TSharkResult
from core.packet_engine.conversations import (
    ConversationDeltaV2,
    ConversationKey,
    ConversationTracker,
)
from core.packet_engine.schemas import PacketEvent
from core.storage.database import WatchtowerDB
from core.storage.models import (
    ForensicAnalysisRevision,
    ForensicEvidenceComponent,
)


def _create_revision(
    db: WatchtowerDB,
    *,
    case_id: str,
    analysis_id: str,
    digest: str = "ab" * 32,
) -> None:
    db.save_forensic_case_revision(
        {
            "id": case_id,
            "analysis_id": analysis_id,
            "sha256": digest,
            "state": "running",
        },
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": analysis_id.removeprefix("analysis-")[:64],
            "backend": "python",
            "state": "running",
        },
    )


def _conversation(
    *,
    session_id: str = "session-1",
    generation: int = 3,
    packets: int = 3,
    application=None,
) -> ConversationDeltaV2:
    key = ConversationKey(
        sensor_node_id="node-a",
        source="pcap:job:capture.pcap",
        session_id=session_id,
        interface="offline",
        protocol="TCP",
        endpoint_a=("10.0.0.2", 49152),
        endpoint_b=("203.0.113.8", 443),
    )
    return ConversationDeltaV2(
        contract_version=2,
        key=key,
        generation=generation,
        event_time=12.0,
        first_seen=10.0,
        initiator=("10.0.0.2", 49152),
        responder=("203.0.113.8", 443),
        direction="final",
        packet_delta=0,
        byte_delta=0,
        syn_delta=0,
        syn_ack_delta=0,
        rst_delta=0,
        to_responder_packets=packets,
        to_responder_bytes=packets * 100,
        to_initiator_packets=1,
        to_initiator_bytes=80,
        syn_count=1,
        syn_ack_count=1,
        rst_count=0,
        established=True,
        application=application or {"server_name": "example.test"},
        backend="python",
        source_type="network",
    )


def test_native_conversations_are_idempotent_and_revision_scoped(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "ab" * 32
    analysis_a = "analysis-" + "11" * 32
    analysis_b = "analysis-" + "22" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_a)
    _create_revision(db, case_id=case_id, analysis_id=analysis_b)
    delta = _conversation()

    try:
        first = db.save_forensic_conversations(
            case_id, analysis_a, [delta], completeness="complete"
        )
        repeated = db.save_forensic_conversations(
            case_id, analysis_a, [delta], completeness="complete"
        )
        second_revision = db.save_forensic_conversations(
            case_id, analysis_b, [delta], completeness="complete"
        )

        assert first == repeated
        assert first["component"] == "native_conversations"
        assert first["state"] == "complete"
        assert first["sha256"] == repeated["sha256"]
        assert first["record_count"] == second_revision["record_count"] == 1
        assert db.get_forensic_conversations(analysis_a)["items"][0]["analysis_id"] == analysis_a
        assert db.get_forensic_conversations(analysis_b)["items"][0]["analysis_id"] == analysis_b
    finally:
        db.close()


def test_stale_generation_cannot_promote_partial_native_component(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "bc" * 32
    analysis_id = "analysis-" + "12" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="bc" * 32)

    try:
        partial = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [_conversation(generation=5, packets=5)],
            completeness="partial",
        )
        stale = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [_conversation(generation=4, packets=4)],
            completeness="complete",
        )

        assert partial["state"] == "partial"
        assert stale == partial
        stored = db.get_forensic_conversations(analysis_id)["items"]
        assert stored[0]["generation"] == 5
        assert stored[0]["completeness"] == "partial"
    finally:
        db.close()


def test_mixed_stale_partial_and_fresh_complete_rows_keep_component_partial(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "bd" * 32
    analysis_id = "analysis-" + "14" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="bd" * 32)

    try:
        db.save_forensic_conversations(
            case_id,
            analysis_id,
            [_conversation(session_id="session-stale", generation=5, packets=5)],
            completeness="partial",
        )
        mixed = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [
                _conversation(
                    session_id="session-stale", generation=4, packets=4
                ),
                _conversation(
                    session_id="session-fresh", generation=1, packets=1
                ),
            ],
            completeness="complete",
        )
        stored = {
            item["session_id"]: item
            for item in db.get_forensic_conversations(analysis_id)["items"]
        }

        assert mixed["state"] == "partial"
        assert stored["session-stale"]["generation"] == 5
        assert stored["session-stale"]["completeness"] == "partial"
        assert stored["session-fresh"]["generation"] == 1
        assert stored["session-fresh"]["completeness"] == "complete"
    finally:
        db.close()


def test_native_conversations_keep_same_five_tuple_in_separate_sessions(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "cd" * 32
    analysis_id = "analysis-" + "33" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="cd" * 32)

    try:
        manifest = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [_conversation(session_id="session-a"), _conversation(session_id="session-b")],
            completeness="complete",
        )
        page = db.get_forensic_conversations(analysis_id)

        assert manifest["record_count"] == 2
        assert {item["session_id"] for item in page["items"]} == {
            "session-a",
            "session-b",
        }
        assert all(item["sensor_node_id"] == "node-a" for item in page["items"])
        assert all(item["interface"] == "offline" for item in page["items"])
    finally:
        db.close()


def test_native_conversation_upserts_are_generation_aware(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "ef" * 32
    analysis_id = "analysis-" + "44" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="ef" * 32)
    current = _conversation(generation=5, packets=5)

    try:
        original = db.save_forensic_conversations(
            case_id, analysis_id, [current], completeness="complete"
        )
        stale = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [replace(current, generation=4, to_responder_packets=99)],
            completeness="complete",
        )
        advanced = db.save_forensic_conversations(
            case_id,
            analysis_id,
            [replace(current, generation=6, to_responder_packets=6)],
            completeness="complete",
        )
        item = db.get_forensic_conversations(analysis_id)["items"][0]

        assert stale == original
        assert advanced["sha256"] != original["sha256"]
        assert item["generation"] == 6
        assert item["to_responder_packets"] == 6
    finally:
        db.close()


def test_deep_dissection_is_hashed_idempotent_and_revision_scoped(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "ce" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "13" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    records = (
        {"frame.number": "1", "ip.src": "10.0.0.2", "tcp.dstport": "443"},
        {"frame.number": "2", "ip.dst": "10.0.0.2", "tcp.srcport": "443"},
    )

    try:
        first = db.save_forensic_deep_dissection(
            case_id, analysis_id, records, completeness="complete"
        )
        repeated = db.save_forensic_deep_dissection(
            case_id, analysis_id, records, completeness="complete"
        )
        page = db.get_forensic_deep_dissection(
            analysis_id, limit=1, offset=0
        )

        assert repeated == first
        assert first["component"] == "tshark_deep_dissection"
        assert first["record_count"] == 2
        assert len(first["sha256"]) == 64
        assert page["items"] == [
            {
                "ordinal": 0,
                "record_sha256": page["items"][0]["record_sha256"],
                "fields": records[0],
            }
        ]
        assert page["next_cursor"] == 1
        assert page["limit"] == 1
    finally:
        db.close()


@pytest.mark.parametrize(
    "terminal_state", ["complete", "partial", "cancelled", "failed"]
)
def test_terminal_deep_dissection_rejects_state_change_without_hash_change(
    tmp_path, terminal_state
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "cf" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "15" * 32
    records = ({"frame.number": "1", "ip.src": "10.0.0.2"},)
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)

    try:
        published = db.save_forensic_deep_dissection(
            case_id, analysis_id, records, completeness="complete"
        )
        db.save_forensic_analysis_revision(
            {
                "case_id": case_id,
                "analysis_id": analysis_id,
                "pcap_sha256": digest,
                "pipeline_version": "watchtower-forensics-v2.0",
                "configuration_hash": analysis_id.removeprefix("analysis-")[:64],
                "backend": "python",
                "state": terminal_state,
            }
        )
        exact = db.save_forensic_deep_dissection(
            case_id, analysis_id, records, completeness="complete"
        )

        assert exact == published
        with pytest.raises(ValueError, match="immutable|state"):
            db.save_forensic_deep_dissection(
                case_id, analysis_id, records, completeness="partial"
            )

        component = {
            item["component"]: item
            for item in db.get_forensic_evidence_components(analysis_id)
        }["tshark_deep_dissection"]
        revision = db.get_forensic_analysis_revision(analysis_id)
        assert revision["state"] == terminal_state
        assert component["sha256"] == published["sha256"]
        assert component["state"] == "complete"
        assert revision["evidence_components"]["tshark_deep_dissection"] == {
            "sha256": published["sha256"],
            "record_count": 1,
            "state": "complete",
        }
    finally:
        db.close()


def test_native_conversation_rejects_cross_scope_and_bounds_application_metadata(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "12" * 32
    analysis_id = "analysis-" + "55" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="12" * 32)
    application = {
        "authorization": "Bearer secret-token",
        "server_name": "x" * 10_000,
        **{f"field_{index:02d}": index for index in range(100)},
    }

    try:
        with pytest.raises(ValueError, match="scope"):
            db.save_forensic_conversations(
                "case-" + "99" * 32,
                analysis_id,
                [_conversation(application=application)],
                completeness="complete",
            )

        db.save_forensic_conversations(
            case_id,
            analysis_id,
            [_conversation(application=application)],
            completeness="complete",
        )
        stored = db.get_forensic_conversations(analysis_id)["items"][0]["application"]

        assert stored["authorization"]["redacted"] is True
        assert len(stored["server_name"]) <= 512
        assert len(stored) <= 32
    finally:
        db.close()


def _bidirectional_pcap(path):
    packets = [
        scapy.Ether()
        / scapy.IP(src="10.0.0.2", dst="203.0.113.8")
        / scapy.TCP(sport=49152, dport=443, flags="S"),
        scapy.Ether()
        / scapy.IP(src="203.0.113.8", dst="10.0.0.2")
        / scapy.TCP(sport=443, dport=49152, flags="SA"),
        scapy.Ether()
        / scapy.IP(src="10.0.0.2", dst="203.0.113.8")
        / scapy.TCP(sport=49152, dport=443, flags="A"),
    ]
    for timestamp, packet in enumerate(packets, start=10):
        packet.time = float(timestamp)
    scapy.wrpcap(str(path), packets)
    return path


def _event(sport, timestamp, *, flags="S"):
    return PacketEvent(
        timestamp=float(timestamp),
        src_ip="10.0.0.2",
        dst_ip="203.0.113.8",
        src_port=int(sport),
        dst_port=443,
        protocol="TCP",
        size=60,
        flags=flags,
        interface="offline",
        session_id="pcap:analysis-capacity",
        source="pcap:analysis-capacity",
        backend="python",
    )


@pytest.mark.parametrize(
    ("flags", "expected_initiator", "expected_responder", "expected_direction"),
    [
        ("SA", ("10.0.0.2", 49152), ("203.0.113.8", 443), "to_initiator"),
        ("S", ("203.0.113.8", 443), ("10.0.0.2", 49152), "to_responder"),
        ("A", ("203.0.113.8", 443), ("10.0.0.2", 49152), "to_responder"),
    ],
)
def test_tracker_first_packet_infers_handshake_roles(
    flags, expected_initiator, expected_responder, expected_direction
):
    tracker = ConversationTracker()
    event = PacketEvent(
        timestamp=1.0,
        src_ip="203.0.113.8",
        dst_ip="10.0.0.2",
        src_port=443,
        dst_port=49152,
        protocol="TCP",
        size=60,
        flags=flags,
        interface="offline",
        session_id="pcap:analysis-handshake",
        source="pcap:analysis-handshake",
        backend="python",
    )

    _metadata, delta = tracker.update_with_delta(event)

    assert delta.initiator == expected_initiator
    assert delta.responder == expected_responder
    assert delta.direction == expected_direction


def test_tracker_resumes_evicted_generation_without_counter_reset():
    tracker = ConversationTracker(maximum=100)
    tracker.update_with_delta(_event(40000, 1))
    tracker.update_with_delta(_event(40000, 2, flags="A"))
    for index in range(100):
        tracker.update_with_delta(_event(41000 + index, 10 + index))

    _metadata, resumed = tracker.update_with_delta(
        _event(40000, 200, flags="A")
    )

    assert resumed.generation == 3
    assert resumed.to_responder_packets == 3


def _capacity_pcap(path, count=101):
    packets = []
    for index in range(count):
        packet = (
            scapy.Ether()
            / scapy.IP(src="10.0.0.2", dst="203.0.113.8")
            / scapy.TCP(sport=40000 + index, dport=443, flags="S")
        )
        packet.time = float(index + 1)
        packets.append(packet)
    scapy.wrpcap(str(path), packets)
    return path


def test_engine_persists_evicted_conversations_and_marks_capacity_partial(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "core.forensics.engine.ConversationTracker",
        lambda: ConversationTracker(maximum=100),
    )
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    case_id = "case-" + "45" * 32
    analysis_id = "analysis-" + "67" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="45" * 32)
    engine = ForensicsEngine(db=db, data_dir=str(tmp_path / "engine"), silent=True)

    try:
        report = engine.analyze_pcap(
            str(_capacity_pcap(tmp_path / "capacity.pcap")),
            source_name="pcap:capacity-job",
            conversation_source=f"pcap:{analysis_id}",
            mode="memory",
            backend="python",
            case_id=case_id,
            analysis_id=analysis_id,
        )
        page = db.get_forensic_conversations(analysis_id, limit=200)
        component = db.get_forensic_evidence_components(analysis_id)[0]

        assert len(page["items"]) == 101
        assert component["record_count"] == 101
        assert component["state"] == "partial"
        assert report.status == "PARTIAL"
        assert "native_conversation_capacity_exceeded" in (
            report.summary["visibility_limitations"]
        )
    finally:
        db.close()


@pytest.mark.parametrize("mode", ["memory", "streaming"])
def test_engine_persists_finalized_native_conversation_without_reconstructing_flows(
    tmp_path, mode
):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    case_id = "case-" + "34" * 32
    analysis_id = "analysis-" + ("66" if mode == "memory" else "77") * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="34" * 32)
    source = f"pcap:job-{mode}:capture.pcap"
    engine = ForensicsEngine(db=db, data_dir=str(tmp_path / mode), silent=True)

    try:
        report = engine.analyze_pcap(
            str(_bidirectional_pcap(tmp_path / f"{mode}.pcap")),
            source_name=source,
            mode=mode,
            backend="python",
            case_id=case_id,
            analysis_id=analysis_id,
        )
        page = db.get_forensic_conversations(analysis_id)
        directional_rows = db.source_conversation_rows(source, limit=10)

        assert report.analysis_id == analysis_id
        assert len(page["items"]) == 1
        assert len(directional_rows) == 2
        conversation = page["items"][0]
        assert conversation["case_id"] == case_id
        assert conversation["analysis_id"] == analysis_id
        assert conversation["session_id"] == source
        assert conversation["source"] == source
        assert conversation["interface"] == "offline"
        assert conversation["protocol"] == "TCP"
        assert conversation["initiator_ip"] == "10.0.0.2"
        assert conversation["responder_ip"] == "203.0.113.8"
        assert conversation["to_responder_packets"] == 2
        assert conversation["to_initiator_packets"] == 1
        assert conversation["syn_count"] == 1
        assert conversation["syn_ack_count"] == 1
        assert conversation["established"] is True
        assert conversation["backend"] == "python"
        assert conversation["completeness"] == "complete"
    finally:
        db.close()


def test_revision_completion_atomically_references_published_component_hashes(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "56" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "88" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    conversations = db.save_forensic_conversations(
        case_id,
        analysis_id,
        [_conversation()],
        completeness="complete",
    )
    packet_index = {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "pcap_sha256": digest,
        "schema_version": 1,
        "manifest_path": str(tmp_path / "manifest.json"),
        "manifest_sha256": "91" * 32,
        "row_count": 3,
        "partition_count": 1,
        "first_timestamp": 10.0,
        "last_timestamp": 12.0,
        "state": "complete",
    }
    db.save_forensic_packet_index(packet_index)

    try:
        db.save_forensic_case_revision(
            {
                "id": case_id,
                "analysis_id": analysis_id,
                "sha256": digest,
                "state": "complete",
                "progress": 100.0,
            },
            {
                "case_id": case_id,
                "analysis_id": analysis_id,
                "pcap_sha256": digest,
                "pipeline_version": "watchtower-forensics-v2.0",
                "configuration_hash": "88" * 32,
                "backend": "python",
                "state": "complete",
                "report_hash": "92" * 32,
            },
        )
        revision = db.get_forensic_analysis_revision(analysis_id)

        assert revision["state"] == "complete"
        assert revision["evidence_components"] == {
            "native_conversations": {
                "sha256": conversations["sha256"],
                "record_count": 1,
                "state": "complete",
            },
            "packet_index": {
                "sha256": packet_index["manifest_sha256"],
                "record_count": 3,
                "state": "complete",
            },
        }
    finally:
        db.close()


def test_partial_revision_references_only_successfully_published_components(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "78" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "99" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    native = db.save_forensic_conversations(
        case_id,
        analysis_id,
        [_conversation()],
        completeness="complete",
    )

    try:
        db.save_forensic_case_revision(
            {
                "id": case_id,
                "analysis_id": analysis_id,
                "sha256": digest,
                "state": "partial",
                "visibility_limitations": ["packet_index_unavailable"],
            },
            {
                "case_id": case_id,
                "analysis_id": analysis_id,
                "pcap_sha256": digest,
                "pipeline_version": "watchtower-forensics-v2.0",
                "configuration_hash": "99" * 32,
                "backend": "python",
                "state": "partial",
                "visibility_limitations": ["packet_index_unavailable"],
            },
        )
        revision = db.get_forensic_analysis_revision(analysis_id)

        assert revision["state"] == "partial"
        assert revision["visibility_limitations"] == ["packet_index_unavailable"]
        assert revision["evidence_components"] == {
            "native_conversations": {
                "sha256": native["sha256"],
                "record_count": 1,
                "state": "complete",
            }
        }
    finally:
        db.close()


def test_terminal_revision_rejects_higher_native_generation(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "8b" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "ab" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    initial = _conversation(generation=3, packets=3)
    db.save_forensic_conversations(
        case_id, analysis_id, [initial], completeness="complete"
    )
    db.save_forensic_case_revision(
        {
            "id": case_id,
            "analysis_id": analysis_id,
            "sha256": digest,
            "state": "complete",
        },
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": "ab" * 32,
            "backend": "python",
            "state": "complete",
        },
    )

    try:
        original = db.get_forensic_analysis_revision(analysis_id)
        with pytest.raises(ValueError, match="immutable"):
            db.save_forensic_conversations(
                case_id,
                analysis_id,
                [replace(initial, generation=4, to_responder_packets=4)],
                completeness="complete",
            )
        db.save_forensic_packet_index({
            "analysis_id": analysis_id,
            "case_id": case_id,
            "pcap_sha256": digest,
            "schema_version": 1,
            "manifest_path": str(tmp_path / "late-manifest.json"),
            "manifest_sha256": "ac" * 32,
            "row_count": 4,
            "partition_count": 1,
            "state": "complete",
        })
        revision = db.get_forensic_analysis_revision(analysis_id)

        assert revision["state"] == "complete"
        assert revision["evidence_components"]["native_conversations"] == (
            original["evidence_components"]["native_conversations"]
        )
        assert revision["evidence_components"]["packet_index"]["sha256"] == "ac" * 32
    finally:
        db.close()


def test_terminal_empty_native_component_rejects_completeness_change(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "8c" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "ac" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    published = db.save_forensic_conversations(
        case_id, analysis_id, [], completeness="complete"
    )
    db.save_forensic_analysis_revision(
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": analysis_id.removeprefix("analysis-")[:64],
            "backend": "python",
            "state": "complete",
        }
    )

    try:
        with pytest.raises(ValueError, match="immutable|state"):
            db.save_forensic_conversations(
                case_id, analysis_id, [], completeness="partial"
            )
        component = {
            item["component"]: item
            for item in db.get_forensic_evidence_components(analysis_id)
        }["native_conversations"]
        revision = db.get_forensic_analysis_revision(analysis_id)
        assert component["state"] == "complete"
        assert revision["evidence_components"]["native_conversations"] == {
            "sha256": published["sha256"],
            "record_count": 0,
            "state": "complete",
        }
    finally:
        db.close()


def _complete_packet_index(db, tmp_path, *, case_id, analysis_id, digest):
    values = {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "pcap_sha256": digest,
        "schema_version": 1,
        "manifest_path": str(tmp_path / f"{analysis_id}-manifest.json"),
        "manifest_sha256": "ae" * 32,
        "row_count": 7,
        "partition_count": 1,
        "state": "complete",
    }
    db.save_forensic_packet_index(values)
    db.save_forensic_analysis_revision(
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": analysis_id.removeprefix("analysis-")[:64],
            "backend": "python",
            "state": "complete",
        }
    )
    return values


def _remove_packet_index_component(db, analysis_id):
    with db.session_scope(write=True) as session:
        session.query(ForensicEvidenceComponent).filter_by(
            analysis_id=analysis_id,
            component="packet_index",
        ).delete()
        revision = session.query(ForensicAnalysisRevision).filter_by(
            analysis_id=analysis_id
        ).one()
        revision.evidence_components_json = "{}"


def test_complete_packet_index_idempotent_save_repairs_component_snapshot(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "9c" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "af" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    values = _complete_packet_index(
        db,
        tmp_path,
        case_id=case_id,
        analysis_id=analysis_id,
        digest=digest,
    )

    try:
        _remove_packet_index_component(db, analysis_id)
        db.save_forensic_packet_index(values)

        components = {
            item["component"]: item
            for item in db.get_forensic_evidence_components(analysis_id)
        }
        revision = db.get_forensic_analysis_revision(analysis_id)
        assert components["packet_index"]["sha256"] == values["manifest_sha256"]
        assert revision["evidence_components"]["packet_index"]["sha256"] == (
            values["manifest_sha256"]
        )
    finally:
        db.close()


def test_complete_packet_index_rejects_requested_state_change(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "9e" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "b1" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    values = _complete_packet_index(
        db,
        tmp_path,
        case_id=case_id,
        analysis_id=analysis_id,
        digest=digest,
    )

    try:
        with pytest.raises(ValueError, match="immutable|state"):
            db.save_forensic_packet_index({**values, "state": "partial"})
        revision = db.get_forensic_analysis_revision(analysis_id)
        assert revision["evidence_components"]["packet_index"]["state"] == "complete"
    finally:
        db.close()


def test_database_open_backfills_complete_packet_index_component(tmp_path):
    digest = "9d" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "b0" * 32
    db = WatchtowerDB(data_dir=str(tmp_path))
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    values = _complete_packet_index(
        db,
        tmp_path,
        case_id=case_id,
        analysis_id=analysis_id,
        digest=digest,
    )
    _remove_packet_index_component(db, analysis_id)
    db.close()

    reopened = WatchtowerDB(data_dir=str(tmp_path))
    try:
        components = {
            item["component"]: item
            for item in reopened.get_forensic_evidence_components(analysis_id)
        }
        revision = reopened.get_forensic_analysis_revision(analysis_id)
        assert components["packet_index"]["record_count"] == values["row_count"]
        assert revision["evidence_components"]["packet_index"]["sha256"] == (
            values["manifest_sha256"]
        )
    finally:
        reopened.close()


def test_case_conversation_reads_prefer_native_and_label_legacy_reconstruction(
    tmp_path,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    case_id = "case-" + "9a" * 32
    analysis_id = "analysis-" + "aa" * 32
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest="9a" * 32)
    delta = _conversation()
    db.save_forensic_conversations(
        case_id, analysis_id, [delta], completeness="complete"
    )
    db.upsert_flow(
        src_ip="192.0.2.10",
        dst_ip="192.0.2.20",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        start_time=1.0,
        last_seen=2.0,
        packet_count=1,
        byte_count=100,
        source="pcap:legacy",
        l7_metadata={},
    )
    service = object.__new__(WatchtowerApiService)
    service.db = db

    try:
        native = service._pcap_conversation_page(
            delta.key.source, 100, 0, analysis_id=analysis_id
        )
        legacy = service._pcap_conversation_page(
            "pcap:legacy", 100, 0, analysis_id="analysis-legacy"
        )

        assert native["mode"] == "native"
        assert native["legacy_fallback"] is False
        assert native["directional_rows_scanned"] == 0
        assert native["items"][0]["generation"] == delta.generation
        assert legacy["mode"] == "legacy_reconstruction"
        assert legacy["legacy_fallback"] is True
        assert legacy["directional_rows_scanned"] == 1
    finally:
        db.close()


def test_current_native_publication_failure_is_not_labeled_legacy(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    digest = "9b" * 32
    case_id = "case-" + digest
    analysis_id = "analysis-" + "ad" * 32
    source = f"pcap:{analysis_id}"
    _create_revision(db, case_id=case_id, analysis_id=analysis_id, digest=digest)
    db.save_forensic_analysis_revision(
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": analysis_id.removeprefix("analysis-")[:64],
            "backend": "python",
            "state": "partial",
            "visibility_limitations": ["native_conversations_unavailable"],
        }
    )
    db.upsert_flow(
        src_ip="192.0.2.10",
        dst_ip="192.0.2.20",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        start_time=1.0,
        last_seen=2.0,
        packet_count=1,
        byte_count=100,
        source=source,
        l7_metadata={},
    )
    service = object.__new__(WatchtowerApiService)
    service.db = db

    try:
        page = service._pcap_conversation_page(
            source, 100, 0, analysis_id=analysis_id
        )

        assert page["mode"] == "native_unavailable"
        assert page["legacy_fallback"] is False
        assert page["items"] == []
        assert page["directional_rows_scanned"] == 0
        assert page["visibility_limitations"] == [
            "native_conversations_unavailable"
        ]
    finally:
        db.close()


class _MemoryCredentialStore:
    def __init__(self):
        self.secrets = {}

    def set(self, reference, secret):
        self.secrets[reference] = secret

    def get(self, reference):
        return self.secrets.get(reference)

    def delete(self, reference):
        return self.secrets.pop(reference, None) is not None


class _RevisionAwareEngine:
    observed: ClassVar[dict] = {}

    def __init__(self, **_kwargs):
        pass

    def analyze_pcap(
        self,
        path,
        progress_callback,
        source_name,
        mode,
        backend,
        cancel_event,
        case_id=None,
        analysis_id=None,
    ):
        self.__class__.observed = {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "source": source_name,
        }
        size = os.path.getsize(path)
        progress_callback(size, size)
        return SimpleNamespace(
            status="COMPLETE",
            summary={"total_flows": 0},
            bytes_processed=size,
            error=None,
            report_id=None,
            entities={},
        )


class _NativePersistenceEngine:
    observed_conversation_sources: ClassVar[list[str]] = []

    def __init__(self, db, **_kwargs):
        self.db = db

    def analyze_pcap(
        self,
        path,
        progress_callback,
        source_name,
        mode,
        backend,
        cancel_event,
        case_id=None,
        analysis_id=None,
        conversation_source=None,
    ):
        self.__class__.observed_conversation_sources.append(conversation_source)
        delta = _conversation()
        stable_key = replace(
            delta.key,
            source=conversation_source,
            session_id=conversation_source,
        )
        manifest = self.db.save_forensic_conversations(
            case_id,
            analysis_id,
            [replace(delta, key=stable_key)],
            completeness="complete",
        )
        size = os.path.getsize(path)
        progress_callback(size, size)
        return SimpleNamespace(
            status="COMPLETE",
            summary={
                "total_flows": 0,
                "native_conversations": {
                    "state": "complete",
                    "record_count": manifest["record_count"],
                    "sha256": manifest["sha256"],
                },
            },
            bytes_processed=size,
            error=None,
            report_id=None,
            entities={},
        )


def _wait_for_job(manager, job_id):
    deadline = time.time() + 3
    job = manager.get(job_id)
    while job["status"] not in {"complete", "partial", "failed"} and time.time() < deadline:
        time.sleep(0.01)
        job = manager.get(job_id)
    return job


def test_content_addressed_rerun_reuses_native_source_and_identity(tmp_path):
    _NativePersistenceEngine.observed_conversation_sources = []
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    manager = PcapJobManager(
        db=db,
        engine_factory=_NativePersistenceEngine,
        credential_store=_MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
        packet_index_builder=None,
        tshark_dissector=None,
    )

    try:
        jobs = []
        for name in ("first.pcap", "renamed.pcap"):
            capture = tmp_path / name
            capture.write_bytes(b"same-content-addressed-pcap")
            submitted = manager.submit(str(capture), name, "memory", "python")
            jobs.append(_wait_for_job(manager, submitted["id"]))

        assert jobs[0]["analysis_id"] == jobs[1]["analysis_id"]
        assert jobs[0]["source"] != jobs[1]["source"]
        assert _NativePersistenceEngine.observed_conversation_sources == [
            f"pcap:{jobs[0]['analysis_id']}",
            f"pcap:{jobs[0]['analysis_id']}",
        ]
        page = db.get_forensic_conversations(jobs[0]["analysis_id"])
        component = db.get_forensic_evidence_components(jobs[0]["analysis_id"])
        assert len(page["items"]) == 1
        assert page["items"][0]["source"] == f"pcap:{jobs[0]['analysis_id']}"
        assert page["items"][0]["session_id"] == f"pcap:{jobs[0]['analysis_id']}"
        assert component[0]["record_count"] == 1
    finally:
        manager.shutdown()
        db.close()


def test_job_passes_true_revision_id_and_records_missing_tshark_limitation(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = Path(tmp_path) / "capture.pcap"
    capture.write_bytes(b"pcap-job-fixture")
    manager = PcapJobManager(
        db=db,
        engine_factory=_RevisionAwareEngine,
        credential_store=_MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
        packet_index_builder=None,
        tshark_dissector=TSharkDissector(
            configured_executable=tmp_path / "missing-tshark.exe",
            trusted_installations=(),
        ),
    )

    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        deadline = time.time() + 3
        job = manager.get(submitted["id"])
        while job["status"] not in {"complete", "partial", "failed"} and time.time() < deadline:
            time.sleep(0.01)
            job = manager.get(submitted["id"])

        assert job["status"] == "complete"
        assert _RevisionAwareEngine.observed["case_id"] == job["case_id"]
        assert _RevisionAwareEngine.observed["analysis_id"] == job["analysis_id"]
        assert job["analysis_id"] != job["case_id"]
        assert job["summary"]["tshark"]["health"]["state"] == "unavailable"
        assert "tshark_unavailable" in job["summary"]["visibility_limitations"]
        revision = db.get_forensic_analysis_revision(job["analysis_id"])
        assert revision["state"] == "complete"
        assert "tshark_unavailable" in revision["visibility_limitations"]
    finally:
        manager.shutdown()
        db.close()


class _SuccessfulTShark:
    def dissect(self, _path):
        records = (
            {"frame.number": "1", "ip.src": "10.0.0.2"},
            {"frame.number": "2", "ip.dst": "10.0.0.2"},
        )
        return TSharkResult(
            records=records,
            limitations=(),
            health={
                "plugin": "tshark",
                "state": "healthy",
                "error_code": None,
                "records": len(records),
            },
        )


def test_job_persists_successful_tshark_evidence_and_exposes_bounded_read(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = Path(tmp_path) / "deep.pcap"
    capture.write_bytes(b"deep-dissection-fixture")
    manager = PcapJobManager(
        db=db,
        engine_factory=_RevisionAwareEngine,
        credential_store=_MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
        packet_index_builder=None,
        tshark_dissector=_SuccessfulTShark(),
    )
    service = object.__new__(WatchtowerApiService)
    service.db = db
    service.jobs = manager

    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_job(manager, submitted["id"])
        page = service.pcap_deep_dissection(job["id"], limit=1, cursor=0)
        revision = db.get_forensic_analysis_revision(job["analysis_id"])

        assert job["status"] == "complete"
        assert job["summary"]["tshark"]["state"] == "healthy"
        assert job["summary"]["tshark"]["record_count"] == 2
        assert len(job["summary"]["tshark"]["evidence_sha256"]) == 64
        assert page["items"][0]["fields"]["frame.number"] == "1"
        assert page["next_cursor"] == 1
        assert revision["evidence_components"]["tshark_deep_dissection"] == {
            "sha256": job["summary"]["tshark"]["evidence_sha256"],
            "record_count": 2,
            "state": "complete",
        }
    finally:
        manager.shutdown()
        db.close()
