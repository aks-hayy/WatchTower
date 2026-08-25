from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import io

import pytest


def _module():
    from core.packet_engine import rust_analysis

    return rust_analysis


def _plan(module):
    return module.AnalysisPlanWire(
        plan_sha256=b"\x00" * 32,
        semantic_plugin_sha256=bytes.fromhex("11" * 32),
        execution_mode="aggregate-v1",
        analysis_mode="memory",
        flags=module.ANALYSIS_FLAG_PACKET_INDEX | module.ANALYSIS_FLAG_TERMINAL_METRICS,
        target_batch_bytes=1_048_576,
        max_active_conversations=100_000,
        max_resume_conversations=100_000,
        max_directional_flows=220_000,
        max_endpoints=440_000,
        max_flow_samples=500,
        max_flow_sample_bytes=268_435_456,
        max_stream_segments=10_000,
        max_stream_bytes=16_777_216,
        source="pcap:fixture",
        session_id="rust-replay",
        interface="pcap",
        sensor_node_id="local",
        selector_programs=(),
    )


def test_analysis_plan_round_trip_self_hashes_and_preserves_bounded_fields():
    module = _module()
    plan = _plan(module)

    encoded = module.encode_analysis_plan(plan)
    decoded = module.decode_analysis_plan(encoded)

    assert decoded == replace(plan, plan_sha256=sha256(encoded[33:]).digest())
    assert decoded.plan_sha256 == sha256(encoded[33:]).digest()


def test_analysis_plan_round_trips_compiled_selector_programs():
    module = _module()
    plan = replace(
        _plan(module),
        selector_programs=(
            module.AnalysisSelectorProgramWire(
                program_id=3,
                candidate_mode="deep-scapy-v1",
                clauses=(
                    module.AnalysisSelectorClauseWire("either-port-in", (53, 5353)),
                    module.AnalysisSelectorClauseWire(
                        "payload-prefix-in", (b"GET ", b"POST ")
                    ),
                ),
            ),
        ),
    )

    decoded = module.decode_analysis_plan(module.encode_analysis_plan(plan))

    assert decoded.selector_programs == plan.selector_programs


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda payload: payload[:-1], "truncated"),
        (lambda payload: payload + b"x", "trailing"),
        (lambda payload: bytes([2]) + payload[1:], "schema"),
        (lambda payload: payload[:65] + bytes([99]) + payload[66:], "execution mode"),
        (lambda payload: payload[:66] + bytes([99]) + payload[67:], "analysis mode"),
    ],
)
def test_analysis_plan_decoder_rejects_malformed_or_unrecognized_input(mutate, message):
    module = _module()
    encoded = module.encode_analysis_plan(_plan(module))

    with pytest.raises(module.AnalysisProtocolError, match=message):
        module.decode_analysis_plan(mutate(encoded))


def test_analysis_stream_requires_matching_hello_before_any_other_output():
    module = _module()
    plan = _plan(module)
    validator = module.AnalysisStreamValidator(plan)

    with pytest.raises(module.AnalysisProtocolError, match="first output.*hello"):
        validator.accept(module.FRAME_ANALYSIS_WORK, b"")

    hello = module.encode_analysis_hello(
        module.AnalysisHelloWire(
            plan_sha256=module.decode_analysis_plan(module.encode_analysis_plan(plan)).plan_sha256,
            sensor_version="2.0.0",
            pcap_datalink=1,
            normalized_link_type="ethernet",
            capability_bits=module.ANALYSIS_CAPABILITY_V1,
        )
    )
    validator.accept(module.FRAME_ANALYSIS_HELLO, hello)
    assert validator.hello is not None


def test_analysis_stream_rejects_hello_with_a_different_plan_digest():
    module = _module()
    plan = _plan(module)
    validator = module.AnalysisStreamValidator(plan)
    hello = module.encode_analysis_hello(
        module.AnalysisHelloWire(
            plan_sha256=b"\xff" * 32,
            sensor_version="2.0.0",
            pcap_datalink=1,
            normalized_link_type="ethernet",
            capability_bits=module.ANALYSIS_CAPABILITY_V1,
        )
    )

    with pytest.raises(module.AnalysisProtocolError, match="plan digest"):
        validator.accept(module.FRAME_ANALYSIS_HELLO, hello)


class _FakeChild:
    def __init__(self, stdout, *, exit_code=0):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.returncode = None
        self.exit_code = exit_code
        self.terminated = False
        self.waited = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = self.exit_code

    def kill(self):
        self.returncode = self.exit_code

    def wait(self, timeout=None):
        self.waited = True
        self.returncode = self.exit_code
        return self.returncode


def test_analysis_child_writes_plan_requires_hello_and_reaps_early_close():
    module = _module()
    plan = _plan(module)
    resolved = module.decode_analysis_plan(module.encode_analysis_plan(plan))
    hello = module.encode_analysis_hello(
        module.AnalysisHelloWire(
            plan_sha256=resolved.plan_sha256,
            sensor_version="2.0.0",
            pcap_datalink=1,
            normalized_link_type="ethernet",
            capability_bits=module.ANALYSIS_CAPABILITY_V1,
        )
    )
    child = _FakeChild(module.encode_transport_frame(module.FRAME_ANALYSIS_HELLO, hello))
    session = module.RustAnalysisChild(child, plan)

    assert session.start().plan_sha256 == resolved.plan_sha256
    kind, payload = module.read_transport_frame(io.BytesIO(child.stdin.getvalue()))
    assert kind == module.FRAME_ANALYSIS_PLAN
    assert module.decode_analysis_plan(payload) == resolved

    session.close()
    assert child.terminated and child.waited


def test_analysis_child_reaps_process_when_the_handshake_is_invalid():
    module = _module()
    child = _FakeChild(module.encode_transport_frame(module.FRAME_ANALYSIS_WORK, b""))
    session = module.RustAnalysisChild(child, _plan(module))

    with pytest.raises(module.AnalysisProtocolError, match="first output.*hello"):
        session.start()

    assert child.terminated and child.waited


def test_analysis_stream_requires_a_matching_terminal_certificate_before_clean_eof():
    module = _module()
    plan = _plan(module)
    resolved = module.decode_analysis_plan(module.encode_analysis_plan(plan))
    validator = module.AnalysisStreamValidator(plan)
    hello = module.encode_analysis_hello(
        module.AnalysisHelloWire(
            plan_sha256=resolved.plan_sha256,
            sensor_version="2.0.0",
            pcap_datalink=1,
            normalized_link_type="ethernet",
            capability_bits=module.ANALYSIS_CAPABILITY_V1,
        )
    )
    validator.accept(module.FRAME_ANALYSIS_HELLO, hello)

    with pytest.raises(module.AnalysisProtocolError, match="terminal certificate"):
        validator.finish(0)

    end = module.AnalysisEndWire(
        plan_sha256=resolved.plan_sha256,
        terminal_status="complete",
        error_code="",
        packet_index_rows=7,
        decoded_work_items=7,
        raw_candidate_items=0,
        raw_candidate_bytes=0,
        flow_snapshot_records=1,
        terminal_directional_flows=1,
        conversation_snapshot_records=1,
        terminal_conversations=1,
        stream_segment_records=0,
        stream_segment_bytes=0,
        stream_truncated_segments=0,
        stream_truncated_bytes=0,
        first_decoded_timestamp=1.0,
        last_decoded_timestamp=2.0,
        packet_index_digest=b"\x01" * 32,
        work_digest=b"\x02" * 32,
        flow_digest=b"\x03" * 32,
        conversation_digest=b"\x04" * 32,
        stream_digest=b"\x05" * 32,
        read_decode_ns=10,
        candidate_match_ns=11,
        aggregate_ns=12,
        blocked_write_ns=13,
        endpoint_high_water=2,
        flow_high_water=1,
        conversation_high_water=1,
        resume_high_water=0,
        sample_bytes_high_water=0,
    )
    validator.accept(module.FRAME_ANALYSIS_END, module.encode_analysis_end(end))

    assert validator.finish(0) == end


def _ascii8(value: str) -> bytes:
    encoded = value.encode("ascii")
    return bytes([len(encoded)]) + encoded


def _work_frame(*, duplicate_endpoint: bool = False, unknown_flow: bool = False) -> bytes:
    endpoint_count = 2
    payload = bytearray(b"\x01")
    payload.extend((1).to_bytes(4, "big"))
    payload.extend(endpoint_count.to_bytes(2, "big"))
    payload.extend((1).to_bytes(2, "big"))
    payload.extend((1).to_bytes(2, "big"))
    payload.extend((1).to_bytes(2, "big"))
    endpoint_ids = (1, 1) if duplicate_endpoint else (1, 2)
    for endpoint_id, address in zip(endpoint_ids, ("10.0.0.1", "10.0.0.2")):
        payload.extend(endpoint_id.to_bytes(4, "big"))
        payload.extend(_ascii8(address))
    payload.extend((7).to_bytes(4, "big"))
    payload.extend((1).to_bytes(4, "big"))
    payload.extend((2).to_bytes(4, "big"))
    payload.extend((51000).to_bytes(2, "big"))
    payload.extend((443).to_bytes(2, "big"))
    payload.append(6)
    payload.extend((9).to_bytes(4, "big"))
    payload.extend((1).to_bytes(4, "big"))
    payload.extend((51000).to_bytes(2, "big"))
    payload.extend((2).to_bytes(4, "big"))
    payload.extend((443).to_bytes(2, "big"))
    payload.extend((1).to_bytes(4, "big"))
    payload.extend((51000).to_bytes(2, "big"))
    payload.extend((2).to_bytes(4, "big"))
    payload.extend((443).to_bytes(2, "big"))
    payload.append(6)
    payload.extend(__import__("struct").pack(">d", 100.0))
    payload.extend((33).to_bytes(8, "big"))
    payload.extend(__import__("struct").pack(">d", 100.0))
    payload.extend((60).to_bytes(4, "big"))
    payload.extend((99 if unknown_flow else 7).to_bytes(4, "big"))
    payload.extend((9).to_bytes(4, "big"))
    payload.append(64)
    payload.extend((0x02).to_bytes(2, "big"))
    payload.extend(b"\x01\x02")
    payload.extend((5).to_bytes(8, "big"))
    payload.extend(__import__("struct").pack(">d", 100.0))
    for value in (1, 60, 1, 0, 0, 1, 1, 60, 0, 0, 1, 0, 0):
        payload.extend(value.to_bytes(8, "big"))
    for value in (1, 0, 0):
        payload.extend(value.to_bytes(4, "big"))
    payload.append(0)
    payload.extend((5).to_bytes(4, "big"))
    payload.extend(b"frame")
    return bytes(payload)


def test_work_decoder_registers_definitions_and_returns_a_bounded_candidate():
    module = _module()
    decoder = module.AnalysisDataDecoder()

    batch = decoder.decode_work(_work_frame())

    assert batch.sequence == 1
    assert batch.items[0].packet_ordinal == 33
    assert batch.items[0].flow.source.address == "10.0.0.1"
    assert batch.items[0].conversation.initiator.address == "10.0.0.1"
    assert batch.items[0].conversation.protocol == 6
    assert batch.items[0].candidate_mode == "deep-scapy-v1"
    assert batch.items[0].raw_frame == b"frame"


def test_work_decoder_rejects_duplicate_definitions_and_unknown_references():
    module = _module()

    with pytest.raises(module.AnalysisProtocolError, match="duplicate endpoint ID"):
        module.AnalysisDataDecoder().decode_work(_work_frame(duplicate_endpoint=True))
    with pytest.raises(module.AnalysisProtocolError, match="unknown flow ID"):
        module.AnalysisDataDecoder().decode_work(_work_frame(unknown_flow=True))


def test_work_decoder_rejects_trailing_bytes_and_nonfinite_timestamps():
    module = _module()
    with pytest.raises(module.AnalysisProtocolError, match="trailing"):
        module.AnalysisDataDecoder().decode_work(_work_frame() + b"x")

    malformed = bytearray(_work_frame())
    packet_timestamp_offset = 13 + (4 + 1 + 8) * 2 + 17 + 37 + 8
    malformed[packet_timestamp_offset:packet_timestamp_offset + 8] = __import__("struct").pack(">d", float("nan"))
    with pytest.raises(module.AnalysisProtocolError, match="packet timestamp.*finite"):
        module.AnalysisDataDecoder().decode_work(bytes(malformed))


def _terminal_flow_frame(flow_id: int = 7) -> bytes:
    payload = bytearray(b"\x01")
    payload.extend((2).to_bytes(4, "big"))
    payload.extend((1).to_bytes(2, "big"))
    payload.extend(flow_id.to_bytes(4, "big"))
    payload.extend((1).to_bytes(4, "big"))
    payload.append(2)
    payload.extend(__import__("struct").pack(">dd", 100.0, 101.0))
    for value in (2, 120, 1, 1, 0):
        payload.extend(value.to_bytes(8, "big"))
    payload.extend((1).to_bytes(2, "big"))
    payload.extend((60).to_bytes(4, "big"))
    payload.extend(__import__("struct").pack(">d", 100.0))
    return bytes(payload)


def _terminal_conversation_frame(conversation_id: int = 9) -> bytes:
    payload = bytearray(b"\x01")
    payload.extend((3).to_bytes(4, "big"))
    payload.extend((1).to_bytes(2, "big"))
    payload.extend(conversation_id.to_bytes(4, "big"))
    payload.append(2)
    payload.extend(__import__("struct").pack(">d", 101.0))
    for value in (2, 1, 60, 1, 60, 1, 1, 0):
        payload.extend(value.to_bytes(8, "big"))
    payload.append(1)
    return bytes(payload)


def test_terminal_aggregate_decoders_resolve_definitions_and_samples():
    module = _module()
    decoder = module.AnalysisDataDecoder()
    decoder.decode_work(_work_frame())

    flows = decoder.decode_flows(_terminal_flow_frame())
    conversations = decoder.decode_conversations(_terminal_conversation_frame())

    assert flows.sequence == 2
    assert flows.records[0].definition.flow_id == 7
    assert flows.records[0].samples == ((60, 100.0),)
    assert conversations.records[0].definition.conversation_id == 9
    assert conversations.records[0].established is True


def test_terminal_aggregate_decoders_reject_unknown_ids():
    module = _module()
    decoder = module.AnalysisDataDecoder()
    decoder.decode_work(_work_frame())

    with pytest.raises(module.AnalysisProtocolError, match="unknown terminal flow ID"):
        decoder.decode_flows(_terminal_flow_frame(99))
    with pytest.raises(module.AnalysisProtocolError, match="unknown terminal conversation ID"):
        decoder.decode_conversations(_terminal_conversation_frame(99))


def test_work_item_projects_to_packet_event_with_exact_origin_and_flags():
    module = _module()
    item = module.AnalysisDataDecoder().decode_work(_work_frame()).items[0]

    event = module.work_item_to_packet_event(
        item,
        {
            "session_id": "session-7",
            "device_id": "pcap",
            "source_type": "network",
            "source": "pcap:fixture",
            "sensor_node_id": "local",
        },
        link_type="ethernet",
    )

    assert (event.src_ip, event.dst_ip, event.src_port, event.dst_port) == (
        "10.0.0.1", "10.0.0.2", 51000, 443
    )
    assert event.protocol == "TCP"
    assert event.flags == "S"
    assert event.raw == b"frame"
    assert event.session_id == "session-7"
    assert event.backend == "rust"
