import io
from pathlib import Path
import queue
import struct

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, wrpcap
from scapy.utils import RawPcapWriter

from core.packet_engine.capture import packet_to_event
from core.packet_engine.rust_capture import (
    FRAME_EVENTS, MAGIC, aggregate_replay_events, build_aggregate_analysis_plan,
    decode_event_batch, read_frame, replay_events,
    rust_sensor_available, sensor_binary, start_rust_capture,
)


def _encode_test_event(raw):
    payload = bytearray(struct.pack(">H", 1))
    payload.extend(struct.pack(">d", 1.5))
    payload.extend(bytes([8]) + b"10.0.0.1")
    payload.extend(bytes([8]) + b"10.0.0.2")
    payload.extend(struct.pack(">HHBIHI", 12345, 443, 6, len(raw), 0x12, len(raw)))
    payload.extend(raw)
    return bytes(payload)


def test_binary_frame_rejects_invalid_and_truncated_data():
    with pytest.raises(ValueError):
        read_frame(io.BytesIO(b"BAD!" + bytes([1, FRAME_EVENTS]) + struct.pack(">I", 0)))
    with pytest.raises(EOFError):
        read_frame(io.BytesIO(MAGIC + bytes([1, FRAME_EVENTS]) + struct.pack(">I", 100)))


def test_binary_batch_preserves_raw_packet_and_provenance():
    raw = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=443, flags="SA"))
    events = decode_event_batch(_encode_test_event(raw), {
        "session_id": "rust-1", "device_id": "Ethernet",
        "source_type": "network", "link_type": "ethernet",
    })
    assert len(events) == 1
    assert events[0].raw == raw
    assert events[0].backend == "rust"
    assert events[0].session_id == "rust-1"
    assert events[0].flags == "SA"


def test_sensor_binary_uses_configured_packaged_path(monkeypatch, tmp_path):
    import core.packet_engine.rust_capture as rust_capture

    packaged = tmp_path / ("watchtower-sensor.exe" if rust_capture.os.name == "nt" else "watchtower-sensor")
    packaged.write_bytes(b"sensor")
    monkeypatch.setenv("WATCHTOWER_RUST_SENSOR", str(packaged))

    assert sensor_binary() == packaged


def test_sensor_binary_uses_path_before_source_tree(monkeypatch, tmp_path):
    import core.packet_engine.rust_capture as rust_capture

    packaged = tmp_path / "watchtower-sensor"
    packaged.write_bytes(b"sensor")
    monkeypatch.delenv("WATCHTOWER_RUST_SENSOR", raising=False)
    monkeypatch.setattr(rust_capture.shutil, "which", lambda _name: str(packaged))

    assert sensor_binary() == packaged


def test_replay_normal_eof_waits_for_child_and_propagates_nonzero_exit(
    monkeypatch, tmp_path
):
    import core.packet_engine.rust_capture as rust_capture

    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")

    class FailedProcess:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO(b"invalid capture header")
            self.returncode = None
            self.waited = False
            self.terminated = False

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.waited = True
            self.returncode = 7
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

    process = FailedProcess()
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: Path(binary))
    monkeypatch.setattr(rust_capture.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(RuntimeError, match="invalid capture header"):
        list(replay_events(tmp_path / "corrupt.pcap"))

    assert process.waited
    assert not process.terminated


def test_replay_caller_close_terminates_child_without_reporting_signal_exit(
    monkeypatch, tmp_path
):
    import core.packet_engine.rust_capture as rust_capture

    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    raw = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
    payload = _encode_test_event(raw)
    frame = MAGIC + bytes([1, FRAME_EVENTS]) + struct.pack(">I", len(payload)) + payload

    class RunningProcess:
        def __init__(self):
            self.stdout = io.BytesIO(frame)
            self.stderr = io.BytesIO()
            self.returncode = None
            self.terminated = False

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

    process = RunningProcess()
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: Path(binary))
    monkeypatch.setattr(rust_capture.subprocess, "Popen", lambda *args, **kwargs: process)
    events = replay_events(tmp_path / "capture.pcap")

    assert next(events).src_ip == "10.0.0.1"
    events.close()

    assert process.terminated


def test_aggregate_replay_requires_handshake_and_terminal_certificate(
    monkeypatch, tmp_path
):
    import core.packet_engine.rust_analysis as protocol
    import core.packet_engine.rust_capture as rust_capture

    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    plan = build_aggregate_analysis_plan(
        semantic_plugin_digest="11" * 32,
        analysis_mode="memory",
        origin={
            "source": "pcap:fixture",
            "session_id": "analysis-1",
            "device_id": "pcap",
            "sensor_node_id": "local",
        },
    )
    resolved = protocol.decode_analysis_plan(protocol.encode_analysis_plan(plan))
    hello = protocol.encode_analysis_hello(protocol.AnalysisHelloWire(
        plan_sha256=resolved.plan_sha256,
        sensor_version="2.0.0",
        pcap_datalink=1,
        normalized_link_type="ethernet",
        capability_bits=protocol.ANALYSIS_CAPABILITY_V1,
    ))
    end = protocol.encode_analysis_end(protocol.AnalysisEndWire(
        plan_sha256=resolved.plan_sha256,
        terminal_status="complete",
        error_code="",
        packet_index_rows=0,
        decoded_work_items=0,
        raw_candidate_items=0,
        raw_candidate_bytes=0,
        flow_snapshot_records=0,
        terminal_directional_flows=0,
        conversation_snapshot_records=0,
        terminal_conversations=0,
        stream_segment_records=0,
        stream_segment_bytes=0,
        stream_truncated_segments=0,
        stream_truncated_bytes=0,
        first_decoded_timestamp=None,
        last_decoded_timestamp=None,
        packet_index_digest=b"\x00" * 32,
        work_digest=b"\x00" * 32,
        flow_digest=b"\x00" * 32,
        conversation_digest=b"\x00" * 32,
        stream_digest=b"\x00" * 32,
        read_decode_ns=0,
        candidate_match_ns=0,
        aggregate_ns=0,
        blocked_write_ns=0,
        endpoint_high_water=0,
        flow_high_water=0,
        conversation_high_water=0,
        resume_high_water=0,
        sample_bytes_high_water=0,
    ))
    output = b"".join((
        protocol.encode_transport_frame(protocol.FRAME_ANALYSIS_HELLO, hello),
        protocol.encode_transport_frame(protocol.FRAME_ANALYSIS_END, end),
    ))

    class RecordingBytesIO(io.BytesIO):
        def close(self):
            pass

    class CompletedProcess:
        def __init__(self):
            self.stdin = RecordingBytesIO()
            self.stdout = io.BytesIO(output)
            self.stderr = io.BytesIO()
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    process = CompletedProcess()
    commands = []
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: Path(binary))
    monkeypatch.setattr(
        rust_capture.subprocess,
        "Popen",
        lambda command, **_kwargs: commands.append(command) or process,
    )
    result = {}

    assert list(aggregate_replay_events(
        tmp_path / "fixture.pcap",
        semantic_plugin_digest="11" * 32,
        analysis_mode="memory",
        origin={
            "source": "pcap:fixture",
            "session_id": "analysis-1",
            "device_id": "pcap",
            "sensor_node_id": "local",
        },
        result=result,
    )) == []
    assert commands[0][1:3] == ["analyze", "--pcap"]
    kind, payload = protocol.read_transport_frame(io.BytesIO(process.stdin.getvalue()))
    assert kind == protocol.FRAME_ANALYSIS_PLAN
    assert protocol.decode_analysis_plan(payload) == resolved
    assert result["terminal_status"] == "complete"


def test_live_capture_reports_child_open_error_through_readiness_queue(
    monkeypatch, tmp_path
):
    import core.packet_engine.rust_capture as rust_capture

    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")

    class FailedProcess:
        def __init__(self):
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO(b"capture device open denied")
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 9
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: Path(binary))
    monkeypatch.setattr(
        rust_capture.subprocess,
        "Popen",
        lambda *args, **kwargs: FailedProcess(),
    )
    readiness = queue.Queue(maxsize=1)

    with pytest.raises(RuntimeError, match="capture device open denied"):
        start_rust_capture(
            "Ethernet",
            queue.Queue(),
            readiness_queue=readiness,
        )

    assert readiness.get_nowait() == {
        "status": "error",
        "message": "capture device open denied",
    }


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_replay_matches_python_l2_l4_events(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S"),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=5353),
    ]
    pcap = tmp_path / "parity.pcap"
    wrpcap(str(pcap), packets)
    rust_events = list(replay_events(pcap))
    python_events = [packet_to_event(packet) for packet in packets]

    assert len(rust_events) == len(python_events)
    for rust_event, python_event in zip(rust_events, python_events):
        assert (rust_event.src_ip, rust_event.dst_ip, rust_event.src_port, rust_event.dst_port) == (
            python_event.src_ip, python_event.dst_ip, python_event.src_port, python_event.dst_port,
        )


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_replay_supports_raw_ip_and_rejects_unsupported_link_types(tmp_path):
    raw_ip = tmp_path / "raw-ip.pcap"
    raw_writer = RawPcapWriter(str(raw_ip), linktype=228, sync=True)
    raw_writer.write(bytes(IP(src="10.40.0.1", dst="10.40.0.2") / UDP(sport=53000, dport=53)))
    raw_writer.close()

    events = list(replay_events(raw_ip))
    assert len(events) == 1
    assert (
        events[0].src_ip,
        events[0].dst_ip,
        events[0].src_port,
        events[0].dst_port,
        events[0].link_type,
    ) == ("10.40.0.1", "10.40.0.2", 53000, 53, "raw-ip")

    unsupported = tmp_path / "unsupported-80211.pcap"
    unsupported_writer = RawPcapWriter(str(unsupported), linktype=105, sync=True)
    unsupported_writer.write(
        b"\x02\x00\x00\x00"
        + bytes(IP(src="10.50.0.1", dst="10.50.0.2") / UDP(sport=1, dport=2))
    )
    unsupported_writer.close()

    with pytest.raises(RuntimeError, match=r"unsupported.*link type.*105"):
        list(replay_events(unsupported))
