from pathlib import Path

import pytest
import scapy.all as scapy

from core.capture_sources import bluetooth
from core.forensics.engine import ForensicsEngine
from core.forensics.stream_spool import SegmentSpool
from core.packet_engine.schemas import CaptureOrigin


def _pcap(path: Path, count=100):
    packets = []
    for index in range(count):
        packet = (scapy.Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:03")/
                  scapy.IP(src="10.0.0.2", dst="10.0.0.3")/
                  scapy.TCP(sport=12345, dport=8080, seq=index * 4)/scapy.Raw(b"data"))
        packet.time = 1.0 + index
        packets.append(packet)
    scapy.wrpcap(str(path), packets)
    return path


def test_streaming_and_memory_flow_parity(tmp_path):
    pcap = _pcap(tmp_path / "fixture.pcap")
    memory = ForensicsEngine(data_dir=tmp_path / "memory", silent=True).analyze_pcap(str(pcap), mode="memory")
    streaming_engine = ForensicsEngine(data_dir=tmp_path / "streaming", silent=True)
    streaming = streaming_engine.analyze_pcap(str(pcap), mode="streaming")
    assert memory.summary["total_flows"] == streaming.summary["total_flows"] == 1
    assert memory.summary["total_entities"] == streaming.summary["total_entities"]
    assert streaming.status == "COMPLETE"
    assert streaming.bytes_processed == streaming.total_bytes
    flow_id = ("10.0.0.2", "10.0.0.3", 12345, 8080, "TCP")
    assert streaming_engine.load_stream(flow_id, streaming)["to_server"] == b"data" * 100


def test_cancelled_and_corrupt_pcaps_are_not_complete(tmp_path):
    pcap = _pcap(tmp_path / "cancel.pcap")
    calls = {"count": 0}
    def cancelled():
        calls["count"] += 1
        return calls["count"] > 10
    engine = ForensicsEngine(data_dir=tmp_path / "cancelled", silent=True)
    report = engine.analyze_pcap(str(pcap), mode="streaming", cancel_event=cancelled)
    assert report.status == "CANCELLED"
    assert engine.db.get_reports()[0]["status"] == "CANCELLED"

    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"not a capture")
    failed_engine = ForensicsEngine(data_dir=tmp_path / "failed", silent=True)
    with pytest.raises(ValueError, match="analysis failed"):
        failed_engine.analyze_pcap(str(corrupt), mode="streaming")
    assert failed_engine.db.get_reports()[0]["status"] == "FAILED"


def test_segment_spool_bounds_and_cleanup(tmp_path):
    path = tmp_path / "segments.sqlite"
    spool = SegmentSpool(path, max_bytes=8, max_segments=2)
    flow_id = ("10.0.0.1", "10.0.0.2", 1, 2, "TCP")
    assert spool.append(flow_id, "to_server", 1, b"123456", 1.0)
    assert spool.append(flow_id, "to_server", 7, b"7890", 2.0)
    assert not spool.append(flow_id, "to_server", 11, b"x", 3.0)
    assert spool.truncated_bytes == 3
    assert sum(len(item["payload"]) for item in spool.load(flow_id)["to_server"]) == 8
    spool.cleanup()
    assert not path.exists()


def test_bluetooth_windows_unavailable_and_hci_fixture(monkeypatch):
    monkeypatch.setattr(bluetooth.sys, "platform", "win32")
    device = list(bluetooth.BluetoothHCISource().list_devices())[0]
    assert not device.available
    assert "unavailable on Windows" in device.unavailable_reason

    from scapy.layers.bluetooth import (
        HCI_Event_Hdr, HCI_Event_LE_Meta, HCI_Hdr, HCI_LE_Meta_Advertising_Report,
    )
    packet = HCI_Hdr()/HCI_Event_Hdr()/HCI_Event_LE_Meta()/HCI_LE_Meta_Advertising_Report(
        addr="aa:bb:cc:dd:ee:ff", rssi=-50,
    )
    packet.time = 4.0
    origin = CaptureOrigin("session", "bluetooth", "hci0", "python", "bluetooth-hci")
    observation = bluetooth.parse_hci_observation(packet, origin)
    assert observation.observation_type == "advertisement"
    assert observation.subject == "aa:bb:cc:dd:ee:ff"
    assert observation.metadata["rssi"] == -50
