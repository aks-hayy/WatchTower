import threading

import core.capture_sources.network as network_source_module
from core.capture_sources.base import CaptureDevice
from core.capture_sources import default_registry
from core.capture_sources.network import NetworkInterfaceSource
from core.cli.modules.forensics import ForensicsModule, console as forensics_console
from core.daemon.server import EngineManager
from core.forensics.base import BaseParser
from core.forensics.plugin_loader import PluginLoader
from core.packet_engine.schemas import CaptureOrigin, PacketEvent, PacketEventBatch
from core.packet_engine.flow_worker import _pending_stats_snapshot, _record_pending_stats
from core.storage.database import WatchtowerDB


def test_capture_contract_and_source_registry_are_versioned():
    origin = CaptureOrigin(
        session_id="session-1", source_type="network", device_id="Ethernet",
        backend="python",
    )
    event = PacketEvent(
        timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=443, protocol="TCP", size=60, flags="S",
        session_id=origin.session_id, interface=origin.device_id,
    )
    batch = PacketEventBatch(origin=origin, events=[event], sequence=7)

    assert batch.origin.api_version == 1
    assert batch.events[0].session_id == "session-1"
    devices = default_registry().list_devices()
    assert any(device.source_type == "network" for device in devices)
    assert any(device.source_type == "bluetooth" for device in devices)


def test_capture_sessions_and_reused_tuple_provenance_are_isolated(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    for session_id, backend in (("session-a", "python"), ("session-b", "rust")):
        db.create_capture_session(
            session_id=session_id, source_type="network", device_id="Ethernet",
            backend=backend, source="live_Ethernet",
        )
        db.upsert_flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=443,
            protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=1,
            byte_count=60, source=f"live_Ethernet#{session_id}",
            capture_session_id=session_id, capture_interface="Ethernet",
            capture_backend=backend, capture_type="network",
        )

    flows = db.get_flows(source="live", interface="Ethernet", limit=10)
    assert len(flows) == 2
    assert {item["capture_session_id"] for item in flows} == {"session-a", "session-b"}
    assert len(db.get_flows(source="live", capture_session_id="session-b")) == 1

    db.finish_capture_session("session-a", metrics={"received_packets": 10, "dropped_packets": 1})
    sessions = db.get_capture_sessions(interface="Ethernet")
    finished = next(item for item in sessions if item["id"] == "session-a")
    assert finished["status"] == "STOPPED"
    assert finished["received_packets"] == 10
    assert finished["dropped_packets"] == 1
    db.close()


def test_plugin_lifecycle_health_and_compatibility_defaults():
    loader = PluginLoader()
    loader.reset("pcap:test")
    health = loader.list_plugins()

    assert loader.get_parsers()
    assert loader.get_detectors()
    assert all(item["valid"] for item in health.values())
    assert all(isinstance(parser, BaseParser) for parser in loader.get_parsers())
    assert all(parser.supported_link_types for parser in loader.get_parsers())
    assert any("bluetooth-hci" in parser.supported_link_types for parser in loader.get_parsers())


def test_disconnected_network_interface_is_not_available(monkeypatch):
    class Interface:
        name = "Wi-Fi"
        description = "Test wireless adapter"
        ip = "169.254.1.10"

    class Stats:
        isup = False

    monkeypatch.setattr(
        network_source_module.psutil, "net_if_stats", lambda: {"Wi-Fi": Stats()}
    )

    device = NetworkInterfaceSource._to_device(Interface())

    assert not device.available
    assert "disconnected or disabled" in device.unavailable_reason


def test_daemon_rejects_disconnected_interface_before_process_start(monkeypatch):
    unavailable = CaptureDevice(
        source_type="network", device_id="Wi-Fi", name="Wi-Fi",
        available=False, unavailable_reason="Wi-Fi is disconnected",
    )
    monkeypatch.setattr(NetworkInterfaceSource, "get_device", lambda self, value: unavailable)
    manager = object.__new__(EngineManager)
    manager.engines = {}
    manager.lock = threading.Lock()

    result = manager.start_engine("Wi-Fi", backend="python")

    assert result == {"status": "error", "message": "Wi-Fi is disconnected"}
    assert manager.engines == {}


def test_status_stats_are_scoped_to_active_interfaces_only():
    class Accumulator:
        def get_today(self, source):
            values = {
                "live_Wi-Fi": {"total_flows": 3, "total_packets": 12, "total_bytes": 4096},
                "live_Ethernet": {"total_flows": 99, "total_packets": 999, "total_bytes": 9999},
            }
            return values[source]

    class Database:
        def get_today_live_interfaces(self):
            return ["Ethernet", "Wi-Fi"]

    module = object.__new__(ForensicsModule)
    module.options = {"interfaces": ["Wi-Fi"]}
    module.acc = Accumulator()
    module.db = Database()

    with forensics_console.capture() as capture:
        module.show_stats()
    output = capture.get()

    assert "Wi-Fi" in output
    assert "Ethernet" not in output
    assert "12" in output


def test_live_stats_snapshots_count_packet_deltas_once():
    pending = {}
    origin = CaptureOrigin(
        session_id="session-1", source_type="network", device_id="Ethernet", backend="python"
    )
    for timestamp, size in ((1.0, 60), (2.0, 100)):
        event = PacketEvent(
            timestamp=timestamp, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=50000, dst_port=443, protocol="TCP", size=size, flags="A",
            interface="Ethernet", session_id=origin.session_id,
        )
        _record_pending_stats(pending, event)

    first = _pending_stats_snapshot(pending, "Ethernet", 0.0, 5.0, total_flows=1)
    assert first.total_packets == 2
    assert first.total_bytes == 160
    assert first.protocol_distribution == {"TCP": 2}

    pending.pop("Ethernet")
    second = _pending_stats_snapshot(pending, "Ethernet", 5.0, 10.0, total_flows=1)
    assert second.total_packets == 0
    assert second.total_bytes == 0
