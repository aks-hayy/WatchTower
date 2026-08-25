import time

import pytest

import core.detection.behavioral_state as behavioral_state
from core.forensics.plugin_loader import PluginLoader
from core.forensics.plugins.detectors.beaconing_detector import BeaconingDetector
from core.forensics.plugins.detectors.stateful_behavior_detector import UnifiedStatefulBehaviorDetector
from core.packet_engine.conversations import (
    ConversationDeltaV2,
    ConversationKey,
    ConversationTracker,
)
from core.packet_engine.schemas import FlowAggregate, PacketEvent


def tcp_flow(src, dst, sport, dport, seen, established=False, novelty=False):
    flow = FlowAggregate((src, dst, sport, dport, "TCP"), 0.0, seen)
    flow.packet_count = 1
    flow.byte_count = 60
    flow.tcp_syn_count = 1
    flow.l7_metadata = {
        "conversation_established": established,
        "conversation_syn_ack_count": 1 if established else 0,
        "peer_novelty": novelty,
    }
    return flow


def conversation_delta(
    timestamp,
    generation,
    *,
    dst="198.51.100.77",
    dport=4444,
    to_initiator_packets=0,
):
    initiator = ("10.0.0.5", 56000)
    responder = (dst, dport)
    return ConversationDeltaV2(
        contract_version=2,
        key=ConversationKey(
            sensor_node_id="node-a",
            source="pcap:performance",
            session_id="session-performance",
            interface="offline",
            protocol="UDP",
            endpoint_a=initiator,
            endpoint_b=responder,
        ),
        generation=generation,
        event_time=float(timestamp),
        first_seen=0.0,
        initiator=initiator,
        responder=responder,
        direction="to_responder",
        packet_delta=1,
        byte_delta=75,
        syn_delta=0,
        syn_ack_delta=0,
        rst_delta=0,
        to_responder_packets=generation,
        to_responder_bytes=generation * 75,
        to_initiator_packets=to_initiator_packets,
        to_initiator_bytes=to_initiator_packets * 75,
        syn_count=0,
        syn_ack_count=0,
        rst_count=0,
        established=False,
        application={},
        backend="rust",
        source_type="network",
    )


def tcp_conversation_delta(
    tracker,
    timestamp,
    *,
    src="10.0.0.5",
    dst="10.0.0.20",
    sport=56000,
    dport=443,
    flags="S",
    application=None,
):
    _metadata, delta = tracker.update_with_delta(PacketEvent(
        timestamp=float(timestamp),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol="TCP",
        size=60,
        flags=flags,
        l7_info=dict(application or {}),
        interface="Ethernet",
        session_id="session-attempts",
    ))
    return delta


def test_vertical_scan_does_not_mix_unrelated_traffic():
    detector = UnifiedStatefulBehaviorDetector()
    alerts = []
    for index in range(19):
        alerts.extend(detector.detect(flow=tcp_flow(
            "10.0.0.5", "10.0.0.20", 50000 + index, 20000 + index, float(index),
        )))
    for index in range(30):
        alerts.extend(detector.detect(flow=tcp_flow(
            "10.0.0.5", f"34.100.0.{index + 1}", 51000 + index, 443, 20.0 + index, established=True,
        )))
    assert not any(alert.type in {"PORT_SCAN", "HORIZONTAL_SCAN"} for alert in alerts)

    alerts.extend(detector.detect(flow=tcp_flow(
        "10.0.0.5", "10.0.0.20", 52000, 20019, 50.0,
    )))
    vertical = [alert for alert in alerts if alert.type == "PORT_SCAN"]
    assert len(vertical) == 1
    assert vertical[0].evidence["scan_type"] == "vertical"


def test_horizontal_scan_and_lateral_movement_are_separate_findings():
    scanner = UnifiedStatefulBehaviorDetector()
    alerts = []
    for index in range(20):
        alerts.extend(scanner.detect(flow=tcp_flow(
            "10.0.0.5", f"10.0.1.{index + 1}", 50000 + index, 8080, float(index),
        )))
    assert any(alert.type == "HORIZONTAL_SCAN" for alert in alerts)

    lateral = UnifiedStatefulBehaviorDetector()
    alerts = []
    for index in range(5):
        alerts.extend(lateral.detect(flow=tcp_flow(
            "10.0.0.5", f"10.0.2.{index + 1}", 53000 + index, 445, float(index), novelty=True,
        )))
    finding = next(alert for alert in alerts if alert.type == "LATERAL_MOVEMENT")
    assert finding.evidence["destination_count"] == 5
    assert finding.evidence["corroborators"] == ["peer_novelty"]


def test_cold_start_exfiltration_is_detected_but_capped_medium():
    detector = UnifiedStatefulBehaviorDetector()
    flow = FlowAggregate(("10.0.0.5", "8.8.8.8", 55000, 443, "TCP"), 0.0, 300.0)
    flow.byte_count = 105 * 1024 * 1024
    flow.l7_metadata = {"reverse_byte_count": 1024 * 1024, "peer_novelty": True}
    alert = next(alert for alert in detector.detect(flow=flow) if alert.type == "EXFILTRATION")
    assert alert.severity == "MEDIUM"
    assert alert.evidence["cold_start"] is True


def test_syn_flood_uses_bounded_constant_time_second_buckets():
    detector = UnifiedStatefulBehaviorDetector()
    tracker = ConversationTracker()
    alerts = []
    started = time.perf_counter()
    for second in range(1, 4):
        for index in range(1000):
            _metadata, delta = tracker.update_with_delta(PacketEvent(
                timestamp=second + index / 1000,
                src_ip="10.0.0.5",
                dst_ip="10.0.0.20",
                src_port=55000,
                dst_port=443,
                protocol="TCP",
                size=60,
                flags="S",
                interface="Ethernet",
                session_id="session-syn",
            ))
            alerts.extend(detector.detect(conversation=delta))
    assert [alert.type for alert in alerts] == ["SYN_FLOOD"]
    assert max(len(buckets) for buckets in detector.engine.syn_buckets.values()) <= 4
    assert time.perf_counter() - started < 5.0


def test_ip_classification_reuses_a_bounded_process_cache(monkeypatch):
    original = behavioral_state.ip_address
    calls = 0

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    cache_functions = tuple(
        function
        for function_name in ("_internal", "_address")
        if (function := getattr(behavioral_state, function_name, None)) is not None
    )
    for function in cache_functions:
        clear_cache = getattr(function, "cache_clear", None)
        if clear_cache:
            clear_cache()
    monkeypatch.setattr(behavioral_state, "ip_address", counted)

    assert all(behavioral_state._internal("192.168.0.1") for _ in range(64))
    for index in range(behavioral_state.StatefulBehaviorEngine.MAX_STATE_KEYS + 64):
        behavioral_state._internal(
            f"10.{index // (256 * 256)}.{(index // 256) % 256}.{index % 256}"
        )

    cache_info = getattr(behavioral_state._internal, "cache_info", lambda: None)()
    for function in cache_functions:
        clear_cache = getattr(function, "cache_clear", None)
        if clear_cache:
            clear_cache()
    assert calls == behavioral_state.StatefulBehaviorEngine.MAX_STATE_KEYS + 65
    assert cache_info is not None
    assert cache_info.currsize <= behavioral_state.StatefulBehaviorEngine.MAX_STATE_KEYS


def test_beacon_statistics_are_incremental_not_full_history_rescans(monkeypatch):
    detector = UnifiedStatefulBehaviorDetector()

    def reject_full_rescan(_values):
        raise AssertionError("beacon intervals were rescanned")

    monkeypatch.setattr(behavioral_state.statistics, "mean", reject_full_rescan)
    monkeypatch.setattr(behavioral_state.statistics, "stdev", reject_full_rescan)

    alerts = []
    for generation in range(1, 21):
        alerts.extend(detector.detect(conversation=conversation_delta(
            timestamp=(generation - 1) * 10.0,
            generation=generation,
        )))

    assert [alert.type for alert in alerts] == ["BEACONING"]
    assert alerts[0].evidence["avg_interval"] == 10.0
    assert alerts[0].evidence["coefficient_of_variation"] == 0.0
    assert alerts[0].evidence["sample_count"] == 20


def test_terminal_flow_samples_preserve_beacon_detection():
    detector = UnifiedStatefulBehaviorDetector()
    arrivals = [float(index * 10) for index in range(20)]
    flow = FlowAggregate(
        ("10.45.0.10", "198.51.100.45", 56040, 8443, "TCP"),
        arrivals[0], arrivals[-1],
    )
    for timestamp in arrivals:
        flow.update(100, timestamp)
    flow.l7_metadata.update({
        "peer_novelty": True,
        "reverse_packet_count": 0,
    })

    alerts = detector.detect(flow=flow)

    assert [alert.type for alert in alerts] == ["BEACONING"]


def test_beacon_statistics_remain_exact_across_capacity_eviction():
    engine = behavioral_state.StatefulBehaviorEngine()
    conversation_id = ("capacity",)

    for timestamp in range(600):
        events, totals = engine._append_beacon_event(
            conversation_id,
            float(timestamp),
            75,
        )

    assert len(events) == 512
    assert events[0][0] == 88.0
    assert events[-1][0] == 599.0
    assert totals[0] == pytest.approx(511.0)
    assert totals[1] == pytest.approx(511.0)


def test_beacon_statistics_remove_only_intervals_outside_time_window():
    engine = behavioral_state.StatefulBehaviorEngine()
    conversation_id = ("time",)

    for timestamp in (0.0, 100.0, 200.0, 7300.0):
        events, totals = engine._append_beacon_event(
            conversation_id,
            timestamp,
            75,
        )

    assert list(events) == [
        (100.0, 75),
        (200.0, 75),
        (7300.0, 75),
    ]
    assert totals[0] == pytest.approx(7200.0)
    assert totals[1] == pytest.approx(50_420_000.0)


def test_beacon_statistics_track_variable_intervals():
    engine = behavioral_state.StatefulBehaviorEngine()
    conversation_id = ("variable",)

    for timestamp in (0.0, 1.5, 4.0, 9.25, 20.0):
        events, totals = engine._append_beacon_event(
            conversation_id,
            timestamp,
            75,
        )

    assert len(events) == 5
    assert totals[0] == pytest.approx(20.0)
    assert totals[1] == pytest.approx(151.625)


def test_beacon_statistics_reset_clears_events_and_incremental_totals():
    engine = behavioral_state.StatefulBehaviorEngine()
    engine._append_beacon_event(("reset",), 1.0, 75)
    engine._append_beacon_event(("reset",), 4.0, 75)

    engine.reset()

    assert engine.beacon_events == {}
    assert engine.beacon_interval_totals == {}


def test_alert_cooldown_state_is_deterministically_bounded():
    engine = behavioral_state.StatefulBehaviorEngine()
    total = engine.MAX_STATE_KEYS + 32

    for index in range(total):
        assert engine._emit_once(
            ("source", f"{index:05d}"),
            now=100.0,
            cooldown=3600.0,
        )

    expected_keys = {
        ("source", f"{index:05d}")
        for index in range(32, total)
    }
    assert len(engine.last_alert) == engine.MAX_STATE_KEYS
    assert set(engine.last_alert) == expected_keys
    assert not engine._emit_once(
        ("source", f"{total - 1:05d}"),
        now=101.0,
        cooldown=3600.0,
    )


def test_irrelevant_conversation_does_not_scan_attempt_state():
    detector = UnifiedStatefulBehaviorDetector()

    class CountingAttempts(dict):
        scans = 0

        def items(self):
            self.scans += 1
            return super().items()

        def values(self):
            self.scans += 1
            return super().values()

    attempts = CountingAttempts()
    detector.engine.attempts = attempts

    assert detector.detect(conversation=conversation_delta(
        timestamp=10.0,
        generation=1,
    )) == []
    assert attempts.scans == 0


def test_successful_handshakes_update_attempt_outcomes_before_scan_threshold():
    detector = UnifiedStatefulBehaviorDetector()
    tracker = ConversationTracker()
    alerts = []

    for index in range(20):
        sport = 56000 + index
        dport = 20000 + index
        alerts.extend(detector.detect(conversation=tcp_conversation_delta(
            tracker,
            index * 2,
            sport=sport,
            dport=dport,
        )))
        alerts.extend(detector.detect(conversation=tcp_conversation_delta(
            tracker,
            index * 2 + 1,
            src="10.0.0.20",
            dst="10.0.0.5",
            sport=dport,
            dport=sport,
            flags="SA",
        )))

    assert not any(alert.type == "PORT_SCAN" for alert in alerts)
    assert len(detector.engine.attempts) == 20
    assert all(
        attempt["established"]
        for attempt in detector.engine.attempts.values()
    )


def test_existing_attempt_traversal_runs_only_when_late_evidence_changes_state():
    detector = UnifiedStatefulBehaviorDetector()
    tracker = ConversationTracker()
    detector.detect(conversation=tcp_conversation_delta(tracker, 1.0))

    class CountingAttempts(dict):
        scans = 0

        def items(self):
            self.scans += 1
            return super().items()

        def values(self):
            self.scans += 1
            return super().values()

    attempts = CountingAttempts(detector.engine.attempts)
    detector.engine.attempts = attempts

    assert detector.detect(conversation=tcp_conversation_delta(
        tracker,
        2.0,
        flags="A",
    )) == []
    assert attempts.scans == 0

    assert detector.detect(conversation=tcp_conversation_delta(
        tracker,
        3.0,
        flags="A",
        application={"role_policy_violation": True},
    )) == []
    assert attempts.scans > 0
    assert next(iter(attempts.values()))["role_policy"] is True


def test_late_role_evidence_rechecks_successful_admin_fanout():
    detector = UnifiedStatefulBehaviorDetector()
    tracker = ConversationTracker()
    source = "10.0.0.5"
    targets = [f"10.0.2.{index}" for index in range(1, 6)]
    detector.engine.peer_seen.update((source, target) for target in targets)
    alerts = []

    for index, target in enumerate(targets):
        sport = 57000 + index
        alerts.extend(detector.detect(conversation=tcp_conversation_delta(
            tracker,
            index * 3,
            src=source,
            dst=target,
            sport=sport,
            dport=445,
        )))
        alerts.extend(detector.detect(conversation=tcp_conversation_delta(
            tracker,
            index * 3 + 1,
            src=target,
            dst=source,
            sport=445,
            dport=sport,
            flags="SA",
        )))

    assert not any(alert.type == "LATERAL_MOVEMENT" for alert in alerts)
    alerts.extend(detector.detect(conversation=tcp_conversation_delta(
        tracker,
        20.0,
        src=source,
        dst=targets[-1],
        sport=57004,
        dport=445,
        flags="A",
        application={"role_policy_violation": True},
    )))

    lateral = [alert for alert in alerts if alert.type == "LATERAL_MOVEMENT"]
    assert len(lateral) == 1
    assert lateral[0].evidence["corroborators"] == ["role_policy"]
    assert all(
        attempt["established"]
        for attempt in detector.engine.attempts.values()
    )


def test_low_volume_conversations_reuse_destination_classification(monkeypatch):
    detector = UnifiedStatefulBehaviorDetector()
    original = behavioral_state.ip_address
    calls = 0

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    for function_name in ("_internal", "_address"):
        clear_cache = getattr(
            getattr(behavioral_state, function_name, None), "cache_clear", None
        )
        if clear_cache:
            clear_cache()
    monkeypatch.setattr(behavioral_state, "ip_address", counted)

    for generation in range(1, 21):
        assert detector.detect(conversation=conversation_delta(
            timestamp=float(generation),
            generation=generation,
            dst="8.8.8.8",
            dport=443,
            to_initiator_packets=1,
        )) == []

    assert calls <= 2


def test_beacon_requires_independent_corroboration_and_excludes_control_traffic():
    arrivals = [float(index * 6) for index in range(25)]
    detector = BeaconingDetector()

    multicast = FlowAggregate(("10.0.0.1", "224.0.0.22", 0, 0, "OTHER"), 0.0, 144.0)
    multicast.arrival_times = arrivals
    multicast.packet_sizes = [64] * 25
    multicast.packet_count = 25
    assert detector.detect(flow=multicast, arrival_times=arrivals) == []

    heartbeat = FlowAggregate(("10.0.0.10", "10.0.0.5", 8009, 55000, "TCP"), 0.0, 144.0)
    heartbeat.arrival_times = arrivals
    heartbeat.packet_sizes = [100] * 25
    heartbeat.packet_count = 25
    heartbeat.l7_metadata = {"reverse_packet_count": 25, "conversation_established": True}
    assert detector.detect(flow=heartbeat, arrival_times=arrivals) == []

    beacon = FlowAggregate(("10.0.0.5", "198.51.100.77", 56000, 4444, "UDP"), 0.0, 144.0)
    beacon.arrival_times = arrivals
    beacon.packet_sizes = [75] * 25
    beacon.packet_count = 25
    beacon.l7_metadata = {"reverse_packet_count": 0}
    alert = detector.detect(flow=beacon, arrival_times=arrivals)[0]
    assert alert.severity == "MEDIUM"
    assert alert.evidence["corroborators"] == ["protocol_semantic_anomaly", "response_anomaly"]


def test_plugin_loader_has_one_enabled_stateful_behavior_family():
    detectors = PluginLoader().get_detectors()
    enabled = [
        detector for detector in detectors
        if detector.enabled and detector.manifest and detector.manifest.detector_id == "watchtower.stateful.host"
    ]
    assert [detector.name for detector in enabled] == ["Unified Stateful Behavior Detector"]
