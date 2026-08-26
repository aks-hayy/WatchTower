# core/packet_engine/flow_worker.py

import sys
import os
import logging
import queue as queue_module
from concurrent.futures import ThreadPoolExecutor

# Ensure local imports work when spawned in a new process on Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import time
from collections import defaultdict
from core.packet_engine.schemas import FlowAggregate, WindowSnapshot, AlertRecord, HardwareObservation
from core.packet_engine.conversations import ConversationTracker
from core.detection.streams import LiveTCPStreamTracker
from core.packet_engine.persistence import DailyAccumulator
from core.packet_engine.analytics import AnalyticsEngine
from core.forensics.engine import ForensicsEngine
from core.storage.database import WatchtowerDB
from core.constants import FLOW_TIMEOUT, EVIDENCE_TRIGGER
import math
import psutil
from scapy.all import wrpcap, Ether, IP, TCP, UDP
from core.packet_engine.utils import get_geoip_info
from core.endpoint.attribution import EndpointAttributor, legacy_process_label
from core.packet_engine.processors import StatAggregator, SecurityScorer, AlertManager
from core.detection.payload import application_payload

logger = logging.getLogger("flow_worker")

# Deep Scapy parsing and plugin dispatch are bounded for live capture. Flow
# and conversation accounting still consume every packet. These protocols
# need continuous parsing because their evidence is distributed across
# datagrams; other payloads are sampled and re-opened for direct markers.
LIVE_FORENSIC_SAMPLE_LIMIT = 16
LIVE_FORENSIC_CONTROL_PORTS = frozenset({
    53, 67, 68, 88, 123, 137, 138, 161, 162, 389, 445, 546, 547,
    1900, 5353, 5355,
})
LIVE_FORENSIC_MARKERS = (
    b"user ", b"pass ", b"password", b"authorization", b"ntlmssp",
    b"ssh-", b"get ", b"post ", b"http/", b"\x16\x03", b"mqtt",
    b"modbus", b"coap", b"mz", b"authentication failed", b"login failed",
)


def _should_deep_inspect_live_packet(event, flow) -> bool:
    """Decide whether a live frame warrants Scapy/plugin processing."""
    if not event.raw:
        return False
    protocol = str(event.protocol or "").upper()
    if protocol in {"ARP", "ICMP", "ICMPV6", "OTHER"}:
        return True
    ports = {int(event.src_port or 0), int(event.dst_port or 0)}
    if ports & LIVE_FORENSIC_CONTROL_PORTS:
        return True
    if flow is None or flow.live_forensics_payloads < LIVE_FORENSIC_SAMPLE_LIMIT:
        return True
    # Rust events retain the complete frame. A bounded byte search lets a
    # later suspicious marker re-open inspection without decoding every
    # ordinary encrypted/data segment with Scapy.
    sample = bytes(event.raw[:64 * 1024]).lower()
    return any(marker in sample for marker in LIVE_FORENSIC_MARKERS)


def _record_baseline_event(windows, event):
    bucket = int(float(event.timestamp) // 300) * 300
    key = (event.interface, bucket, event.src_ip)
    values = windows.setdefault(key, {
        "outbound_bytes": 0.0, "packet_count": 0.0, "flow_keys": set(),
        "peers": set(), "ports": set(), "syn_count": 0.0, "syn_ack_count": 0.0,
        "dns_queries": 0.0, "interval_count": 0, "interval_mean": 0.0,
        "interval_m2": 0.0, "last_timestamp": None, "generated_probe": False,
    })
    values["outbound_bytes"] += float(event.size or 0)
    values["packet_count"] += 1.0
    if len(values["flow_keys"]) < 4096:
        values["flow_keys"].add((event.dst_ip, event.dst_port, event.protocol))
    if len(values["peers"]) < 4096:
        values["peers"].add(event.dst_ip)
    if len(values["ports"]) < 4096:
        values["ports"].add(int(event.dst_port or 0))
    flags = str(event.flags or "")
    if "S" in flags and "A" not in flags:
        values["syn_count"] += 1.0
    if "S" in flags and "A" in flags:
        values["syn_ack_count"] += 1.0
    if int(event.dst_port or 0) == 53:
        values["dns_queries"] += 1.0
    previous = values["last_timestamp"]
    if previous is not None:
        interval = max(0.0, float(event.timestamp) - previous)
        values["interval_count"] += 1
        delta = interval - values["interval_mean"]
        values["interval_mean"] += delta / values["interval_count"]
        values["interval_m2"] += delta * (interval - values["interval_mean"])
    values["last_timestamp"] = float(event.timestamp)
    values["generated_probe"] = values["generated_probe"] or (event.l7_info or {}).get("generated_by") == "WatchTower"


def _flush_baseline_windows(db, windows, current_time, source_for_interface):
    from core.detection.baseline import learning_allowed

    current_bucket = int(float(current_time) // 300) * 300
    completed = [key for key in windows if key[1] < current_bucket]
    for interface, bucket, subject in completed:
        values = windows.pop((interface, bucket, subject))
        findings = db.get_detection_findings(subject=subject, source=source_for_interface(interface), limit=100)
        confirmed_threat = any(
            item.get("category") == "THREAT" and bucket <= float(item.get("last_seen") or 0) < bucket + 300
            for item in findings
        )
        if not learning_allowed(generated_probe=values["generated_probe"], confirmed_threat=confirmed_threat):
            continue
        variance = values["interval_m2"] / max(1, values["interval_count"] - 1)
        mean = values["interval_mean"]
        features = {
            "outbound_bytes": values["outbound_bytes"],
            "packet_count": values["packet_count"],
            "flow_count": float(len(values["flow_keys"])),
            "peer_cardinality": float(len(values["peers"])),
            "port_cardinality": float(len(values["ports"])),
            "syn_response_ratio": values["syn_ack_count"] / max(1.0, values["syn_count"]),
            "dns_queries": values["dns_queries"],
            "request_periodicity": 0.0 if mean <= 0 else 1.0 - min(1.0, math.sqrt(max(0.0, variance)) / mean),
        }
        source = source_for_interface(interface)
        for feature, value in features.items():
            db.update_feature_baseline(subject, feature, value, bucket + 300, source=source, interface=interface)


def _record_pending_stats(pending, event):
    stats = pending.setdefault(event.interface, {
        "packets": 0, "bytes": 0, "protocols": defaultdict(int),
        "ports": defaultdict(int), "talkers": defaultdict(int), "timeline": {},
    })
    stats["packets"] += 1
    stats["bytes"] += int(event.size)
    stats["protocols"][event.protocol] += 1
    if event.dst_port:
        stats["ports"][int(event.dst_port)] += 1
    stats["talkers"][event.src_ip] += int(event.size)
    bucket = int(float(event.timestamp) // 60) * 60
    timeline = stats["timeline"].setdefault(bucket, {"packets": 0, "bytes": 0})
    timeline["packets"] += 1
    timeline["bytes"] += int(event.size)


def _pending_stats_snapshot(pending, interface, window_start, window_end, total_flows):
    stats = pending.get(interface) or {
        "packets": 0, "bytes": 0, "protocols": {}, "ports": {}, "talkers": {}, "timeline": {},
    }
    return WindowSnapshot(
        window_start=window_start, window_end=window_end, total_flows=total_flows,
        total_packets=stats["packets"], total_bytes=stats["bytes"],
        protocol_distribution=dict(stats["protocols"]), protocol_entropy=0.0,
        port_distribution=dict(stats["ports"]), top_talkers=dict(stats["talkers"]),
        traffic_timeline=dict(stats["timeline"]), interface=interface,
    )


def cleanup_expired_flows(flow_table, current_time):
    expired = [
        flow_id
        for flow_id, flow in flow_table.items()
        if current_time - flow.last_seen > FLOW_TIMEOUT
    ]
    for flow_id in expired:
        del flow_table[flow_id]


def enforce_memory_limit(flow_table, max_size):
    if len(flow_table) <= max_size:
        return

    # Batch removal of oldest flows (O(N log N) instead of O(M*N))
    num_to_remove = len(flow_table) - max_size
    sorted_items = sorted(flow_table.items(), key=lambda x: x[1].last_seen)

    for i in range(num_to_remove):
        del flow_table[sorted_items[i][0]]


def build_snapshot(flow_table, window_start, window_end, analytics_engine=None, forensics_engine=None,
                   behavioral_engine=None, source=None, capture_interface=None,
                   capture_session_id=None, capture_backend=None, detection_flow_ids=None,
                   baseline_cache=None):
    stats = StatAggregator()
    scorer = SecurityScorer(analytics_engine, forensics_engine, behavioral_engine)
    alert_mgr = AlertManager()
    alert_mgr.behavioral = behavioral_engine
    evidence_tasks = []
    # Behavioral baselines are keyed by subject, not by directional flow.
    # Reusing the lookup for a snapshot avoids one SQLite query per flow during
    # busy-window refreshes while preserving the same subject-scoped result.
    baseline_cache = baseline_cache if baseline_cache is not None else {}
    
    active_flows = [f for f in flow_table.values() if f.last_seen >= window_start]
    
    total_packets = 0
    total_bytes = 0
    max_behavior_score = 0.0

    dirty_ids = set(detection_flow_ids) if detection_flow_ids is not None else None
    for f in active_flows:
        total_packets += f.packet_count
        total_bytes += f.byte_count
        
        # 1. Aggregate Stats
        stats.aggregate(f, window_start)
        
        # Attach context, never direct risk bonuses, before detector evaluation.
        should_detect = dirty_ids is None or f.flow_id in dirty_ids
        if should_detect and behavioral_engine is not None:
            f.l7_metadata["peer_novelty"] = bool(f.l7_metadata.get("peer_novelty")) or (
                behavioral_engine.check_peer_anomaly(f.flow_id[0], f.flow_id[1]) > 0
            )
        if should_detect and forensics_engine is not None and hasattr(forensics_engine.db, "get_feature_baselines"):
            subject = str(f.flow_id[0])
            if subject not in baseline_cache:
                baseline_cache[subject] = forensics_engine.db.get_feature_baselines(
                    subject=subject, feature="outbound_bytes",
                )
            baselines = baseline_cache[subject]
            mature = next((item for item in baselines if item["maturity"]["mature"]), None)
            if mature:
                f.l7_metadata["outbound_bytes_p99"] = float(mature.get("p99") or 0.0)

        # 2. Compute Scores
        if should_detect and forensics_engine is not None and source:
            forensic_alerts = forensics_engine.process_live_flow(
                f, source=source, capture_interface=capture_interface,
                capture_session_id=capture_session_id, capture_backend=capture_backend,
            )
            b_score = analytics_engine.compute_behavior_score(f) if analytics_engine else 0.0
            t_score = sum(alert.score for alert in forensic_alerts)
        elif should_detect:
            b_score, t_score, forensic_alerts = scorer.score_flow(f)
        else:
            b_score, t_score, forensic_alerts = 0.0, 0.0, []
        final_score = b_score + t_score
        max_behavior_score = max(max_behavior_score, final_score)
        
        # 3. Handle Alerts
        # Detector findings are already persisted by process_live_flow. Snapshot
        # persistence must not emit a second aggregate or forensic alert.
        if not source:
            alert_mgr.process_alerts(f, b_score, t_score, forensic_alerts)
        
        # 4. Evidence Triggers (Asynchronous)
        if final_score > EVIDENCE_TRIGGER and hasattr(f, "raw_packets") and f.raw_packets:
            pcap_path = os.path.join("data/forensics", f"evidence_{f.flow_id[0]}_{f.flow_id[1]}_{int(time.time())}.pcap")
            if "evidence_pcap" not in f.l7_metadata:
                evidence_tasks.append({"type": "WRITE_PCAP", "path": pcap_path, "packets": list(f.raw_packets)})
                f.l7_metadata["evidence_pcap"] = pcap_path

    return WindowSnapshot(
        window_start=window_start,
        window_end=window_end,
        total_flows=len(active_flows),
        total_packets=total_packets,
        total_bytes=total_bytes,
        protocol_distribution=dict(stats.protocol_distribution),
        protocol_entropy=stats.compute_entropy(),
        behavior_score=max_behavior_score,
        final_score=max_behavior_score,
        port_distribution=dict(stats.port_distribution),
        top_talkers=dict(stats.top_talkers),
        traffic_timeline=dict(sorted(stats.timeline_buckets.items())),
        alerts=[] if source else alert_mgr.alerts[:10]
    ), evidence_tasks


def compute_entropy(distribution):
    total = sum(distribution.values())
    if total == 0:
        return 0

    entropy = 0
    for count in distribution.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _increment_metric(metrics, key, amount=1):
    if metrics is None or key not in metrics:
        return
    value = metrics[key]
    with value.get_lock():
        value.value += amount


def _record_queue_health(metrics, packet_queue, event):
    if metrics is None:
        return
    lag_ms = max(0.0, (time.time() - float(event.timestamp or time.time())) * 1000.0)
    _increment_metric(metrics, "queue_lag_total_ms", lag_ms)
    _increment_metric(metrics, "queue_lag_samples", 1)
    if "queue_lag_current_ms" in metrics:
        metrics["queue_lag_current_ms"].value = lag_ms
    if "queue_lag_max_ms" in metrics:
        with metrics["queue_lag_max_ms"].get_lock():
            metrics["queue_lag_max_ms"].value = max(metrics["queue_lag_max_ms"].value, lag_ms)
    try:
        depth = max(0, int(packet_queue.qsize()))
    except (NotImplementedError, OSError):
        depth = 0
    if "queue_depth" in metrics:
        metrics["queue_depth"].value = depth
    if "queue_depth_high_watermark" in metrics:
        with metrics["queue_depth_high_watermark"].get_lock():
            metrics["queue_depth_high_watermark"].value = max(
                metrics["queue_depth_high_watermark"].value, depth
            )


def flow_worker(packet_queue, snapshot_queue, config, control_queue=None, evidence_queue=None,
                capture_origin=None, metrics=None, worker_done_event=None,
                acknowledgement_queue=None):
    if config.silent:
        log_path = os.path.join(config.data_dir, "engine.log")
        log_file = open(log_path, "a", buffering=1)
        sys.stdout = log_file
        sys.stderr = log_file

    interface_flow_tables = defaultdict(dict)
    device_flow_tables = {}
    pending_stats = {}
    baseline_windows = {}
    dirty_flow_ids = defaultdict(set)
    conversations = ConversationTracker(maximum=config.max_flow_table_size)
    streams = LiveTCPStreamTracker(maximum_streams=min(config.max_flow_table_size, 16_384))
    geoip_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="watchtower-geoip")
    geoip_pending = {}
    geoip_waiters = defaultdict(list)
    geoip_results = {}
    last_conversation_evaluation = {}
    draining = False
    drain_reason = "operator_stop"
    persisted_generation = 0

    # Shared SQLite database
    db = WatchtowerDB(data_dir=config.data_dir)
    endpoint_attributor = EndpointAttributor(db)
    
    # Initialise the daily stats accumulator (now wraps SQLite)
    accumulator = DailyAccumulator(data_dir=config.data_dir)
    analytics = AnalyticsEngine()
    
    # ForensicsEngine for live identity extraction
    forensics = ForensicsEngine(db=db, data_dir=config.data_dir)
    
    from core.packet_engine.analytics import BehavioralEngine
    behavioral = BehavioralEngine(db=db)
    db.purge_inactive_feature_baselines()
    last_baseline_purge = time.time()

    last_snapshot_time = time.time()

    def schedule_geoip(flow, ip):
        """Schedule public enrichment without blocking packet analytics."""
        ip = str(ip or "")
        if not ip or ip in geoip_results:
            if ip in geoip_results:
                flow.l7_metadata["geoip"] = geoip_results[ip]
            return
        if ip not in geoip_pending:
            geoip_pending[ip] = geoip_executor.submit(get_geoip_info, ip)
        flow.l7_metadata["geoip_pending"] = True
        geoip_waiters[ip].append(flow)

    def drain_geoip():
        for ip, future in list(geoip_pending.items()):
            if not future.done():
                continue
            try:
                info = future.result()
            except Exception:
                info = {"country": "Unknown", "city": "Remote", "asn": "Unknown ASN"}
            geoip_results[ip] = info
            for flow in geoip_waiters.pop(ip, ()):
                flow.l7_metadata.pop("geoip_pending", None)
                flow.l7_metadata["geoip"] = info
            geoip_pending.pop(ip, None)
        # Keep this enrichment cache bounded for long-running sensors.
        while len(geoip_results) > 4096:
            geoip_results.pop(next(iter(geoip_results)))

    def should_evaluate_conversation(delta) -> bool:
        """Throttle expensive stateful checks without losing control events."""
        key = delta.key
        event_time = float(delta.event_time)
        immediate = (
            int(delta.generation) <= 1
            or int(delta.syn_delta) > 0
            or int(delta.syn_ack_delta) > 0
            or int(delta.rst_delta) > 0
        )
        previous = last_conversation_evaluation.get(key)
        if immediate or previous is None or event_time - previous >= 1.0:
            last_conversation_evaluation[key] = event_time
            if len(last_conversation_evaluation) > 32_768:
                oldest = sorted(
                    last_conversation_evaluation.items(), key=lambda item: item[1]
                )[:8_192]
                for old_key, _old_time in oldest:
                    last_conversation_evaluation.pop(old_key, None)
            return True
        return False

    last_snapshot_time = time.time()

    def flush_final_state():
        nonlocal persisted_generation
        now = time.time()
        for conversation_delta in conversations.finalize():
            forensics.process_live_conversation(
                conversation_delta,
                source=conversation_delta.key.source,
                capture_interface=conversation_delta.key.interface,
                capture_session_id=conversation_delta.key.session_id,
                capture_backend=conversation_delta.backend,
            )
        for iface, flow_table in interface_flow_tables.items():
            if not flow_table and not pending_stats.get(iface):
                continue
            group_source = f"live_{iface}"
            session_id = (capture_origin or {}).get("session_id")
            record_source = f"{group_source}#{session_id[:12]}" if session_id else group_source
            changed_ids = set(dirty_flow_ids.get(iface) or ())
            changed_flows = {flow_id: flow_table[flow_id] for flow_id in changed_ids if flow_id in flow_table}
            snapshot, tasks = build_snapshot(
                flow_table, now - config.window_size, now,
                analytics_engine=analytics, forensics_engine=forensics,
                behavioral_engine=behavioral, source=record_source,
                capture_interface=iface, capture_session_id=session_id,
                capture_backend=(capture_origin or {}).get("backend"),
                detection_flow_ids=changed_ids,
            )
            snapshot.interface = iface
            accumulator.merge(
                snapshot, flow_table=changed_flows, source=record_source,
                stats_source=group_source, capture_origin=capture_origin,
                stats_snapshot=_pending_stats_snapshot(
                    pending_stats, iface, now - config.window_size, now, len(flow_table)
                ),
            )
            for task in tasks:
                if evidence_queue is None:
                    break
                try:
                    evidence_queue.put(task, timeout=0.05)
                except queue_module.Full:
                    _increment_metric(metrics, "evidence_dropped")
            dirty_flow_ids[iface].clear()
            pending_stats.pop(iface, None)
            persisted_generation += 1

    try:
        while True:
            current_time = time.time()
            drain_geoip()
            if current_time - last_baseline_purge >= 86400:
                db.purge_inactive_feature_baselines(as_of=current_time)
                last_baseline_purge = current_time

            # Check for control messages
            if control_queue:
                try:
                    msg = control_queue.get_nowait()
                    if msg.get("type") == "STOP":
                        draining = True
                        drain_reason = str(msg.get("reason") or "operator_stop")
                        logger.info("[worker] Received STOP signal. Draining packet queue.")
                    elif msg.get("type") == "DUMP":
                        filename = msg.get("filename", "dump.pcap")
                        logger.info(f"[worker] dumping all captured packets to {filename}")
                        all_raw = []
                        for iface_table in interface_flow_tables.values():
                            for flow in iface_table.values():
                                all_raw.extend(flow.raw_packets)

                        if all_raw:
                            wrpcap(filename, [Ether(p) for p in all_raw])
                            logger.info(f"[worker] dump complete: {len(all_raw)} packets written to {filename}")
                        else:
                            logger.info("[worker] nothing to dump — no packets captured yet")
                except queue_module.Empty:
                    pass
                except Exception as e:
                    logger.error(f"[worker] control message error: {e}")

            # Consume packets
            consumed = 0
            for batch_index in range(config.packet_batch_size):
                try:
                    event = packet_queue.get(timeout=0.05) if batch_index == 0 else packet_queue.get_nowait()
                except queue_module.Empty:
                    break
                consumed += 1
                _record_queue_health(metrics, packet_queue, event)

                if isinstance(event, HardwareObservation):
                    db.insert_hardware_observation({
                        "capture_session_id": event.origin.session_id,
                        "timestamp": event.timestamp, "source_type": event.origin.source_type,
                        "device_id": event.origin.device_id, "observation_type": event.observation_type,
                        "subject": event.subject, "peer": event.peer, "metadata": event.metadata,
                    })
                    _increment_metric(metrics, "processed_packets")
                    continue

                conversation_metadata, conversation_delta = conversations.update_with_delta(event)
                event.l7_info = {**(event.l7_info or {}), **conversation_metadata}
                _record_pending_stats(pending_stats, event)
                _record_baseline_event(baseline_windows, event)

                flow_id = (
                    event.src_ip,
                    event.dst_ip,
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                )

                # GLOBAL MODE
                if config.monitoring_mode in ["GLOBAL", "HYBRID"]:
                    iface_table = interface_flow_tables[event.interface]
                    created_flow = flow_id not in iface_table
                    if flow_id not in iface_table:
                        iface_table[flow_id] = FlowAggregate(
                            flow_id=flow_id, start_time=event.timestamp, last_seen=event.timestamp
                        )

                    flow = iface_table[flow_id]
                    flow.update(event.size, event.timestamp, event.flags, l7_info=event.l7_info, raw=event.raw)
                    if created_flow:
                        attribution = endpoint_attributor.attribute(
                            src_ip=event.src_ip, src_port=event.src_port,
                            dst_ip=event.dst_ip, dst_port=event.dst_port,
                            protocol=event.protocol, observed_at=event.timestamp,
                        )
                        flow.l7_metadata["process_attribution"] = attribution
                        # Existing consumers still show process_info; its source is now explicit.
                        flow.l7_metadata["process_info"] = legacy_process_label(attribution)
                    dirty_flow_ids[event.interface].add(flow_id)
                    reverse_flow_id = (
                        event.dst_ip, event.src_ip, event.dst_port, event.src_port, event.protocol,
                    )
                    reverse_flow = iface_table.get(reverse_flow_id)
                    if reverse_flow is not None:
                        reverse_direction = (
                            "to_initiator" if conversation_metadata["conversation_direction"] == "to_responder"
                            else "to_responder"
                        )
                        reverse_flow.l7_metadata.update({
                            "conversation_direction": reverse_direction,
                            "initiator_ip": conversation_metadata["initiator_ip"],
                            "initiator_port": conversation_metadata["initiator_port"],
                            "responder_ip": conversation_metadata["responder_ip"],
                            "responder_port": conversation_metadata["responder_port"],
                            "conversation_established": conversation_metadata["conversation_established"],
                            "conversation_syn_count": conversation_metadata["conversation_syn_count"],
                            "conversation_syn_ack_count": conversation_metadata["conversation_syn_ack_count"],
                            "conversation_rst_count": conversation_metadata["conversation_rst_count"],
                            "reverse_byte_count": (
                                conversation_metadata["conversation_to_responder_bytes"]
                                if reverse_direction == "to_initiator"
                                else conversation_metadata["conversation_to_initiator_bytes"]
                            ),
                            "reverse_packet_count": (
                                conversation_metadata["conversation_to_responder_packets"]
                                if reverse_direction == "to_initiator"
                                else conversation_metadata["conversation_to_initiator_packets"]
                            ),
                        })
                        dirty_flow_ids[event.interface].add(reverse_flow_id)
                    
                    # Live forensic processing: extract identities and write to SQLite.
                    # Flow accounting above remains lossless; deep packet work
                    # is bounded so busy encrypted sessions cannot starve it.
                    if event.raw and _should_deep_inspect_live_packet(event, flow):
                        try:
                            from scapy.all import Ether as EtherParse
                            raw_packet = EtherParse(event.raw)
                            stream_alerts = []
                            payload = application_payload(raw_packet, maximum=16 * 1024 * 1024)
                            has_live_evidence = forensics.has_live_evidence(raw_packet, payload=payload)
                            packet_evidence = has_live_evidence
                            if (
                                packet_evidence
                                and raw_packet.haslayer(TCP)
                                and payload
                            ):
                                # Inspect connection starts and suspicious or
                                # protocol-shaped payloads, but do not run the
                                # full packet plugin set on every bulk TLS or
                                # HTTP body segment. The stream tracker below
                                # remains lossless within its bounded spool.
                                sample = payload[:8192].lower()
                                evidence_markers = (
                                    b"user ", b"pass ", b"password", b"authorization",
                                    b"ntlmssp", b"ssh-", b"get ", b"post ", b"http/",
                                    b"\x16\x03", b"mqtt", b"modbus", b"coap", b"mz",
                                )
                                if flow.live_forensics_payloads >= 8 and not any(
                                    marker in sample for marker in evidence_markers
                                ):
                                    packet_evidence = False
                                else:
                                    flow.live_forensics_payloads += 1
                            stream_snapshot = (
                                streams.update(raw_packet, event)
                                if has_live_evidence and raw_packet.haslayer(TCP)
                                and bool(raw_packet[TCP].payload)
                                else None
                            )
                            if stream_snapshot is not None:
                                stream_alerts = forensics.process_live_stream(
                                    flow, stream_snapshot.payload, stream_snapshot.direction,
                                    stream_snapshot.timestamp, capture_interface=event.interface,
                                    capture_session_id=event.session_id,
                                    capture_backend=event.backend,
                                    truncated=stream_snapshot.truncated,
                                )
                            suppressed_types = {
                                alert.type for alert in stream_alerts
                                if alert.type in {"CLEARTEXT_CREDENTIALS", "CLEARTEXT_SECRET"}
                            }
                            if packet_evidence:
                                identities, live_alerts = forensics.process_live_packet(
                                    raw_packet, flow, capture_interface=event.interface,
                                    capture_session_id=event.session_id,
                                    capture_backend=event.backend,
                                    persist_identity=False,
                                    suppressed_alert_types=suppressed_types,
                                    payload_override=payload,
                                )
                            else:
                                identities, live_alerts = {}, []
                            # Merge identities into flow metadata
                            if identities:
                                flow.l7_metadata.update({k: v for k, v in identities.items() if v})
                            if any(alert.type == "AUTHENTICATION_ABUSE" for alert in live_alerts):
                                for alert in live_alerts:
                                    if alert.type == "AUTHENTICATION_ABUSE":
                                        forensics.note_live_behavior_signal(
                                            str((alert.evidence or {}).get("source") or event.src_ip),
                                            "auth_failure",
                                            event.timestamp,
                                        )
                        except Exception:
                            _increment_metric(metrics, "detector_errors")
                    
                    # Enrich new flows
                    if "geoip" not in flow.l7_metadata and "geoip_pending" not in flow.l7_metadata:
                        schedule_geoip(flow, event.dst_ip)

                conversation_metadata_for_detection = dict(event.l7_info or {})
                if config.monitoring_mode in ["GLOBAL", "HYBRID"]:
                    conversation_metadata_for_detection.update(
                        interface_flow_tables[event.interface][flow_id].l7_metadata
                    )
                conversation_delta = conversations.enrich_delta(
                    conversation_delta, conversation_metadata_for_detection
                )
                if should_evaluate_conversation(conversation_delta):
                    forensics.process_live_conversation(
                        conversation_delta,
                        source=(capture_origin or {}).get("source") or (
                            f"live_{event.interface}#{event.session_id[:12]}"
                            if event.session_id else f"live_{event.interface}"
                        ),
                        capture_interface=event.interface,
                        capture_session_id=event.session_id,
                        capture_backend=event.backend,
                    )

                # PER_DEVICE MODE
                if config.monitoring_mode in ["PER_DEVICE", "HYBRID"]:
                    device_id = event.src_ip

                    if device_id not in device_flow_tables:
                        device_flow_tables[device_id] = {}

                    table = device_flow_tables[device_id]
                    if flow_id not in table:
                        table[flow_id] = FlowAggregate(
                            flow_id=flow_id, start_time=event.timestamp, last_seen=event.timestamp
                        )

                    flow = table[flow_id]
                    flow.update(event.size, event.timestamp, event.flags)

                _increment_metric(metrics, "processed_packets")

            if consumed == 0 and metrics is not None:
                if "queue_depth" in metrics:
                    metrics["queue_depth"].value = 0
                if "queue_lag_current_ms" in metrics:
                    metrics["queue_lag_current_ms"].value = 0.0

            if draining and consumed == 0:
                try:
                    flush_final_state()
                    if metrics is not None and "pending_packets" in metrics:
                        metrics["pending_packets"].value = 0
                    logger.info("[worker] Queue drained and final state persisted (%s).", drain_reason)
                    if acknowledgement_queue is not None:
                        acknowledgement_queue.put({
                            "stage": "worker",
                            "persisted_generation": persisted_generation,
                            "processed_packets": (
                                int(metrics["processed_packets"].value)
                                if metrics and "processed_packets" in metrics else 0
                            ),
                            "acknowledged_at": time.time(),
                        })
                except Exception as flush_e:
                    _increment_metric(metrics, "detector_errors")
                    logger.error(f"[worker] Final flush error: {flush_e}")
                    raise
                return

            # Cleanup expired flows
            session_id = (capture_origin or {}).get("session_id")
            _flush_baseline_windows(
                db, baseline_windows, current_time,
                lambda iface: f"live_{iface}#{session_id[:12]}" if session_id else f"live_{iface}",
            )

            # Cleanup expired flows
            for table in interface_flow_tables.values():
                cleanup_expired_flows(table, current_time)
            for table in device_flow_tables.values():
                cleanup_expired_flows(table, current_time)
            conversations.expire(current_time - FLOW_TIMEOUT)
            streams.expire(current_time - FLOW_TIMEOUT)

            # Enforce memory limits
            for table in interface_flow_tables.values():
                enforce_memory_limit(table, config.max_flow_table_size)
            for table in device_flow_tables.values():
                enforce_memory_limit(table, config.max_flow_table_size)

            # Sliding Window Snapshot
            if current_time - last_snapshot_time >= config.step_size:
                # Snapshot scoring and persistence are intentionally deferred
                # while capture is under pressure. This prevents a dashboard
                # refresh from competing with packet processing and turning a
                # temporary burst into queue loss. The next quiet iteration
                # builds the complete window from the in-memory aggregates.
                try:
                    snapshot_queue_depth = int(packet_queue.qsize())
                except (NotImplementedError, OSError):
                    snapshot_queue_depth = 0
                snapshot_pressure_limit = max(512, int(config.packet_queue_size * 0.25))
                if snapshot_queue_depth > snapshot_pressure_limit:
                    time.sleep(0.01)
                    continue

                window_start = current_time - config.window_size
                window_end = current_time

                if window_end - window_start > 0:
                    total_flows = sum(len(t) for t in interface_flow_tables.values())
                    logger.debug(f"[worker] building snapshot flows={total_flows}")
                
                if config.monitoring_mode in ["GLOBAL", "HYBRID"]:
                    for iface, flow_table in interface_flow_tables.items():
                        group_source = f"live_{iface}"
                        session_id = (capture_origin or {}).get("session_id")
                        record_source = f"{group_source}#{session_id[:12]}" if session_id else group_source
                        changed_ids = set(dirty_flow_ids.get(iface) or ())
                        changed_flows = {
                            flow_id: flow_table[flow_id]
                            for flow_id in changed_ids if flow_id in flow_table
                        }
                        snapshot, tasks = build_snapshot(
                            flow_table, 
                            window_start, 
                            window_end, 
                            analytics_engine=analytics,
                            forensics_engine=forensics,
                            behavioral_engine=behavioral, source=record_source,
                            capture_interface=iface, capture_session_id=session_id,
                            capture_backend=(capture_origin or {}).get("backend"),
                            detection_flow_ids=changed_ids,
                        )
                        snapshot.interface = iface
                        analytics.update_baselines(snapshot)
                        try:
                            snapshot_queue.put(("GLOBAL", snapshot), timeout=0.05)
                        except queue_module.Full:
                            _increment_metric(metrics, "snapshot_dropped")
                        
                        # Dispatch asynchronous evidence tasks
                        if evidence_queue:
                            for t in tasks:
                                try:
                                    evidence_queue.put(t, timeout=0.05)
                                except queue_module.Full:
                                    _increment_metric(metrics, "evidence_dropped")
                                
                        # Persist snapshot into SQLite via accumulator
                        accumulator.merge(
                            snapshot, flow_table=changed_flows, source=record_source,
                            stats_source=group_source, capture_origin=capture_origin,
                            stats_snapshot=_pending_stats_snapshot(
                                pending_stats, iface, window_start, window_end, len(flow_table)
                            ),
                        )
                        pending_stats.pop(iface, None)
                        
                        # Populate the peer matrix through the storage repository.
                        unseen_pairs = []
                        for f in changed_flows.values():
                            if f.last_seen >= window_start:
                                if f.l7_metadata.get("generated_by") == "WatchTower":
                                    continue
                                pair = (f.flow_id[0], f.flow_id[1])
                                if pair not in behavioral._peer_cache:
                                    unseen_pairs.append(pair)
                        if unseen_pairs:
                            db.remember_behavioral_peers(unseen_pairs)
                            behavioral._peer_cache.update(unseen_pairs)
                        dirty_flow_ids[iface].clear()

                if config.monitoring_mode in ["PER_DEVICE", "HYBRID"]:
                    for device_id, table in device_flow_tables.items():
                        snapshot, _ = build_snapshot(
                            table, 
                            window_start, 
                            window_end, 
                            analytics_engine=analytics,
                            forensics_engine=forensics
                        )
                        try:
                            snapshot_queue.put((f"DEVICE:{device_id}", snapshot), timeout=0.05)
                        except queue_module.Full:
                            _increment_metric(metrics, "snapshot_dropped")

                last_snapshot_time = current_time

            time.sleep(0.1)
    except Exception as e:
        import traceback
        _increment_metric(metrics, "detector_errors")
        logger.critical(f"[worker] CRITICAL ERROR: {e}\n{traceback.format_exc()}")
        # Do not sys.exit here — let the daemon's process tracking detect the failure
        # and the daemon will log it without crashing itself
    finally:
        if worker_done_event is not None:
            worker_done_event.set()
        try:
            accumulator.db.close()
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass
        try:
            geoip_executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
