# core/packet_engine/flow_worker.py

import sys
import os
import logging

# Ensure local imports work when spawned in a new process on Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import time
from collections import defaultdict
from core.packet_engine.schemas import FlowAggregate, WindowSnapshot, AlertRecord
from core.packet_engine.persistence import DailyAccumulator
from core.packet_engine.analytics import AnalyticsEngine
from core.forensics.engine import ForensicsEngine
from core.storage.database import WatchtowerDB
from core.constants import (
    FLOW_TIMEOUT, ALERT_THRESHOLD, EVIDENCE_TRIGGER,
    C2_PORTS, INTERNAL_IP_PREFIXES, ALERT_COOLDOWN, SCAN_HIGH_SYN_COUNT
)
import math
import psutil
from scapy.all import wrpcap, Ether, IP, TCP, UDP
from core.packet_engine.utils import get_geoip_info, get_process_info
from core.packet_engine.processors import StatAggregator, SecurityScorer, AlertManager

logger = logging.getLogger("flow_worker")


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


def build_snapshot(flow_table, window_start, window_end, analytics_engine=None, forensics_engine=None, behavioral_engine=None):
    stats = StatAggregator()
    scorer = SecurityScorer(analytics_engine, forensics_engine, behavioral_engine)
    alert_mgr = AlertManager()
    alert_mgr.behavioral = behavioral_engine
    evidence_tasks = []
    
    active_flows = [f for f in flow_table.values() if f.last_seen >= window_start]
    
    total_packets = 0
    total_bytes = 0
    max_behavior_score = 0.0

    for f in active_flows:
        total_packets += f.packet_count
        total_bytes += f.byte_count
        
        # 1. Aggregate Stats
        stats.aggregate(f, window_start)
        
        # 2. Compute Scores
        b_score, t_score, forensic_alerts = scorer.score_flow(f)
        final_score = b_score + t_score
        max_behavior_score = max(max_behavior_score, final_score)
        
        # 3. Handle Alerts
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
        alerts=alert_mgr.alerts[:10]
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


def flow_worker(packet_queue, snapshot_queue, config, control_queue=None, evidence_queue=None):
    if config.silent:
        log_path = os.path.join(config.data_dir, "engine.log")
        log_file = open(log_path, "a", buffering=1)
        sys.stdout = log_file
        sys.stderr = log_file

    interface_flow_tables = defaultdict(dict)
    device_flow_tables = {}

    # Shared SQLite database
    db = WatchtowerDB(data_dir=config.data_dir)
    
    # Initialise the daily stats accumulator (now wraps SQLite)
    accumulator = DailyAccumulator(data_dir=config.data_dir)
    analytics = AnalyticsEngine()
    
    # ForensicsEngine for live identity extraction
    forensics = ForensicsEngine(db=db, data_dir=config.data_dir)
    
    from core.packet_engine.analytics import BehavioralEngine
    behavioral = BehavioralEngine(db=db)

    last_snapshot_time = time.time()

    last_snapshot_time = time.time()

    try:
        while True:
            current_time = time.time()

            # Check for control messages
            if control_queue and not control_queue.empty():
                try:
                    msg = control_queue.get_nowait()
                    if msg.get("type") == "STOP":
                        logger.info("[worker] Received STOP signal. Flushing and exiting.")
                        # Final flush to DB before exit
                        try:
                            final_acc = DailyAccumulator(data_dir=db._data_dir if hasattr(db, '_data_dir') else "data")
                            for iface, flow_table in interface_flow_tables.items():
                                if flow_table:
                                    snapshot, _ = build_snapshot(flow_table, time.time() - 10, time.time())
                                    snapshot.interface = iface
                                    accumulator.merge(snapshot, flow_table=flow_table, source=f"live_{iface}")
                        except Exception as flush_e:
                            logger.error(f"[worker] Final flush error: {flush_e}")
                        return  # Clean exit
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
                except Exception as e:
                    logger.error(f"[worker] control message error: {e}")

            # Consume packets
            while not packet_queue.empty():
                event = packet_queue.get()

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
                    if flow_id not in iface_table:
                        iface_table[flow_id] = FlowAggregate(
                            flow_id=flow_id, start_time=event.timestamp, last_seen=event.timestamp
                        )

                    flow = iface_table[flow_id]
                    flow.update(event.size, event.timestamp, event.flags, l7_info=event.l7_info, raw=event.raw)
                    
                    # Live forensic processing: extract identities and write to SQLite
                    if event.raw:
                        try:
                            from scapy.all import Ether as EtherParse
                            raw_packet = EtherParse(event.raw)
                            identities, live_alerts = forensics.process_live_packet(raw_packet, flow)
                            # Merge identities into flow metadata
                            if identities:
                                flow.l7_metadata.update({k: v for k, v in identities.items() if v})
                        except Exception:
                            pass
                    
                    # Enrich new flows
                    if "process_info" not in flow.l7_metadata:
                        flow.l7_metadata["process_info"] = get_process_info(event.src_port)
                    if "geoip" not in flow.l7_metadata:
                        flow.l7_metadata["geoip"] = get_geoip_info(event.dst_ip)

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

            # Cleanup expired flows
            for table in interface_flow_tables.values():
                cleanup_expired_flows(table, current_time)
            for table in device_flow_tables.values():
                cleanup_expired_flows(table, current_time)

            # Enforce memory limits
            for table in interface_flow_tables.values():
                enforce_memory_limit(table, config.max_flow_table_size)
            for table in device_flow_tables.values():
                enforce_memory_limit(table, config.max_flow_table_size)

            # Sliding Window Snapshot
            if current_time - last_snapshot_time >= config.step_size:

                window_start = current_time - config.window_size
                window_end = current_time

                if window_end - window_start > 0:
                    total_flows = sum(len(t) for t in interface_flow_tables.values())
                    logger.debug(f"[worker] building snapshot flows={total_flows}")
                
                if config.monitoring_mode in ["GLOBAL", "HYBRID"]:
                    for iface, flow_table in interface_flow_tables.items():
                        snapshot, tasks = build_snapshot(
                            flow_table, 
                            window_start, 
                            window_end, 
                            analytics_engine=analytics,
                            forensics_engine=forensics,
                            behavioral_engine=behavioral
                        )
                        snapshot.interface = iface
                        analytics.update_baselines(snapshot)
                        snapshot_queue.put(("GLOBAL", snapshot))
                        
                        # Dispatch asynchronous evidence tasks
                        if evidence_queue:
                            for t in tasks:
                                evidence_queue.put(t)
                                
                        # Persist snapshot into SQLite via accumulator
                        accumulator.merge(snapshot, flow_table=flow_table, source=f"live_{iface}")
                        
                        # Populate Peer Matrix for new flows
                        session = db._get_session()
                        from core.storage.models import BehavioralBaseline
                        for f in flow_table.values():
                            if f.last_seen >= window_start:
                                pair = (f.flow_id[0], f.flow_id[1])
                                if pair not in behavioral._peer_cache:
                                    # Double check DB and insert
                                    exists = session.query(BehavioralBaseline).filter_by(
                                        entity_ip=pair[0], pattern_key="comm_pair", pattern_data=pair[1]
                                    ).first()
                                    if not exists:
                                        baseline = BehavioralBaseline(
                                            entity_ip=pair[0], pattern_key="comm_pair", 
                                            pattern_data=pair[1], last_updated=time.time()
                                        )
                                        session.add(baseline)
                                        behavioral._peer_cache.add(pair)
                        session.commit()

                if config.monitoring_mode in ["PER_DEVICE", "HYBRID"]:
                    for device_id, table in device_flow_tables.items():
                        snapshot, _ = build_snapshot(
                            table, 
                            window_start, 
                            window_end, 
                            analytics_engine=analytics,
                            forensics_engine=forensics
                        )
                        snapshot_queue.put((f"DEVICE:{device_id}", snapshot))

                last_snapshot_time = current_time

            time.sleep(0.1)
    except Exception as e:
        import traceback
        logger.critical(f"[worker] CRITICAL ERROR: {e}\n{traceback.format_exc()}")
        # Do not sys.exit here — let the daemon's process tracking detect the failure
        # and the daemon will log it without crashing itself
