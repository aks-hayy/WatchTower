# core/forensics/engine.py

import os
import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import logging

# Suppress scapy warnings that slow down parsing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy.conf.logLevel = logging.ERROR
from core.forensics.models import ForensicReport, EntityProfile, ForensicAlert, CarvedFile
from core.forensics.plugin_loader import PluginLoader
from core.packet_engine.schemas import FlowAggregate, PacketEvent
from core.packet_engine.conversations import ConversationTracker
from core.forensics.forwarder import AlertForwarder
from core.packet_engine.capture import packet_to_event
from core.forensics.vt_client import VirusTotalClient, get_file_hash
from core.forensics.identity import IdentityResolver
from core.storage.database import WatchtowerDB
from core.backend_policy import backend_policy
from core.packet_engine.utils import normalize_packet
from core.detection.payload import application_payload
from typing import Dict, List, Optional, Tuple
import time
import hashlib
from pathlib import Path
import tempfile
import warnings
from core.constants import MAX_STREAM_BYTES, MAX_STREAM_SEGMENTS, MAX_REASSEMBLY_GAP


# Offline replay sees every packet.  Accumulating entity observations before a
# bulk upsert avoids one SQLite transaction per packet without changing the
# resulting packet and byte counters.
OFFLINE_ENTITY_FLUSH_INTERVAL = 50_000
OFFLINE_ENTITY_PENDING_LIMIT = 10_000
OFFLINE_HARDWARE_PENDING_LIMIT = 1_000

# These plugins consume only the L2-L4 and bounded application-payload
# surface supplied by ``FastPacket``.  Protocol parsers that depend on a full
# Scapy graph (notably DNS/DHCP/discovery) remain on the deep-decode path.
# Keeping the allow-list here makes the accelerated backend conservative for
# third-party plugins: they opt in explicitly with ``fast_path = True``.
FAST_PATH_PARSER_NAMES = frozenset({
    "ARP and NDP Parser", "ICMP Metadata Parser", "DHCPv6 Parser",
    "LLDP and CDP Parser", "QUIC Metadata Parser", "SSH Parser", "LDAP Parser",
    "RDP Parser", "Mail Protocol Parser", "SNMP Parser", "NTP Parser",
    "FTP Parser", "Full Name Scraper", "HTTP Parser", "MQTT Parser",
    "CoAP Parser", "Modbus TCP Parser", "Kerberos Parser", "NBNS Parser",
    "NTLM Parser", "SMB Stateful Parser", "TLS Parser",
})
FAST_PATH_DETECTOR_NAMES = frozenset({
    "LAN Trust Detector", "Reconnaissance and Lateral Movement Detector",
    "Application Abuse Detector", "IoT and OT Safety Detector",
    "Cleartext FTP Credential Detector", "File Transfer Detector",
})

class ForensicsEngine:
    """Shared forensic analysis module used by both live pipeline and offline analysis.
    
    Two modes of operation:
    1. Live mode:  process_live_packet() called per-packet from flow_worker
    2. Offline mode: analyze_pcap() processes an entire PCAP file
    
    Both modes write to the same SQLite database.
    """

    def __init__(self, db: WatchtowerDB = None, data_dir: str = "data", silent: bool = False):
        scoring_mode = os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower()
        if scoring_mode not in {"legacy", "dual", "v2"}:
            raise ValueError("WATCHTOWER_SCORING_MODE must be legacy, dual, or v2")
        self.silent = silent
        self.data_dir = str(data_dir)
        # SQLite database — shared with the rest of the system
        self.db = db or WatchtowerDB(data_dir=data_dir)
        
        # In-memory state for the current analysis session
        self.report = ForensicReport()
        self.flow_table: Dict[tuple, FlowAggregate] = {}
        self.plugin_loader = PluginLoader()
        self.forwarder = AlertForwarder(config={"enabled": False}) # Configured via settings in the future
        self._current_progress_callback = None
        self.tls_session = None
        self._raw_streams = {}
        self._raw_stream_bytes = {}
        
        # Source tag for this session
        self._source = "live"
        self._vendor_cache = {}
        self.identity_resolver = IdentityResolver()
        self._analysis_mode = "memory"
        self._capture_backend = "python"
        self._conversation_source = "offline"
        self._segment_spool = None
        self._finalized_flow_count = 0
        self._pending_entities = {}
        self._pending_hardware_observations = []
        self._pending_flow_rows = []
        self._batch_entity_observations = False
        self._batch_hardware_observations = False
        self._batch_flow_persistence = False
        self._offline_parsers = ()
        self._offline_packet_detectors = ()
        self._offline_flow_detectors = ()
        self._offline_stream_detectors = ()
        self._offline_parser_port_filters = {}
        self._offline_fast_parsers = ()
        self._offline_deep_decode_ports = frozenset()
        self._offline_fast_packet_detectors = ()
        self._offline_os_detectors = ()
        self._fast_tls_payloads = set()
        self._defer_encrypted_streams = False
        self._conversation_tracker = ConversationTracker()
        self._native_case_id = None
        self._native_analysis_id = None
        self._native_persistence_failed = False
        self._fast_tls_payloads = set()
        from core.survey.probe_registry import ProbeRegistry
        self._probe_registry = ProbeRegistry(self.data_dir)

    def get_vendor(self, mac: str) -> Optional[str]:
        """Simple OUI lookup for common hardware vendors."""
        if not mac: return None
        prefix = mac.replace(":", "").upper()[:6]
        if prefix in self._vendor_cache:
            return self._vendor_cache[prefix]
            
        vendors = {
            "44370B": "LG Electronics",
            "00E04C": "Realtek",
            "B827EB": "Raspberry Pi",
            "001788": "Philips Hue",
            "D80D17": "Apple",
            "28CFDA": "Apple",
            "C4AD34": "Apple",
            "000C29": "VMware",
            "080027": "VirtualBox",
            "E4E4AB": "Sonos",
            "34D270": "Sonos"
        }
        self._vendor_cache[prefix] = vendors.get(prefix)
        return self._vendor_cache[prefix]

    @staticmethod
    def _add_flow_evidence(alert: ForensicAlert, flow: FlowAggregate):
        if not flow:
            return
        src_ip, dst_ip, src_port, dst_port, protocol = flow.flow_id
        alert.evidence = dict(alert.evidence or {})
        alert.evidence.setdefault("src_ip", src_ip)
        alert.evidence.setdefault("dst_ip", dst_ip)
        alert.evidence.setdefault("src_port", src_port)
        alert.evidence.setdefault("dst_port", dst_port)
        alert.evidence.setdefault("protocol", protocol)

    def _store_alert(self, ip: str, alert: ForensicAlert, add_to_report: bool = False,
                     detector=None, capture_interface: str = None,
                     capture_session_id: str = None, capture_backend: str = None) -> bool:
        """Persist legacy compatibility and the canonical V2 finding exactly once."""
        mode = os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower()
        result = {"created": True, "suppressed": False, "score": alert.score, "severity": alert.severity}
        if mode in {"legacy", "dual"}:
            result = self.db.insert_alert(
                entity_ip=ip,
                timestamp=alert.timestamp,
                alert_type=alert.type,
                severity=alert.severity,
                score=alert.score,
                explanation=alert.explanation,
                evidence=alert.evidence,
                source=self._source,
                capture_interface=capture_interface,
                capture_session_id=capture_session_id,
                capture_backend=capture_backend,
            )
        elif mode == "v2":
            decision = self.db.alert_policy.evaluate(
                ip, alert.type, alert.severity, alert.score,
                alert.explanation, alert.evidence, alert.timestamp,
            )
            result.update({
                "suppressed": decision.suppressed,
                "suppression_reason": decision.suppression_reason or "policy suppression",
                "score": decision.score, "severity": decision.severity,
            })
        if mode in {"dual", "v2"}:
            from core.detection.contracts import detector_alert_to_finding
            finding = detector_alert_to_finding(
                detector, alert, ip, source=self._source,
                capture_interface=capture_interface,
                capture_session_id=capture_session_id,
                capture_backend=capture_backend,
            )
            finding_errors = finding.validate(getattr(detector, "manifest", None))
            if finding_errors:
                if detector is not None:
                    self.plugin_loader.record_error(detector, ValueError("; ".join(finding_errors)))
            else:
                finding_result = self.db.upsert_detection_finding(finding)
                if result.get("suppressed") and finding_result.get("created"):
                    self.db.set_finding_disposition(
                        finding_result["id"], "benign_expected",
                        result.get("suppression_reason") or "legacy detection policy suppression",
                        actor="watchtower-policy",
                    )
                entity = self.db.get_entity(ip) or {}
                self.db.recompute_risk_rollups(
                    ip, source=self._source, interface=capture_interface,
                    capture_session_id=capture_session_id, as_of=finding.last_seen,
                    asset_role=entity.get("asset_role"),
                )
        if not result.get("created") or result.get("suppressed"):
            return False
        alert.score = result["score"]
        alert.severity = result["severity"]
        if add_to_report:
            self.report.add_alert(ip, alert)
        self.forwarder.forward(alert, ip)
        return True

    # ----------------------------------------------------------------
    # Live Mode: Per-packet processing for flow_worker
    # ----------------------------------------------------------------

    def process_live_packet(self, packet, flow: FlowAggregate = None, capture_interface: str = None,
                            capture_session_id: str = None, capture_backend: str = None,
                            persist_identity: bool = True,
                            suppressed_alert_types=None) -> Tuple[Dict, List[ForensicAlert]]:
        """Lightweight per-packet processing for live capture.
        
        Extracts identities and runs live detection rules.
        Writes entity updates to SQLite.
        Returns (identities, alerts).
        """
        if IP in packet:
            ip_layer = packet[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            hop_limit = ip_layer.ttl
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            hop_limit = ip_layer.hlim
        elif scapy.ARP in packet:
            ip_layer = None
            src_ip, dst_ip = packet[scapy.ARP].psrc, packet[scapy.ARP].pdst
            hop_limit = None
        else:
            return {}, []
        if capture_interface:
            group = f"live_{capture_interface}"
            self._source = f"{group}#{capture_session_id[:12]}" if capture_session_id else group
        watchtower_probe = self._probe_registry.matches(
            src_ip, dst_ip,
            int(packet[scapy.TCP].sport) if scapy.TCP in packet else (int(packet[scapy.UDP].sport) if scapy.UDP in packet else 0),
            int(packet[scapy.TCP].dport) if scapy.TCP in packet else (int(packet[scapy.UDP].dport) if scapy.UDP in packet else 0),
            "TCP" if scapy.TCP in packet else ("UDP" if scapy.UDP in packet else "OTHER"),
            float(packet.time),
        )
        if watchtower_probe and flow is not None:
            flow.l7_metadata["generated_by"] = "WatchTower"

        # 1. Run Parsers
        all_found_alerts = []
        identities = {
            "mac": None, "local_hostname": None, "netbios_name": None, 
            "remote_hostname": None, "username": None, "full_name": None,
            "device_type": None, "vendor": None
        }
        # Do not bind ``Ether.src`` to every IP packet.  On a switched LAN it
        # identifies the next hop (normally the gateway) for remote traffic,
        # not the IP source.  ARP/NDP parsers below provide direct bindings.
            
        tls_info = {}
        protocol_metadata = {}
        for parser in self.plugin_loader.get_parsers():
            if not parser.enabled: continue
            try:
                res = parser.parse(packet)
                if "identities" in res:
                    identities.update(self.identity_resolver.observe(
                        src_ip, parser.name, res["identities"], float(packet.time)
                    ))
                if "tls_info" in res:
                    tls_info.update(res["tls_info"])
                if "metadata" in res:
                    protocol_metadata.update(res["metadata"])
                for observation in res.get("observations", []):
                    self.db.insert_hardware_observation(observation)
            except Exception as e:
                self.plugin_loader.record_error(parser, e)
                if not self.silent: print(f"Parser error {parser.name}: {e}")

        ja3_hash = tls_info.get("ja3")
        ja4_string = tls_info.get("ja4")
        tls_library = tls_info.get("library")
        
        if tls_library and any(m in tls_library for m in ["Metasploit", "Empire", "Cobalt"]):
            self._store_alert(src_ip, ForensicAlert(
                timestamp=float(packet.time), type="KNOWN_BAD", severity="CRITICAL", score=45.0,
                explanation=f"TLS Fingerprint match: {tls_library}", evidence={"ja3": ja3_hash, "ja4": ja4_string},
            ))

        # 2. Run Detectors
        os_info = "Unknown"
        packet_detectors = [
            detector for detector in self.plugin_loader.get_detectors()
            if detector.enabled
            and (
                getattr(detector, "manifest", None) is None
                or "packet" in detector.manifest.input_kinds
            )
        ]
        packet_detectors.sort(key=lambda detector: (
            getattr(detector.manifest, "detector_id", "") == "watchtower.application.abuse",
            getattr(detector.manifest, "detector_id", ""),
        ))
        claimed_protocol = False
        for detector in packet_detectors:
            if watchtower_probe: continue
            try:
                if hop_limit is not None and hasattr(detector, 'detect_os'):
                    res_os = detector.detect_os(hop_limit)
                    if res_os and res_os != "Unknown": os_info = res_os
                
                alerts = detector.detect(
                    packet=packet, flow=flow,
                    domain=protocol_metadata.get("dns_domain") or identities.get("remote_hostname"),
                    metadata=protocol_metadata,
                    claimed_protocol=claimed_protocol,
                )
                for alert in alerts:
                    if alert.type == "CLEARTEXT_CREDENTIALS":
                        claimed_protocol = True
                    if alert.type in set(suppressed_alert_types or ()):
                        continue
                    alert.timestamp = float(packet.time)
                    self._add_flow_evidence(alert, flow)
                    if self._store_alert(src_ip, alert, detector=detector,
                                         capture_interface=capture_interface,
                                         capture_session_id=capture_session_id,
                                         capture_backend=capture_backend):
                        if flow is not None:
                            flow.alert_history[
                                f"{detector.manifest.detector_id}:{alert.type}:canonical"
                            ] = alert.timestamp
                        all_found_alerts.append(alert)
            except Exception as e:
                self.plugin_loader.record_error(detector, e)
                if not self.silent: print(f"Detector error {detector.name}: {e}")

        # Upsert entity with all discovered metadata
        strongest = self.identity_resolver.strongest_source(src_ip)
        resolved = self.identity_resolver.values_for(src_ip)
        if persist_identity:
            self.db.upsert_entity(
                ip=src_ip,
                mac=resolved.get("mac"),
                vendor=resolved.get("vendor"),
                device_type=resolved.get("device_type"),
                hostname=resolved.get("local_hostname"),
                netbios_name=resolved.get("netbios_name"),
                username=resolved.get("username"),
                full_name=resolved.get("full_name"),
                os_info=os_info,
                confidence=strongest.confidence if strongest else 0.5,
                identity_source=strongest.source if strongest else "Passive",
                ja3_hash=ja3_hash,
                ja4_string=ja4_string,
                tls_library=tls_library,
                packets=1,
                bytes_count=len(packet),
                timestamp=float(packet.time),
                source=self._source
            )

        identities.update(protocol_metadata)
        return identities, all_found_alerts

    def process_live_stream(self, flow: FlowAggregate, stream: bytes, direction: str,
                            timestamp: float, capture_interface: str = None,
                            capture_session_id: str = None, capture_backend: str = None,
                            truncated: bool = False,
                            add_to_report: bool = False) -> List[ForensicAlert]:
        """Run stream plugins in deterministic protocol-specific-first order."""
        found = []
        detectors = [
            detector for detector in self.plugin_loader.get_detectors()
            if detector.enabled and "stream" in getattr(getattr(detector, "manifest", None), "input_kinds", ())
        ]
        detectors.sort(key=lambda detector: (
            getattr(detector.manifest, "detector_id", "") == "watchtower.application.abuse",
            getattr(detector.manifest, "detector_id", ""),
        ))
        claimed_protocol = False
        for detector in detectors:
            try:
                alerts = detector.detect(
                    stream=stream, flow_id=flow.flow_id, direction=direction,
                    timestamp=timestamp, truncated=truncated,
                    claimed_protocol=claimed_protocol,
                )
                for alert in alerts:
                    alert.timestamp = float(alert.timestamp or timestamp)
                    if alert.type == "CLEARTEXT_CREDENTIALS":
                        claimed_protocol = True
                    history_key = f"{detector.manifest.detector_id}:{alert.type}:canonical"
                    if alert.timestamp - float(flow.alert_history.get(history_key, -10_000.0)) < 300.0:
                        continue
                    self._add_flow_evidence(alert, flow)
                    if self._store_alert(
                        flow.flow_id[0], alert, detector=detector,
                        add_to_report=add_to_report,
                        capture_interface=capture_interface,
                        capture_session_id=capture_session_id,
                        capture_backend=capture_backend,
                    ):
                        flow.alert_history[history_key] = alert.timestamp
                        found.append(alert)
            except Exception as exc:
                self.plugin_loader.record_error(detector, exc)
        return found

    def process_live_flow(self, flow: FlowAggregate, source: str, capture_interface: str = None,
                          capture_session_id: str = None, capture_backend: str = None) -> List[ForensicAlert]:
        """Finalize flow-capable detectors through the same canonical finding sink."""
        self._source = source
        found = []
        subject = flow.flow_id[0]
        for detector in self.plugin_loader.get_detectors():
            manifest = getattr(detector, "manifest", None)
            if not detector.enabled or manifest is None or "flow" not in manifest.input_kinds:
                continue
            # Conversation-capable detectors receive every dirty generation through
            # process_live_conversation. Re-running them from snapshots duplicates
            # findings and makes detector timing depend on dashboard cadence.
            if "conversation" in manifest.input_kinds:
                continue
            try:
                alerts = detector.detect(
                    flow=flow, arrival_times=flow.arrival_times,
                    domain=flow.l7_metadata.get("dns_domain") or flow.l7_metadata.get("remote_hostname"),
                    metadata=flow.l7_metadata,
                )
                for alert in alerts:
                    if not alert.timestamp:
                        alert.timestamp = flow.last_seen
                    history_key = f"{manifest.detector_id}:{alert.type}"
                    cooldown = float(getattr(detector, "alert_cooldown_seconds", 300.0))
                    if float(alert.timestamp) - float(flow.alert_history.get(history_key, -10_000.0)) < cooldown:
                        continue
                    self._add_flow_evidence(alert, flow)
                    if self._store_alert(subject, alert, detector=detector,
                                         capture_interface=capture_interface,
                                         capture_session_id=capture_session_id,
                                         capture_backend=capture_backend):
                        flow.alert_history[history_key] = float(alert.timestamp)
                        found.append(alert)
            except Exception as exc:
                self.plugin_loader.record_error(detector, exc)
        return found

    def process_live_conversation(self, conversation, source: str,
                                  capture_interface: str = None,
                                  capture_session_id: str = None,
                                  capture_backend: str = None) -> List[ForensicAlert]:
        """Run conversation-state detectors through the canonical finding sink."""
        self._source = source
        found = []
        subject = str(conversation.initiator[0])
        for detector in self.plugin_loader.get_detectors():
            manifest = getattr(detector, "manifest", None)
            if not detector.enabled or manifest is None or "conversation" not in manifest.input_kinds:
                continue
            try:
                alerts = detector.detect(conversation=conversation) or []
                for alert in alerts:
                    alert.timestamp = float(alert.timestamp or conversation.event_time)
                    alert.evidence = dict(alert.evidence or {})
                    alert.evidence.setdefault("src_ip", conversation.initiator[0])
                    alert.evidence.setdefault("src_port", conversation.initiator[1])
                    alert.evidence.setdefault("dst_ip", conversation.responder[0])
                    alert.evidence.setdefault("dst_port", conversation.responder[1])
                    alert.evidence.setdefault("protocol", conversation.key.protocol)
                    if self._store_alert(
                        subject, alert, detector=detector,
                        add_to_report=True,
                        capture_interface=capture_interface,
                        capture_session_id=capture_session_id,
                        capture_backend=capture_backend,
                    ):
                        found.append(alert)
            except Exception as exc:
                self.plugin_loader.record_error(detector, exc)
        return found

    def note_live_behavior_signal(self, subject: str, signal_type: str, timestamp: float) -> None:
        for detector in self.plugin_loader.get_detectors():
            manifest = getattr(detector, "manifest", None)
            if not detector.enabled or manifest is None or "conversation" not in manifest.input_kinds:
                continue
            try:
                detector.detect(signal={
                    "subject": subject,
                    "type": signal_type,
                    "timestamp": float(timestamp),
                })
            except Exception as exc:
                self.plugin_loader.record_error(detector, exc)

    def analyze_flow(self, flow: FlowAggregate) -> List[ForensicAlert]:
        """Runs all loaded detectors against a flow aggregate.
        
        This is used for dynamic, automatic integration of new detectors.
        """
        all_alerts = []
        src_ip = flow.flow_id[0]
        domain = flow.l7_metadata.get("remote_hostname")
        
        for detector in self.plugin_loader.get_detectors():
            if not detector.enabled: continue
            manifest = getattr(detector, "manifest", None)
            if manifest is not None and "conversation" in manifest.input_kinds:
                continue
            try:
                # Some detectors work on packets, some on flows. 
                # We pass both if available, but here we only have the flow.
                alerts = detector.detect(flow=flow, domain=domain, arrival_times=flow.arrival_times)
                for alert in alerts:
                    if not alert.timestamp:
                        alert.timestamp = flow.last_seen
                    self._add_flow_evidence(alert, flow)
                    decision = self.db.alert_policy.evaluate(
                        src_ip, alert.type, alert.severity, alert.score,
                        alert.explanation, alert.evidence, alert.timestamp,
                    )
                    if not decision.suppressed:
                        all_alerts.append(alert)
            except Exception as e:
                self.plugin_loader.record_error(detector, e)
                if not self.silent: print(f"Flow detector error {detector.name}: {e}")
                
        return all_alerts

    # ----------------------------------------------------------------
    # Offline Mode: Full PCAP analysis
    # ----------------------------------------------------------------

    def _drain_evicted_native_conversations(self, *, force: bool = False) -> None:
        if not self._native_case_id or not self._native_analysis_id:
            return
        while self._conversation_tracker.pending_eviction_count and (
            force or self._conversation_tracker.pending_eviction_count >= 256
        ):
            batch = self._conversation_tracker.drain_evicted(256)
            try:
                self.db.save_forensic_conversations(
                    self._native_case_id,
                    self._native_analysis_id,
                    batch,
                    completeness="partial",
                    publish_component=False,
                )
            except Exception:
                self._native_persistence_failed = True
                logging.getLogger(__name__).exception(
                    "Unable to drain evicted native conversations for analysis %s",
                    self._native_analysis_id,
                )
                return

    def analyze_pcap(self, file_path: str, progress_callback=None, keylog_file=None, source_name=None,
                     mode: str = "auto", backend: str = None, cancel_event=None,
                     case_id: str = None, analysis_id: str = None,
                     conversation_source: str = None) -> ForensicReport:
        """Full offline PCAP analysis. Results written to SQLite."""
        backend = backend_policy.replay_backend(backend)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        if mode not in {"auto", "memory", "streaming"}:
            raise ValueError("mode must be auto, memory, or streaming")
        if backend not in {"python", "rust"}:
            raise ValueError("backend must be python or rust")

        total_bytes = os.path.getsize(file_path)
        selected_mode = "streaming" if mode == "auto" and total_bytes >= 2 * 1024 ** 3 else ("memory" if mode == "auto" else mode)

        self._current_progress_callback = progress_callback
        self._source = source_name if source_name else f"pcap:{os.path.basename(file_path)}"
        self._conversation_source = str(conversation_source or self._source)
        self._analysis_mode = selected_mode
        self._capture_backend = backend
        self._defer_encrypted_streams = backend == "rust"
        self.plugin_loader.reset(self._source)
        
        # Clear any previous analysis for this source
        self.db.clear_source(self._source)
        
        # Create a forensic report record
        report_id = self.db.create_report(self._source, time.time(), selected_mode, backend, total_bytes)
        
        # Load TLS keys if provided
        if keylog_file and os.path.exists(keylog_file):
            try:
                from scapy.layers.tls.session import TLSSession
                scapy.load_layer("tls")
                self.tls_session = TLSSession(sslkeylogfile=keylog_file)
                if not self.silent: print(f"[Forensics] Loaded TLS keylog: {keylog_file}")
            except Exception as e:
                if not self.silent: print(f"[Forensics] Error loading TLS keylog: {e}")

        self.report = ForensicReport()
        self.report.report_id = report_id
        self.report.case_id = case_id
        self.report.analysis_id = analysis_id
        self.report.link_type = "pcap-link-layer"
        self.report.parser_version = "watchtower-forensics-v2"
        self.report.source = file_path
        self.report.timestamp = time.time()
        self.report.analysis_mode = selected_mode
        self.report.total_bytes = total_bytes
        self.flow_table = {}
        self._raw_streams = {}
        self._raw_stream_bytes = {}
        self._fast_tls_payloads = set()
        self.identity_resolver = IdentityResolver()
        self._finalized_flow_count = 0
        self._pending_entities = {}
        self._pending_hardware_observations = []
        self._pending_flow_rows = []
        self._batch_entity_observations = True
        self._batch_hardware_observations = True
        # Offline captures have a complete flow table before finalization, so
        # persist one transaction rather than committing once per flow.
        self._batch_flow_persistence = selected_mode != "streaming"
        self._conversation_tracker = ConversationTracker()
        self._native_case_id = case_id
        self._native_analysis_id = analysis_id
        self._native_persistence_failed = False
        self._offline_parsers = tuple(
            parser for parser in self.plugin_loader.get_parsers() if parser.enabled
        )
        self._offline_parser_port_filters = {
            id(parser): frozenset(int(port) for port in getattr(parser, "watched_ports", ()) if int(port) >= 0)
            for parser in self._offline_parsers
        }
        enabled_detectors = tuple(
            detector for detector in self.plugin_loader.get_detectors() if detector.enabled
        )
        self._offline_packet_detectors = tuple(
            detector for detector in enabled_detectors
            if getattr(detector, "manifest", None) is None
            or "packet" in detector.manifest.input_kinds
        )
        self._offline_flow_detectors = tuple(
            detector for detector in enabled_detectors
            if getattr(detector, "manifest", None) is None
            or "flow" in detector.manifest.input_kinds
        )
        self._offline_stream_detectors = tuple(
            detector for detector in enabled_detectors
            if getattr(detector, "manifest", None) is not None
            and "stream" in detector.manifest.input_kinds
        )
        self._offline_fast_parsers = tuple(
            parser for parser in self._offline_parsers
            if getattr(parser, "fast_path", False) or parser.name in FAST_PATH_PARSER_NAMES
        )
        fast_parser_ids = {id(parser) for parser in self._offline_fast_parsers}
        self._offline_deep_decode_ports = frozenset(
            port
            for parser in self._offline_parsers
            if id(parser) not in fast_parser_ids
            for port in self._offline_parser_port_filters.get(id(parser), ())
        )
        self._offline_fast_packet_detectors = tuple(
            detector for detector in self._offline_packet_detectors
            if getattr(detector, "fast_path", False) or detector.name in FAST_PATH_DETECTOR_NAMES
        )
        self._offline_os_detectors = tuple(
            detector for detector in self._offline_flow_detectors
            if detector.name == "OS Fingerprinting Detector"
        )
        if selected_mode == "streaming":
            from core.forensics.stream_spool import SegmentSpool
            spool_dir = Path(self.data_dir) / "spool"
            spool_dir.mkdir(parents=True, exist_ok=True)
            spool_path = spool_dir / f"report-{report_id}.sqlite"
            self._segment_spool = SegmentSpool(spool_path)
            self.report.spool_path = str(spool_path)
        else:
            self._segment_spool = None

        processed_bytes = min(24, total_bytes)
        packet_count = 0
        capture_started_at = None
        capture_ended_at = None
        rust_analysis_result = {}
        rust_analysis_public = {}
        state, analysis_error = "COMPLETE", None
        try:
            if backend == "rust":
                from core.forensics.rust_plan import build_rust_analysis_plan
                from core.packet_engine.rust_capture import aggregate_replay_events

                rust_plan = build_rust_analysis_plan(
                    self._offline_parsers,
                    enabled_detectors,
                    source_type="network",
                    link_type="ethernet",
                    strict_aggregate=True,
                )
                packet_iterator = aggregate_replay_events(
                    file_path,
                    semantic_plugin_digest=rust_plan.semantic_plugin_digest,
                    analysis_mode=selected_mode,
                    origin={
                        "session_id": str(analysis_id or report_id),
                        "source_type": "network",
                        "device_id": "pcap",
                        "sensor_node_id": "local",
                        "source": self._source,
                    },
                    result=rust_analysis_result,
                    selector_programs=rust_plan.selector_programs,
                    cancel_event=cancel_event,
                )
                reader_context = None
            else:
                reader_context = scapy.PcapReader(file_path)
                packet_iterator = reader_context
            with warnings.catch_warnings(record=True) as read_warnings:
                warnings.simplefilter("always")
                for packet in packet_iterator:
                    if backend != "rust" and cancel_event is not None and (
                        (callable(cancel_event) and cancel_event()) or
                        (hasattr(cancel_event, "is_set") and cancel_event.is_set())
                    ):
                        state = "CANCELLED"
                        break
                    if backend == "rust":
                        self._process_packet_offline_fast(packet)
                        packet_size = int(packet.size or len(packet.raw or b""))
                        packet_time = float(packet.timestamp)
                    else:
                        self._process_packet_offline(packet)
                        packet_size = len(packet)
                        packet_time = float(packet.time)
                    capture_started_at = packet_time if capture_started_at is None else min(capture_started_at, packet_time)
                    capture_ended_at = packet_time if capture_ended_at is None else max(capture_ended_at, packet_time)
                    packet_count += 1
                    processed_bytes = min(total_bytes, processed_bytes + packet_size + 16)
                    if (
                        packet_count % OFFLINE_ENTITY_FLUSH_INTERVAL == 0
                        or len(self._pending_entities) >= OFFLINE_ENTITY_PENDING_LIMIT
                    ):
                        self._flush_pending_entities()
                    if (
                        len(self._pending_hardware_observations)
                        >= OFFLINE_HARDWARE_PENDING_LIMIT
                    ):
                        self._flush_pending_hardware_observations()
                    if selected_mode == "streaming" and packet_count % 10_000 == 0:
                        self._evict_idle_flows(packet_time)
                        self._segment_spool.commit()
                    if progress_callback and packet_count % 100 == 0:
                        progress_callback(processed_bytes, total_bytes)
                if reader_context is not None:
                    reader_context.close()
                elif backend == "rust" and hasattr(packet_iterator, "close"):
                    packet_iterator.close()
                if rust_analysis_result:
                    self._apply_rust_terminal_aggregates(rust_analysis_result)
                    terminal_status = rust_analysis_result.get("terminal_status")
                    if terminal_status == "partial" and state == "COMPLETE":
                        state = "PARTIAL"
                        analysis_error = str(
                            rust_analysis_result.get("error_code")
                            or "Rust aggregate analysis completed partially"
                        )
                    elif terminal_status == "cancelled":
                        state = "CANCELLED"
                    rust_analysis_public = {
                        key: value
                        for key, value in rust_analysis_result.items()
                        if not key.startswith("_")
                    }
                actionable_warnings = [
                    item for item in read_warnings
                    if not isinstance(item.message, ResourceWarning)
                ]
                if actionable_warnings and state == "COMPLETE":
                    state = "PARTIAL"
                    analysis_error = "; ".join(str(item.message) for item in actionable_warnings[-3:])
        except Exception as exc:
            state = "PARTIAL" if packet_count else "FAILED"
            analysis_error = str(exc)
            if not self.silent: print(f"Error reading PCAP: {exc}")

        hardware_flush_failed = False
        try:
            self._flush_pending_entities()
            try:
                self._flush_pending_hardware_observations()
            except Exception as exc:
                hardware_flush_failed = True
                if state == "COMPLETE":
                    state = "PARTIAL"
                hardware_error = (
                    f"Hardware observation persistence failed: {exc}"
                )
                analysis_error = (
                    f"{analysis_error}; {hardware_error}"
                    if analysis_error
                    else hardware_error
                )
                logging.getLogger(__name__).exception(hardware_error)
            if packet_count:
                self._finalize_offline_analysis()
                if rust_analysis_public:
                    self.report.summary["rust_aggregate"] = rust_analysis_public
                if hardware_flush_failed:
                    limitations = list(
                        self.report.summary.get("visibility_limitations") or []
                    )
                    limitation = "hardware_observations_unavailable"
                    if limitation not in limitations:
                        limitations.append(limitation)
                    self.report.summary["visibility_limitations"] = limitations
                if case_id and analysis_id:
                    try:
                        self._drain_evicted_native_conversations(force=True)
                        capacity_partial = (
                            self._conversation_tracker.had_evictions
                            or self._conversation_tracker.evidence_lost
                            or self._native_persistence_failed
                        )
                        if capacity_partial:
                            if state == "COMPLETE":
                                state = "PARTIAL"
                            limitations = list(
                                self.report.summary.get("visibility_limitations") or []
                            )
                            limitation = "native_conversation_capacity_exceeded"
                            if limitation not in limitations:
                                limitations.append(limitation)
                            self.report.summary["visibility_limitations"] = limitations
                        conversation_manifest = self.db.save_forensic_conversations(
                            case_id,
                            analysis_id,
                            self._conversation_tracker.finalize(),
                            completeness=(
                                "complete"
                                if state == "COMPLETE" and not capacity_partial
                                else "partial"
                            ),
                        )
                        self.report.summary["native_conversations"] = {
                            "state": conversation_manifest["state"],
                            "record_count": conversation_manifest["record_count"],
                            "sha256": conversation_manifest["sha256"],
                        }
                    except Exception:
                        logging.getLogger(__name__).exception(
                            "Unable to persist native conversations for analysis %s",
                            analysis_id,
                        )
                        if state == "COMPLETE":
                            state = "PARTIAL"
                        analysis_error = "Native conversation evidence is unavailable"
                        limitations = list(
                            self.report.summary.get("visibility_limitations") or []
                        )
                        if "native_conversations_unavailable" not in limitations:
                            limitations.append("native_conversations_unavailable")
                        self.report.summary["visibility_limitations"] = limitations
                        self.report.summary["native_conversations"] = {"state": "failed"}
            else:
                self.report.summary = {"total_flows": 0, "total_entities": 0, "total_alerts": 0,
                                       "high_risk_entities": 0, "carved_files": 0, "primary_suspect": None}
            if self._segment_spool:
                self._segment_spool.commit()
                self.report.summary["stream_truncated_segments"] = self._segment_spool.truncated_segments
                self.report.summary["stream_truncated_bytes"] = self._segment_spool.truncated_bytes
            if state == "COMPLETE":
                processed_bytes = total_bytes
                if progress_callback:
                    progress_callback(total_bytes, total_bytes)
            self.report.status = state
            self.report.capture_started_at = capture_started_at
            self.report.capture_ended_at = capture_ended_at
            self.report.bytes_processed = processed_bytes
            self.report.error = analysis_error
            self.report.summary.update({"analysis_status": state.lower(), "analysis_mode": selected_mode,
                                        "bytes_processed": processed_bytes, "total_bytes": total_bytes})

            self.db.update_report(
                report_id=report_id,
                total_flows=len(self.flow_table),
                total_entities=len(self.report.entities),
                total_alerts=sum(len(e.alerts) for e in self.report.entities.values()),
                summary=self.report.summary, status=state, bytes_processed=processed_bytes,
                error=analysis_error, spool_path=self.report.spool_path,
            )
        finally:
            if self._segment_spool:
                self._segment_spool.close()
                self._segment_spool = None
            self._batch_entity_observations = False
            self._batch_hardware_observations = False
            self._batch_flow_persistence = False
        if state == "FAILED":
            raise ValueError(f"PCAP analysis failed: {analysis_error or 'no packets decoded'}")
        return self.report

    def _process_packet_offline_fast(self, event: PacketEvent):
        """Process a Rust replay event without rebuilding a Scapy packet graph."""
        from core.forensics.fast_packet import FastPacket

        packet = FastPacket(event)
        if not packet.valid:
            return
        is_ndp = (
            packet.protocol_number == 58
            and packet.icmp is not None
            and packet.icmp.type in {133, 134, 135, 136}
        )
        connection = tuple(sorted(((packet.src_ip, packet.sport), (packet.dst_ip, packet.dport))))
        first_connection_payload = connection not in self._fast_tls_payloads
        if (
            event.raw
            and first_connection_payload
            and (
                is_ndp
                or packet.sport in self._offline_deep_decode_ports
                or packet.dport in self._offline_deep_decode_ports
            )
        ):
            try:
                if event.link_type == "raw-ip" and event.raw[0] >> 4 == 4:
                    deep_packet = scapy.IP(event.raw)
                elif event.link_type == "raw-ip" and event.raw[0] >> 4 == 6:
                    deep_packet = scapy.IPv6(event.raw)
                else:
                    deep_packet = scapy.Ether(event.raw)
            except Exception:
                pass
            else:
                deep_packet.time = float(event.timestamp)
                deep_packet.watchtower_origin = {
                    "session_id": event.session_id,
                    "source_type": event.source_type,
                    "device_id": event.interface,
                    "backend": event.backend,
                    "link_type": event.link_type,
                    "sensor_node_id": event.sensor_node_id,
                    "source": event.source,
                }
                self._process_packet_offline(deep_packet)
                return
        self._process_packet_offline(packet, fast_path=True)

    def _apply_rust_terminal_aggregates(self, result):
        """Project certified Rust terminal state into compatibility models."""
        flow_records = tuple(result.pop("_terminal_flows", ()))
        conversation_records = tuple(result.pop("_terminal_conversations", ()))
        protocol_names = {
            6: "TCP", 17: "UDP", 254: "ARP",
        }
        for record in flow_records:
            definition = record.definition
            protocol = protocol_names.get(definition.protocol, "OTHER")
            flow_id = (
                definition.source.address,
                definition.destination.address,
                definition.source_port,
                definition.destination_port,
                protocol,
            )
            flow = self.flow_table.get(flow_id)
            if flow is None:
                flow = FlowAggregate(
                    flow_id=flow_id,
                    start_time=record.start_time,
                    last_seen=record.last_seen,
                )
                self.flow_table[flow_id] = flow
            flow.start_time = record.start_time
            flow.last_seen = record.last_seen
            flow.packet_count = record.packet_count
            flow.byte_count = record.byte_count
            flow.tcp_syn_count = record.syn_count
            flow.tcp_syn_ack_count = record.syn_ack_count
            flow.tcp_rst_count = record.rst_count
            flow.packet_sizes = [size for size, _timestamp in record.samples]
            flow.arrival_times = [timestamp for _size, timestamp in record.samples]

        conversation_by_endpoints = {}
        flow_records_by_endpoints = {}
        for flow_record in flow_records:
            flow_definition = flow_record.definition
            endpoints = frozenset((
                (flow_definition.source.address, flow_definition.source_port),
                (flow_definition.destination.address, flow_definition.destination_port),
            ))
            flow_records_by_endpoints.setdefault(endpoints, []).append(flow_record)
        syn_replay = {}
        for record in conversation_records:
            definition = record.definition
            endpoints = frozenset((
                (definition.endpoint_a.address, definition.endpoint_a_port),
                (definition.endpoint_b.address, definition.endpoint_b_port),
            ))
            conversation_by_endpoints.setdefault(endpoints, record)

        from core.packet_engine.conversations import (
            ConversationDeltaV2,
            ConversationKey,
            ConversationState,
        )

        protocol_by_endpoints = {}
        observed_pairs = set()
        for flow_id, flow in self.flow_table.items():
            endpoints = frozenset(((flow_id[0], flow_id[2]), (flow_id[1], flow_id[3])))
            protocol_by_endpoints.setdefault(endpoints, flow_id[4])
            pair = (flow_id[0], flow_id[1])
            flow.l7_metadata.setdefault("peer_novelty", pair not in observed_pairs)
            observed_pairs.add(pair)
            record = conversation_by_endpoints.get(endpoints)
            if record is None:
                continue
            definition = record.definition
            initiator = (definition.initiator.address, definition.initiator_port)
            responder = (definition.responder.address, definition.responder_port)
            direction = "to_responder" if (flow_id[0], flow_id[2]) == initiator else "to_initiator"
            reverse_bytes = (
                record.to_initiator_bytes
                if direction == "to_responder"
                else record.to_responder_bytes
            )
            reverse_packets = (
                record.to_initiator_packets
                if direction == "to_responder"
                else record.to_responder_packets
            )
            flow.l7_metadata.update({
                "conversation_direction": direction,
                "initiator_ip": initiator[0],
                "initiator_port": initiator[1],
                "responder_ip": responder[0],
                "responder_port": responder[1],
                "reverse_byte_count": reverse_bytes,
                "reverse_packet_count": reverse_packets,
                "conversation_established": record.established,
                "conversation_syn_count": record.syn_count,
                "conversation_syn_ack_count": record.syn_ack_count,
                "conversation_rst_count": record.rst_count,
                "conversation_to_responder_bytes": record.to_responder_bytes,
                "conversation_to_initiator_bytes": record.to_initiator_bytes,
                "conversation_to_responder_packets": record.to_responder_packets,
                "conversation_to_initiator_packets": record.to_initiator_packets,
                "stateful_conversation_finalized": True,
            })

        for record in conversation_records:
            definition = record.definition
            protocol = protocol_names.get(definition.protocol, "OTHER")
            key = ConversationKey(
                sensor_node_id="local",
                source=self._conversation_source,
                session_id=self._conversation_source,
                interface="offline",
                protocol=protocol,
                endpoint_a=(definition.endpoint_a.address, definition.endpoint_a_port),
                endpoint_b=(definition.endpoint_b.address, definition.endpoint_b_port),
            )
            existing = self._conversation_tracker.states.get(key)
            application = dict(existing.application) if existing is not None else {}
            replay_after = float(existing.last_seen) if existing is not None else float("-inf")
            replay_records = flow_records_by_endpoints.get(frozenset((
                (definition.endpoint_a.address, definition.endpoint_a_port),
                (definition.endpoint_b.address, definition.endpoint_b_port),
            )), ())
            for flow_record in replay_records:
                flow_definition = flow_record.definition
                for sample_index, (size, timestamp) in enumerate(flow_record.samples):
                    if timestamp <= replay_after:
                        continue
                    if (
                        protocol == "TCP"
                        and flow_record.syn_count == flow_record.packet_count
                        and flow_record.packet_count > 0
                    ):
                        bucket_key = (
                            flow_definition.source.address,
                            flow_definition.destination.address,
                            int(timestamp),
                        )
                        bucket = syn_replay.setdefault(bucket_key, {
                            "key": key,
                            "initiator": (
                                flow_definition.source.address,
                                flow_definition.source_port,
                            ),
                            "responder": (
                                flow_definition.destination.address,
                                flow_definition.destination_port,
                            ),
                            "packets": 0,
                            "bytes": 0,
                        })
                        bucket["packets"] += 1
                        bucket["bytes"] += size
            state = ConversationState(
                key=key,
                initiator=(definition.initiator.address, definition.initiator_port),
                responder=(definition.responder.address, definition.responder_port),
                first_seen=definition.first_seen,
                last_seen=record.last_seen,
                to_responder_packets=record.to_responder_packets,
                to_responder_bytes=record.to_responder_bytes,
                to_initiator_packets=record.to_initiator_packets,
                to_initiator_bytes=record.to_initiator_bytes,
                syn_count=record.syn_count,
                syn_ack_count=record.syn_ack_count,
                rst_count=record.rst_count,
                established=record.established,
                application=application,
                generation=record.generation,
                backend="rust",
                source_type="network",
            )
            self._conversation_tracker.states[key] = state
            final_delta = ConversationDeltaV2(
                contract_version=2,
                key=key,
                generation=record.generation,
                event_time=record.last_seen,
                first_seen=definition.first_seen,
                initiator=state.initiator,
                responder=state.responder,
                direction="final",
                packet_delta=0,
                byte_delta=0,
                syn_delta=0,
                syn_ack_delta=0,
                rst_delta=0,
                to_responder_packets=record.to_responder_packets,
                to_responder_bytes=record.to_responder_bytes,
                to_initiator_packets=record.to_initiator_packets,
                to_initiator_bytes=record.to_initiator_bytes,
                syn_count=record.syn_count,
                syn_ack_count=record.syn_ack_count,
                rst_count=record.rst_count,
                established=record.established,
                application=application,
                backend="rust",
                source_type="network",
            )
            self.process_live_conversation(
                final_delta,
                source=self._source,
                capture_interface="offline",
                capture_session_id=self._conversation_source,
                capture_backend="rust",
            )

        syn_totals = {}
        for (src, dst, second), bucket in sorted(syn_replay.items()):
            pair = (src, dst)
            cumulative = syn_totals.setdefault(pair, {"packets": 0, "bytes": 0})
            cumulative["packets"] += bucket["packets"]
            cumulative["bytes"] += bucket["bytes"]
            delta = ConversationDeltaV2(
                contract_version=2,
                key=bucket["key"],
                generation=cumulative["packets"],
                event_time=float(second) + 0.999999,
                first_seen=float(second),
                initiator=bucket["initiator"],
                responder=bucket["responder"],
                direction="to_responder",
                packet_delta=bucket["packets"],
                byte_delta=bucket["bytes"],
                syn_delta=bucket["packets"],
                syn_ack_delta=0,
                rst_delta=0,
                to_responder_packets=cumulative["packets"],
                to_responder_bytes=cumulative["bytes"],
                to_initiator_packets=0,
                to_initiator_bytes=0,
                syn_count=cumulative["packets"],
                syn_ack_count=0,
                rst_count=0,
                established=False,
                application={},
                backend="rust",
                source_type="network",
            )
            self.process_live_conversation(
                delta,
                source=self._source,
                capture_interface="offline",
                capture_session_id=self._conversation_source,
                capture_backend="rust",
            )

    def _process_packet_offline(self, packet, fast_path: bool = False):
        """Full per-packet processing for offline mode (richer than live)."""
        import scapy.all as scapy
        
        # Automated Decapsulation (Peel the Onion)
        if not fast_path:
            packet = normalize_packet(packet)
                    
        if scapy.IP in packet:
            ip_layer = packet[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            hop_limit = ip_layer.ttl
        elif scapy.IPv6 in packet:
            ip_layer = packet[scapy.IPv6]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            hop_limit = ip_layer.hlim
        elif scapy.ARP in packet:
            ip_layer = None
            src_ip, dst_ip = packet[scapy.ARP].psrc, packet[scapy.ARP].pdst
            hop_limit = None
        else:
            return
        tcp = packet[scapy.TCP] if scapy.TCP in packet else None
        udp = packet[scapy.UDP] if scapy.UDP in packet else None
        transport = tcp or udp
        protocol = "ARP" if scapy.ARP in packet else ("TCP" if tcp else ("UDP" if udp else "OTHER"))
        src_port = int(transport.sport) if transport is not None else 0
        dst_port = int(transport.dport) if transport is not None else 0
        watchtower_probe = self._probe_registry.matches(
            src_ip, dst_ip, src_port, dst_port, protocol, float(packet.time),
        )
        flow_id = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        # SSL/TLS Decryption Attempt
        decrypted_payload = None
        if self.tls_session and not fast_path and packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            if tcp.payload and (tcp.sport == 443 or tcp.dport == 443 or tcp.sport == 636 or tcp.dport == 636):
                try:
                    from scapy.layers.tls.all import TLS
                    tls_pkt = TLS(bytes(tcp.payload), session=self.tls_session)
                    if hasattr(tls_pkt, "payload") and tls_pkt.payload:
                        decrypted_payload = bytes(tls_pkt.payload)
                except Exception:
                    pass

        # 1. Extract identities using plugins
        current_user = self.report.entities[src_ip].user if src_ip in self.report.entities else None
        
        identities = {"mac": None, "local_hostname": None, "netbios_name": None, "remote_hostname": None, "username": None, "full_name": None}
        # Layer-two identity is accepted only from parsers that prove an ARP or
        # NDP binding.  See process_live_packet for the routed-traffic reason.
            
        tls_info = {}
        protocol_metadata = {}
        if watchtower_probe: protocol_metadata["generated_by"] = "WatchTower"
        shared_payload = application_payload(packet)
        parser_context = {
            "username": current_user,
            "application_payload": shared_payload,
            "transport": transport,
            **dict(getattr(packet, "watchtower_origin", {}) or {}),
        }
        packet_ports = {src_port, dst_port}
        parsers = self._offline_fast_parsers if fast_path else self._offline_parsers
        for parser in parsers:
            watched_ports = self._offline_parser_port_filters.get(id(parser), ())
            if watched_ports and watched_ports.isdisjoint(packet_ports):
                continue
            if fast_path and not self._fast_parser_applies(parser, packet):
                continue
            try:
                res = parser.parse(packet, context=parser_context)
                if "identities" in res:
                    parser_identities = res["identities"]
                    if parser_identities.get("remote_hostname"):
                        identities["remote_hostname"] = parser_identities["remote_hostname"]
                    identities.update(self.identity_resolver.observe(
                        src_ip, parser.name, parser_identities, float(packet.time)
                    ))
                if "tls_info" in res:
                    tls_info.update(res["tls_info"])
                if "metadata" in res:
                    protocol_metadata.update(res["metadata"])
                for observation in res.get("observations", []):
                    self._persist_hardware_observation(observation)
                if "carved_files" in res:
                    for carved in res["carved_files"]:
                        self._save_carved_file(src_ip, flow_id, carved)
            except Exception as e:
                self.plugin_loader.record_error(parser, e)
                if not self.silent: print(f"Parser error {parser.name}: {e}")
                
        # Decrypted payload fallback
        if decrypted_payload:
            for parser in parsers:
                if hasattr(parser, 'extract_from_plaintext'):
                    try:
                        res = parser.extract_from_plaintext(decrypted_payload)
                        if res and "identities" in res:
                            identities.update(self.identity_resolver.observe(
                                src_ip, parser.name, res["identities"], float(packet.time)
                            ))
                        if res and "carved_files" in res:
                            for carved in res["carved_files"]:
                                self._save_carved_file(src_ip, flow_id, carved)
                    except Exception: pass

        # TLS Fingerprinting
        ja3_hash = tls_info.get("ja3")
        ja4_string = tls_info.get("ja4")
        tls_library = tls_info.get("library")
        
        if tls_info:
            if src_ip not in self.report.entities:
                self.report.entities[src_ip] = EntityProfile(ip=src_ip)
            
            profile = self.report.entities[src_ip]
            profile.ja3_hash = ja3_hash
            profile.ja4_string = ja4_string
            profile.tls_library = tls_library
            
            # Alert on known malware
            if profile.tls_library and any(m in profile.tls_library for m in ["Metasploit", "Empire", "Cobalt"]):
                alert = ForensicAlert(
                    timestamp=float(packet.time),
                    type="KNOWN_BAD",
                    severity="CRITICAL",
                    score=45.0,
                    explanation=f"TLS Fingerprint match: {profile.tls_library}",
                    evidence={"ja3": profile.ja3_hash, "ja4": profile.ja4_string}
                )
                self._store_alert(src_ip, alert, add_to_report=True)

        # Update in-memory entity
        resolved_identities = self.identity_resolver.values_for(src_ip)
        if identities.get("remote_hostname"):
            resolved_identities["remote_hostname"] = identities["remote_hostname"]
        self._update_entity_metadata(src_ip, resolved_identities)
        
        # OS Detection (in-memory & SQLite)
        os_info = "Unknown"
        for detector in self._offline_os_detectors:
            if watchtower_probe: continue
            if hasattr(detector, 'detect_os'):
                try:
                    res_os = detector.detect_os(hop_limit) if hop_limit is not None else None
                    if res_os and res_os != "Unknown": os_info = res_os
                except Exception: pass
                
        if src_ip in self.report.entities and not self.report.entities[src_ip].os:
            self.report.entities[src_ip].os = os_info

        if dst_ip not in self.report.entities:
            self.report.entities[dst_ip] = EntityProfile(ip=dst_ip)
            self._persist_entity_observation(
                ip=dst_ip, confidence=0.25, identity_source="ObservedDestination",
                packets=0, bytes_count=0, timestamp=float(packet.time), source=self._source,
            )

        # Also write to SQLite
        strongest = self.identity_resolver.strongest_source(src_ip)
        self._persist_entity_observation(
            ip=src_ip, mac=resolved_identities.get("mac"), hostname=resolved_identities.get("local_hostname"),
            netbios_name=resolved_identities.get("netbios_name"), username=resolved_identities.get("username"),
            full_name=resolved_identities.get("full_name"), os_info=os_info,
            confidence=strongest.confidence if strongest else 0.6,
            identity_source=strongest.source if strongest else "ForensicAnalysis",
            ja3_hash=ja3_hash, ja4_string=ja4_string, tls_library=tls_library,
            packets=1, bytes_count=len(packet), timestamp=float(packet.time), source=self._source
        )

        # Flow aggregation and bidirectional conversation attribution.
        tcp_flags = str(packet[scapy.TCP].flags) if scapy.TCP in packet else ""
        conversation_event = PacketEvent(
            timestamp=float(packet.time), src_ip=str(src_ip), dst_ip=str(dst_ip),
            src_port=int(src_port or 0), dst_port=int(dst_port or 0), protocol=protocol,
            size=len(packet), flags=tcp_flags, l7_info=dict(protocol_metadata),
            interface="offline", session_id=self._conversation_source,
            backend=self._capture_backend, source=self._conversation_source,
        )
        conversation_metadata, conversation_delta = self._conversation_tracker.update_with_delta(conversation_event)
        self._drain_evicted_native_conversations()
        protocol_metadata.update(conversation_metadata)
        self.process_live_conversation(
            conversation_delta,
            source=self._source,
            capture_interface="offline",
            capture_session_id=self._source,
            capture_backend=self._capture_backend,
        )
        if flow_id not in self.flow_table:
            self.flow_table[flow_id] = FlowAggregate(
                flow_id=flow_id, 
                start_time=float(packet.time), 
                last_seen=float(packet.time)
            )
        
        flow = self.flow_table[flow_id]
        flow.update(len(packet), float(packet.time), flags=tcp_flags, l7_info=protocol_metadata)
        reverse_flow_id = (dst_ip, src_ip, dst_port, src_port, protocol)
        reverse_flow = self.flow_table.get(reverse_flow_id)
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
        
        # TCP stream accumulation for reassembly
        if protocol == "TCP" and packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            if tcp.payload:
                payload = bytes(tcp.payload)
                
                if flow_id not in self._raw_streams and self._segment_spool is None:
                    self._raw_streams[flow_id] = {"to_server": [], "to_client": []}

                self._append_stream_segment(flow_id, "to_server", tcp.seq, payload, float(packet.time))
            
                # Reverse flow
                rev_flow_id = (dst_ip, src_ip, dst_port, src_port, protocol)
                if rev_flow_id in self._raw_streams or (
                    self._segment_spool is not None and rev_flow_id in self.flow_table
                ):
                    if tcp.payload:
                        self._append_stream_segment(
                            rev_flow_id, "to_client", tcp.seq, bytes(tcp.payload), float(packet.time)
                        )
        
        # Live detection rules
        packet_detectors = list(
            self._offline_fast_packet_detectors
            if fast_path else self._offline_packet_detectors
        )
        packet_detectors.sort(key=lambda detector: (
            getattr(detector.manifest, "detector_id", "") == "watchtower.application.abuse",
            getattr(detector.manifest, "detector_id", ""),
        ))
        claimed_protocol = False
        for detector in packet_detectors:
            if watchtower_probe: continue
            if fast_path and not self._fast_detector_applies(detector, packet):
                continue
            try:
                alerts = detector.detect(
                    packet=packet, flow=flow,
                    domain=identities.get("remote_hostname"), metadata=protocol_metadata,
                    application_payload=shared_payload,
                    claimed_protocol=claimed_protocol,
                )
                for alert in alerts:
                    if alert.type == "CLEARTEXT_CREDENTIALS":
                        claimed_protocol = True
                    alert.timestamp = float(packet.time)
                    self._add_flow_evidence(alert, flow)
                    if self._store_alert(
                        src_ip,
                        alert,
                        add_to_report=True,
                        detector=detector,
                        capture_interface="offline",
                        capture_session_id=self._conversation_source,
                        capture_backend=self._capture_backend,
                    ):
                        flow.alert_history[
                            f"{detector.manifest.detector_id}:{alert.type}:canonical"
                        ] = alert.timestamp
                    if alert.type == "AUTHENTICATION_ABUSE":
                        self.note_live_behavior_signal(
                            str((alert.evidence or {}).get("source") or src_ip),
                            "auth_failure",
                            float(packet.time),
                        )
            except Exception as e:
                self.plugin_loader.record_error(detector, e)
                if not self.silent: print(f"Detector error {detector.name}: {e}")

    def _fast_parser_applies(self, parser, packet) -> bool:
        """Avoid invoking generic Python plugins on irrelevant fast frames."""
        name = parser.name
        payload = packet.application_payload
        if name == "ARP and NDP Parser":
            return packet.arp is not None or packet.protocol_number == 58
        if name == "ICMP Metadata Parser":
            return packet.protocol_number in {1, 58}
        if name == "LLDP and CDP Parser":
            return bool(packet.ethernet and packet.ethernet.type == 0x88CC) or (
                b"\x01\x00\x0c\xcc\xcc\xcc" in packet.raw[:32]
            )
        if name == "QUIC Metadata Parser":
            return packet.protocol_number == 17 and 443 in {packet.sport, packet.dport} and bool(payload[:1] and payload[0] & 0x80)
        if name == "SSH Parser":
            return payload.startswith(b"SSH-")
        if name == "HTTP Parser":
            return payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ", b"HTTP/"))
        if name == "Full Name Scraper":
            # The parser's useful patterns are an LDAP common-name OID or a
            # UTF-16 display name.  Avoid regex-scanning ordinary bulk data.
            return b"\x06\x03\x55\x04\x03" in payload or b"\x00 \x00" in payload
        if name == "NTLM Parser":
            return b"NTLMSSP" in payload
        if name == "TLS Parser":
            return 443 in {packet.sport, packet.dport} and len(payload) >= 6 and payload[:2] == b"\x16\x03" and payload[5] == 0x01
        return True

    def _fast_detector_applies(self, detector, packet) -> bool:
        """Preserve detector semantics while skipping inert encrypted frames."""
        name = detector.name
        payload = packet.application_payload
        ports = {packet.sport, packet.dport}
        if name == "LAN Trust Detector":
            return packet.arp is not None or packet.protocol_number == 58
        if name == "Cleartext FTP Credential Detector":
            return packet.protocol_number == 6 and packet.dport == 21 and payload.startswith(b"PASS ")
        if name == "File Transfer Detector":
            return b"MZ" in payload
        if name == "IoT and OT Safety Detector":
            return packet.protocol_number == 6 and bool(payload) and bool(ports & {502, 1883})
        if name == "Application Abuse Detector":
            if packet.protocol_number in {1, 58}:
                # ICMP tunnel findings require high entropy.  A bounded
                # diversity sample cheaply rejects ordinary echo payloads
                # (including large padding-style payloads) before the
                # detector performs a full entropy calculation.
                return bool(payload) and len(set(payload[:256])) >= 16
            if packet.protocol_number != 6:
                return False
            if 443 not in ports:
                # These are the only packet-level conditions evaluated by
                # ApplicationAbuseDetector for non-TLS TCP payloads.  The
                # stream pass still handles fragmented secrets, so skipping
                # unrelated bulk bytes does not weaken reassembled evidence.
                sample = payload[:8192].lower()
                return (
                    b"password" in sample
                    or b"passwd" in sample
                    or b"authorization: basic" in sample
                    or (b"user " in sample and b" pass " in sample)
                    or b"authentication failed" in sample
                    or b"login failed" in sample
                    or b"invalid password" in sample
                    or b"535 authentication" in sample
                    or b"authentication successful" in sample
                    or b"login successful" in sample
                    or b"230 login successful" in sample
                    or payload.startswith((b"SSH-", b"RFB ", b"\x03\x00"))
                )
            if not payload:
                return "S" in packet.flags and "A" not in packet.flags
            connection = tuple(sorted(((packet.src_ip, packet.sport), (packet.dst_ip, packet.dport))))
            if connection in self._fast_tls_payloads:
                return False
            self._fast_tls_payloads.add(connection)
            return True
        return True

    def _append_stream_segment(self, flow_id, direction, sequence, payload, timestamp):
        """Append bounded TCP evidence without allowing one flow to exhaust memory."""
        if self._segment_spool is not None:
            self._segment_spool.append(flow_id, direction, sequence, payload, timestamp)
            return
        segments = self._raw_streams[flow_id][direction]
        if len(segments) >= MAX_STREAM_SEGMENTS:
            return
        key = (flow_id, direction)
        used = self._raw_stream_bytes.get(key, 0)
        remaining = MAX_STREAM_BYTES - used
        if remaining <= 0:
            return
        bounded_payload = payload[:remaining]
        if not bounded_payload:
            return
        segments.append({"seq": sequence, "payload": bounded_payload, "time": timestamp})
        self._raw_stream_bytes[key] = used + len(bounded_payload)

    def _update_entity_metadata(self, ip: str, identities: Dict[str, str]):
        """Update in-memory entity profile with extracted identities."""
        if ip not in self.report.entities:
            self.report.entities[ip] = EntityProfile(ip=ip)
        
        profile = self.report.entities[ip]
        if identities.get("mac"):
            profile.mac = identities["mac"]
        
        if identities.get("local_hostname"):
            profile.hostname = identities.get("local_hostname")
        elif identities.get("remote_hostname"):
            remote = identities["remote_hostname"].lower()
            noisy_domains = ["microsoft.com", "google.com", "bing.com", "cloudfront.net", "akamai", "windows.com"]
            if not any(d in remote for d in noisy_domains):
                if not profile.hostname:
                    profile.hostname = remote

        if identities.get("username"):
            profile.user = identities["username"]
        
        if identities.get("full_name"):
            profile.full_name = identities["full_name"]
        elif identities.get("username") and not profile.full_name:
            if "\\" in identities["username"]:
                parts = identities["username"].split("\\")
                profile.user = parts[-1]

    def _evict_idle_flows(self, now: float, idle_seconds: float = 300.0):
        """Persist inactive streaming aggregates and release their packet samples."""
        stale = [flow_id for flow_id, flow in self.flow_table.items() if now - flow.last_seen >= idle_seconds]
        if len(self.flow_table) - len(stale) > 10_000:
            stale_set = set(stale)
            remaining = ((flow.last_seen, flow_id) for flow_id, flow in self.flow_table.items() if flow_id not in stale_set)
            overflow = len(self.flow_table) - len(stale) - 10_000
            stale.extend(flow_id for _seen, flow_id in sorted(remaining)[:overflow])
        for flow_id in stale:
            self._finalize_flow(flow_id, self.flow_table.pop(flow_id))

    def _persist_entity_observation(self, **entity):
        if not self._batch_entity_observations:
            self.db.upsert_entity(**entity)
            return
        ip = entity["ip"]
        pending = self._pending_entities.get(ip)
        if pending is None:
            self._pending_entities[ip] = dict(entity)
            return
        pending["packets"] = int(pending.get("packets") or 0) + int(entity.get("packets") or 0)
        pending["bytes_count"] = int(pending.get("bytes_count") or 0) + int(entity.get("bytes_count") or 0)
        pending["timestamp"] = max(float(pending.get("timestamp") or 0), float(entity.get("timestamp") or 0))
        for key, value in entity.items():
            if value is not None and key not in {"packets", "bytes_count", "timestamp"}:
                pending[key] = value

    def _flush_pending_entities(self):
        if not self._pending_entities:
            return
        self.db.bulk_upsert_entities(list(self._pending_entities.values()))
        self._pending_entities.clear()

    def _persist_hardware_observation(self, observation):
        if not self._batch_hardware_observations:
            self.db.insert_hardware_observation(observation)
            return
        if (
            len(self._pending_hardware_observations)
            >= OFFLINE_HARDWARE_PENDING_LIMIT
        ):
            self._flush_pending_hardware_observations()
        self._pending_hardware_observations.append(dict(observation))
        if (
            len(self._pending_hardware_observations)
            >= OFFLINE_HARDWARE_PENDING_LIMIT
        ):
            self._flush_pending_hardware_observations()

    def _flush_pending_hardware_observations(self):
        if not self._pending_hardware_observations:
            return
        self.db.bulk_insert_hardware_observations(
            self._pending_hardware_observations
        )
        self._pending_hardware_observations.clear()

    def _finalize_flow(self, flow_id, flow):
        src_ip = flow_id[0]
        if src_ip in self.report.entities:
            profile = self.report.entities[src_ip]
            profile.total_packets += flow.packet_count
            profile.total_bytes += flow.byte_count
            profile.unique_destinations.add(flow_id[1])
            if len(profile.flows) < 10_000:
                profile.flows.append(flow_id)
            for detector in self._offline_flow_detectors:
                if flow.l7_metadata.get("generated_by") == "WatchTower": continue
                if (
                    getattr(getattr(detector, "manifest", None), "detector_id", "")
                    == "watchtower.stateful.host"
                    and flow.l7_metadata.get("stateful_conversation_finalized")
                ):
                    arrivals = flow.arrival_times or ()
                    beacon_eligible = (
                        len(arrivals) >= 20
                        and float(arrivals[-1]) - float(arrivals[0]) >= 120.0
                    )
                    if not beacon_eligible:
                        continue
                try:
                    alerts = detector.detect(flow=flow, arrival_times=flow.arrival_times)
                    for alert in alerts:
                        self._add_flow_evidence(alert, flow)
                        self._store_alert(src_ip, alert, add_to_report=True, detector=detector)
                except Exception as exc:
                    self.plugin_loader.record_error(detector, exc)
                    if not self.silent: print(f"Detector error {detector.name}: {exc}")

        packet_count, byte_count = flow.packet_count, flow.byte_count
        start_time = flow.start_time
        if self._analysis_mode == "streaming":
            existing = self.db.get_flow_by_key(flow_id, self._source)
            if existing:
                packet_count += int(existing.get("packet_count") or 0)
                byte_count += int(existing.get("byte_count") or 0)
                start_time = min(start_time, float(existing.get("start_time") or start_time))
        mean, stddev = flow.interarrival_stats()
        flow_row = {
            "src_ip": flow_id[0], "dst_ip": flow_id[1], "src_port": flow_id[2], "dst_port": flow_id[3],
            "protocol": flow_id[4], "start_time": start_time, "last_seen": flow.last_seen,
            "packet_count": packet_count, "byte_count": byte_count,
            "tcp_syn_count": flow.tcp_syn_count, "tcp_rst_count": flow.tcp_rst_count,
            "avg_packet_size": flow.avg_packet_size(), "duration": flow.duration(),
            "interarrival_mean": mean, "interarrival_std": stddev,
            "packet_size_variance": flow.packet_size_variance(), "l7_metadata": flow.l7_metadata,
            "source": self._source,
        }
        if self._batch_flow_persistence:
            self._pending_flow_rows.append(flow_row)
        else:
            self.db.upsert_flow(**flow_row)
        self._finalized_flow_count += 1

    def _finalize_offline_analysis(self):
        """Post-processing: beaconing, lateral movement, reassembly, carving."""
        primary_suspect = None
        max_risk = 0.0

        for flow_id, flow in list(self.flow_table.items()):
            self._finalize_flow(flow_id, flow)

        if self._pending_flow_rows:
            self.db.bulk_upsert_flows(self._pending_flow_rows)
            self._pending_flow_rows.clear()

        # Build one scoped identity card for every endpoint in persisted
        # conversations. This is additive and does not alter captured evidence.
        try:
            from core.intelligence.endpoint_identity import EndpointIdentityResolver

            identity_records = EndpointIdentityResolver(self.db.get_source_flows(self._source)).resolve(
                self._source, "offline", self._source,
            )
            self.db.upsert_endpoint_identities([record.to_dict() for record in identity_records])
        except (TypeError, ValueError):
            # Legacy malformed addresses remain visible as entities without
            # causing a complete PCAP analysis to be marked failed.
            pass

        if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
            for profile in self.report.entities.values():
                profile_as_of = max((float(alert.timestamp or 0.0) for alert in profile.alerts), default=self.report.timestamp)
                assessment = self.db.recompute_risk(
                    profile.ip, source=self._source, as_of=profile_as_of,
                    asset_role=getattr(profile, "asset_role", None), persist=True,
                )
                profile.risk_score = assessment["priority_score"]

        # Identify Primary Suspect
        for profile in self.report.entities.values():
            if profile.risk_score > max_risk:
                max_risk = profile.risk_score
                primary_suspect = profile
        
        # Store streams for the report (needed for CLI dive command)
        self.report.streams = self.flow_table

        # Reassemble and carve
        self._reassemble_and_carve(progress_callback=self._current_progress_callback)

        # Build reproducible passive profiles after every flow has been persisted.
        from core.intelligence.local_assets import LocalAssetProfiler
        profiler = LocalAssetProfiler(self.db)
        try:
            profiler.build_many(list(self.report.entities), source=self._source)
        except ValueError:
            # A malformed legacy IP must not invalidate the PCAP report.
            pass

        # Calculate summary
        total_flows = self.db.count_flows(self._source) if self._analysis_mode == "streaming" else len(self.flow_table)
        self.report.summary = {
            "total_flows": total_flows,
            "total_entities": len(self.report.entities),
            "total_alerts": sum(len(e.alerts) for e in self.report.entities.values()),
            "high_risk_entities": len([e for e in self.report.entities.values() if e.risk_score > 50]),
            "carved_files": sum(len(e.carved_files) for e in self.report.entities.values()),
            "primary_suspect": {
                "ip": primary_suspect.ip,
                "mac": primary_suspect.mac,
                "hostname": primary_suspect.hostname,
                "user": primary_suspect.user,
                "risk_score": primary_suspect.risk_score
            } if primary_suspect else None
        }

    def _reassemble_and_carve(self, progress_callback=None):
        """Reassemble TCP streams and carve files from them."""
        if not self._raw_streams and self._segment_spool is None:
            return
            
        vt_client = VirusTotalClient()
        if self._segment_spool is not None:
            total_streams = self._segment_spool.flow_count()
            stream_items = ((flow_id, self._segment_spool.load(flow_id)) for flow_id in self._segment_spool.flow_ids())
        else:
            total_streams = len(self._raw_streams)
            stream_items = iter(list(self._raw_streams.items()))
        
        if total_streams > 0:
            if not self.silent: print(f"\n[Forensics] Reassembling {total_streams} TCP streams and carving files...")
        
        for idx, (flow_id, directions) in enumerate(stream_items):
            if progress_callback and idx % 10 == 0:
                progress_callback(98 + (idx / total_streams) * 2, 100)

            # Encrypted application records cannot be carved or meaningfully
            # inspected without a supplied key log.  Retain the bounded
            # segments for the current report, but defer costly reassembly of
            # TLS traffic until decryption is actually possible.
            if self._defer_encrypted_streams and self.tls_session is None and {int(flow_id[2]), int(flow_id[3])} & {443, 636}:
                flow = self.report.streams.get(flow_id)
                if flow is not None:
                    flow.l7_metadata.setdefault("stream_processing", "deferred_encrypted")
                continue

            for dir_key in ["to_server", "to_client"]:
                segments = directions[dir_key]
                if not segments or not isinstance(segments, list):
                    continue
                
                segments.sort(key=lambda x: x["seq"])
                
                chunks = []
                last_seq = -1
                assembled_size = 0
                for seg in segments:
                    seq = seg["seq"]
                    payload = seg["payload"]
                    if last_seq == -1:
                        chunks.append(payload)
                        assembled_size += len(payload)
                        last_seq = seq + len(payload)
                    elif seq == last_seq and assembled_size + len(payload) <= MAX_STREAM_BYTES:
                        chunks.append(payload)
                        assembled_size += len(payload)
                        last_seq += len(payload)
                    elif seq > last_seq:
                        gap_size = seq - last_seq
                        if gap_size <= MAX_REASSEMBLY_GAP and assembled_size + gap_size + len(payload) <= MAX_STREAM_BYTES:
                            chunks.append(b"\x00" * gap_size)
                            chunks.append(payload)
                            assembled_size += gap_size + len(payload)
                            last_seq = seq + len(payload)
                
                reassembled = b"".join(chunks)[:MAX_STREAM_BYTES]
                
                # TLS Decryption on full stream
                if self.tls_session and (flow_id[2] == 443 or flow_id[3] == 443 or flow_id[2] == 636 or flow_id[3] == 636):
                    try:
                        from scapy.layers.tls.all import TLS
                        tls_stream = TLS(reassembled, session=self.tls_session)
                        if hasattr(tls_stream, "payload") and tls_stream.payload:
                            reassembled = bytes(tls_stream.payload)
                    except Exception:
                        pass

                # Update the stream in report
                if flow_id in self.report.streams:
                    flow = self.report.streams[flow_id]
                    if dir_key == "to_server":
                        flow.reassembled_to_server = reassembled
                    else:
                        flow.reassembled_to_client = reassembled
                
                # Carve files
                if reassembled:
                    flow = self.report.streams.get(flow_id)
                    timestamp = float(getattr(flow, "last_seen", 0.0) or 0.0)
                    if flow is not None:
                        self.process_live_stream(
                            flow,
                            reassembled,
                            dir_key,
                            timestamp,
                            capture_interface="offline",
                            capture_session_id=self._conversation_source,
                            capture_backend=self._capture_backend,
                            add_to_report=True,
                        )
                    self._carve_from_data(reassembled, flow_id, vt_client)

    def load_stream(self, flow_id, report: ForensicReport = None) -> Dict[str, bytes]:
        """Lazily retrieve a spooled stream after a streaming analysis completes."""
        report = report or self.report
        if not report.spool_path or not Path(report.spool_path).exists():
            flow = report.streams.get(flow_id)
            return {
                "to_server": getattr(flow, "reassembled_to_server", b"") or b"",
                "to_client": getattr(flow, "reassembled_to_client", b"") or b"",
            } if flow else {"to_server": b"", "to_client": b""}
        from core.forensics.stream_spool import SegmentSpool
        spool = SegmentSpool(report.spool_path)
        try:
            directions = spool.load(flow_id)
            result = {}
            for direction, segments in directions.items():
                result[direction] = b"".join(item["payload"] for item in sorted(segments, key=lambda item: item["seq"]))[:MAX_STREAM_BYTES]
            return result
        finally:
            spool.close()

    def _save_carved_file(self, src_ip: str, flow_id: tuple, file_dict: dict):
        """Save a file carved directly by a parser (e.g. SMB)."""
        filename = file_dict.get("filename", "unknown_carved")
        content = file_dict.get("content", b"")
        if not content: return
        
        file_sha = get_file_hash(content)
        ext = "." + filename.split('.')[-1] if '.' in filename else ".bin"
        
        # Deduplicate - check if we already have this hash
        for existing in self.report.entities.get(src_ip, EntityProfile(ip=src_ip)).carved_files:
            if existing.sha256 == file_sha:
                return

        carved = CarvedFile(
            filename=filename,
            extension=ext,
            sha256=file_sha,
            size=len(content),
            flow_id=flow_id,
            timestamp=time.time(),
            data=content if len(content) < 1024*1024 else None
        )
        
        # Optional: VT Check could go here, but we'll do it async or skip for now to keep it fast
        
        if src_ip not in self.report.entities:
            self.report.entities[src_ip] = EntityProfile(ip=src_ip)
            
        self.report.entities[src_ip].carved_files.append(carved)

        self.db.insert_carved_file(
            entity_ip=src_ip,
            filename=filename,
            extension=ext,
            sha256=file_sha,
            size=len(content),
            flow_src=f"{flow_id[0]}:{flow_id[2]}",
            flow_dst=f"{flow_id[1]}:{flow_id[3]}",
            timestamp=carved.timestamp,
            data=carved.data,
            source=self._source,
        )
        
        # Optionally write to disk
        if self.data_dir:
            carve_dir = os.path.join(self.data_dir, "carved")
            os.makedirs(carve_dir, exist_ok=True)
            with open(os.path.join(carve_dir, f"{file_sha[:12]}_{filename}"), "wb") as f:
                f.write(content)

    def _carve_from_data(self, data: bytes, flow_id: tuple, vt_client: VirusTotalClient):
        """Scan reassembled stream for file signatures and carve them."""
        src_ip = flow_id[0]
        
        signatures = {
            "PE": (b"MZ", b"This program cannot be run in DOS mode", ".exe"),
            "ELF": (b"\x7fELF", None, ".elf"),
            "ZIP": (b"PK\x03\x04", None, ".zip"),
            "PNG": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", ".png")
        }
        
        for name, (header, footer, ext) in signatures.items():
            if header in data:
                start_idx = data.find(header)
                end_idx = -1
                
                if footer:
                    footer_idx = data.find(footer, start_idx)
                    if footer_idx != -1:
                        end_idx = footer_idx + len(footer)
                else:
                    end_idx = len(data)

                if end_idx != -1 and (end_idx - start_idx) > 100:
                    carved_data = data[start_idx:end_idx]
                    file_sha = get_file_hash(carved_data)
                    
                    carved = CarvedFile(
                        filename=f"carved_{file_sha[:8]}{ext}",
                        extension=ext,
                        sha256=file_sha,
                        size=len(carved_data),
                        flow_id=flow_id,
                        timestamp=time.time(),
                        data=carved_data if len(carved_data) < 1024*1024 else None
                    )
                    
                    # VT Check
                    carved.vt_results = vt_client.check_hash(file_sha)
                    
                    # Add to in-memory report
                    if src_ip in self.report.entities:
                        self.report.entities[src_ip].carved_files.append(carved)
                        
                        if carved.vt_results and carved.vt_results.get("malicious", 0) > 0:
                            alert = ForensicAlert(
                                timestamp=time.time(),
                                type="MALICIOUS_FILE",
                                severity="CRITICAL",
                                score=80.0,
                                explanation=f"Carved file {carved.filename} identified as MALICIOUS by VirusTotal ({carved.vt_results['malicious']} engines)",
                                evidence={"sha256": file_sha, "vt": carved.vt_results}
                            )
                            self._store_alert(src_ip, alert, add_to_report=True)
                    
                    # Write to SQLite
                    self.db.insert_carved_file(
                        entity_ip=src_ip,
                        filename=carved.filename,
                        extension=ext,
                        sha256=file_sha,
                        size=len(carved_data),
                        flow_src=f"{flow_id[0]}:{flow_id[2]}",
                        flow_dst=f"{flow_id[1]}:{flow_id[3]}",
                        timestamp=time.time(),
                        vt_results=carved.vt_results,
                        data=carved_data if len(carved_data) < 1024*1024 else None,
                        source=self._source
                    )
