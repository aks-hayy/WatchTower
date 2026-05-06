# core/forensics/engine.py

import os
import scapy.all as scapy
from scapy.layers.inet import IP
import logging

# Suppress scapy warnings that slow down parsing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy.conf.logLevel = logging.ERROR
from core.forensics.models import ForensicReport, EntityProfile, ForensicAlert, CarvedFile
from core.forensics.plugin_loader import PluginLoader
from core.packet_engine.schemas import FlowAggregate, PacketEvent
from core.forensics.forwarder import AlertForwarder
from core.packet_engine.capture import packet_to_event
from core.forensics.vt_client import VirusTotalClient, get_file_hash
from core.storage.database import WatchtowerDB
from core.packet_engine.utils import normalize_packet
from typing import Dict, List, Optional, Tuple
import time
import hashlib

class ForensicsEngine:
    """Shared forensic analysis module used by both live pipeline and offline analysis.
    
    Two modes of operation:
    1. Live mode:  process_live_packet() called per-packet from flow_worker
    2. Offline mode: analyze_pcap() processes an entire PCAP file
    
    Both modes write to the same SQLite database.
    """

    def __init__(self, db: WatchtowerDB = None, data_dir: str = "data", silent: bool = False):
        self.silent = silent
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
        
        # Source tag for this session
        self._source = "live"
        self._vendor_cache = {}

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

    # ----------------------------------------------------------------
    # Live Mode: Per-packet processing for flow_worker
    # ----------------------------------------------------------------

    def process_live_packet(self, packet, flow: FlowAggregate = None) -> Tuple[Dict, List[ForensicAlert]]:
        """Lightweight per-packet processing for live capture.
        
        Extracts identities and runs live detection rules.
        Writes entity updates to SQLite.
        Returns (identities, alerts).
        """
        if IP not in packet:
            return {}

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # 1. Run Parsers
        all_found_alerts = []
        identities = {
            "mac": None, "local_hostname": None, "netbios_name": None, 
            "remote_hostname": None, "username": None, "full_name": None,
            "device_type": None, "vendor": None
        }
        if scapy.Ether in packet:
            identities["mac"] = packet[scapy.Ether].src
            identities["vendor"] = self.get_vendor(identities["mac"])
            
        tls_info = {}
        for parser in self.plugin_loader.get_parsers():
            if not parser.enabled: continue
            try:
                res = parser.parse(packet)
                if "identities" in res:
                    for k, v in res["identities"].items():
                        if v: identities[k] = v
                if "tls_info" in res:
                    tls_info.update(res["tls_info"])
            except Exception as e:
                if not self.silent: print(f"Parser error {parser.name}: {e}")

        ja3_hash = tls_info.get("ja3")
        ja4_string = tls_info.get("ja4")
        tls_library = tls_info.get("library")
        
        if tls_library and any(m in tls_library for m in ["Metasploit", "Empire", "Cobalt"]):
            self.db.insert_alert(
                entity_ip=src_ip, timestamp=float(packet.time),
                alert_type="KNOWN_BAD", severity="CRITICAL", score=45.0,
                explanation=f"TLS Fingerprint match: {tls_library}",
                evidence={"ja3": ja3_hash, "ja4": ja4_string}, source=self._source
            )
            self.forwarder.forward(ForensicAlert(type="KNOWN_BAD", severity="CRITICAL", score=45.0, explanation=f"TLS Fingerprint match: {tls_library}", evidence={"ja3": ja3_hash, "ja4": ja4_string}, timestamp=float(packet.time)), src_ip)

        # 2. Run Detectors
        os_info = "Unknown"
        for detector in self.plugin_loader.get_detectors():
            if not detector.enabled: continue
            try:
                if hasattr(detector, 'detect_os'):
                    res_os = detector.detect_os(ip_layer.ttl)
                    if res_os and res_os != "Unknown": os_info = res_os
                
                alerts = detector.detect(packet=packet, flow=flow, domain=identities.get("remote_hostname"))
                for alert in alerts:
                    all_found_alerts.append(alert)
                    alert.timestamp = float(packet.time)
                    self.db.insert_alert(
                        entity_ip=src_ip, timestamp=alert.timestamp,
                        alert_type=alert.type, severity=alert.severity,
                        score=alert.score, explanation=alert.explanation,
                        evidence=alert.evidence, source=self._source
                    )
                    self.forwarder.forward(alert, src_ip)
            except Exception as e:
                if not self.silent: print(f"Detector error {detector.name}: {e}")

        # Upsert entity with all discovered metadata
        self.db.upsert_entity(
            ip=src_ip,
            mac=identities.get("mac"),
            vendor=identities.get("vendor"),
            device_type=identities.get("device_type"),
            hostname=identities.get("local_hostname"),
            netbios_name=identities.get("netbios_name"),
            username=identities.get("username"),
            full_name=identities.get("full_name"),
            os_info=os_info,
            confidence=0.5, # Passive confidence
            identity_source="Passive",
            ja3_hash=ja3_hash,
            ja4_string=ja4_string,
            tls_library=tls_library,
            packets=1,
            bytes_count=len(packet),
            timestamp=float(packet.time),
            source=self._source
        )

        return identities, all_found_alerts

    def analyze_flow(self, flow: FlowAggregate) -> List[ForensicAlert]:
        """Runs all loaded detectors against a flow aggregate.
        
        This is used for dynamic, automatic integration of new detectors.
        """
        all_alerts = []
        src_ip = flow.flow_id[0]
        domain = flow.l7_metadata.get("remote_hostname")
        
        for detector in self.plugin_loader.get_detectors():
            if not detector.enabled: continue
            try:
                # Some detectors work on packets, some on flows. 
                # We pass both if available, but here we only have the flow.
                alerts = detector.detect(flow=flow, domain=domain, arrival_times=flow.arrival_times)
                for alert in alerts:
                    if not alert.timestamp:
                        alert.timestamp = flow.last_seen
                    all_alerts.append(alert)
            except Exception as e:
                if not self.silent: print(f"Flow detector error {detector.name}: {e}")
                
        return all_alerts

    # ----------------------------------------------------------------
    # Offline Mode: Full PCAP analysis
    # ----------------------------------------------------------------

    def analyze_pcap(self, file_path: str, progress_callback=None, keylog_file=None, source_name=None) -> ForensicReport:
        """Full offline PCAP analysis. Results written to SQLite."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        self._current_progress_callback = progress_callback
        self._source = source_name if source_name else f"pcap:{os.path.basename(file_path)}"
        
        # Clear any previous analysis for this source
        self.db.clear_source(self._source)
        
        # Create a forensic report record
        report_id = self.db.create_report(source=self._source, timestamp=time.time())
        
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
        self.report.source = file_path
        self.report.timestamp = time.time()
        self.flow_table = {}
        self._raw_streams = {}
        
        # Process packets
        try:
            with scapy.PcapReader(file_path) as reader:
                i = 0
                for packet in reader:
                    self._process_packet_offline(packet)
                    i += 1
                    if progress_callback and i % 100 == 0:
                        progress_callback(i, i + 1000)
        except Exception as e:
            if not self.silent: print(f"Error reading PCAP: {e}")
        
        # Post-processing
        self._finalize_offline_analysis()
        
        # Update the report record in DB
        self.db.update_report(
            report_id=report_id,
            total_flows=len(self.flow_table),
            total_entities=len(self.report.entities),
            total_alerts=sum(len(e.alerts) for e in self.report.entities.values()),
            summary=self.report.summary
        )
        
        return self.report

    def _process_packet_offline(self, packet):
        """Full per-packet processing for offline mode (richer than live)."""
        import scapy.all as scapy
        
        # Automated Decapsulation (Peel the Onion)
        packet = normalize_packet(packet)
                    
        if scapy.IP not in packet:
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # SSL/TLS Decryption Attempt
        decrypted_payload = None
        if self.tls_session and packet.haslayer(scapy.TCP):
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
        if scapy.Ether in packet:
            identities["mac"] = packet[scapy.Ether].src
            
        tls_info = {}
        for parser in self.plugin_loader.get_parsers():
            if not parser.enabled: continue
            try:
                res = parser.parse(packet, context={"username": current_user})
                if "identities" in res:
                    for k, v in res["identities"].items():
                        if v: identities[k] = v
                if "tls_info" in res:
                    tls_info.update(res["tls_info"])
                if "carved_files" in res:
                    for carved in res["carved_files"]:
                        self._save_carved_file(src_ip, flow_id, carved)
            except Exception as e:
                if not self.silent: print(f"Parser error {parser.name}: {e}")
                
        # Decrypted payload fallback
        if decrypted_payload:
            for parser in self.plugin_loader.get_parsers():
                if not parser.enabled: continue
                if hasattr(parser, 'extract_from_plaintext'):
                    try:
                        res = parser.extract_from_plaintext(decrypted_payload)
                        if res and "identities" in res:
                            for k, v in res["identities"].items():
                                if v: identities[k] = v
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
                self.report.add_alert(src_ip, alert)
                # Also write to DB
                self.db.insert_alert(
                    entity_ip=src_ip, timestamp=float(packet.time),
                    alert_type="KNOWN_BAD", severity="CRITICAL", score=45.0,
                    explanation=alert.explanation, evidence=alert.evidence,
                    source=self._source
                )
                self.forwarder.forward(alert, src_ip)

        # Update in-memory entity
        self._update_entity_metadata(src_ip, identities)
        
        # OS Detection (in-memory & SQLite)
        os_info = "Unknown"
        for detector in self.plugin_loader.get_detectors():
            if not detector.enabled: continue
            if hasattr(detector, 'detect_os'):
                try:
                    res_os = detector.detect_os(ip_layer.ttl)
                    if res_os and res_os != "Unknown": os_info = res_os
                except Exception: pass
                
        if src_ip in self.report.entities and not self.report.entities[src_ip].os:
            self.report.entities[src_ip].os = os_info

        # Also write to SQLite
        self.db.upsert_entity(
            ip=src_ip, mac=identities.get("mac"), hostname=identities.get("local_hostname"),
            netbios_name=identities.get("netbios_name"), username=identities.get("username"),
            full_name=identities.get("full_name"), os_info=os_info,
            confidence=0.6, identity_source="ForensicAnalysis",
            ja3_hash=ja3_hash, ja4_string=ja4_string, tls_library=tls_library,
            packets=1, bytes_count=len(packet), timestamp=float(packet.time), source=self._source
        )

        # Flow aggregation
        protocol = "OTHER"
        if scapy.TCP in packet: protocol = "TCP"
        elif scapy.UDP in packet: protocol = "UDP"
        
        src_port = packet[scapy.TCP].sport if scapy.TCP in packet else (packet[scapy.UDP].sport if scapy.UDP in packet else 0)
        dst_port = packet[scapy.TCP].dport if scapy.TCP in packet else (packet[scapy.UDP].dport if scapy.UDP in packet else 0)
        
        flow_id = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        if flow_id not in self.flow_table:
            self.flow_table[flow_id] = FlowAggregate(
                flow_id=flow_id, 
                start_time=float(packet.time), 
                last_seen=float(packet.time)
            )
        
        flow = self.flow_table[flow_id]
        flow.update(len(packet), float(packet.time))
        
        # TCP stream accumulation for reassembly
        if protocol == "TCP" and packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            if tcp.payload:
                payload = bytes(tcp.payload)
                
                if flow_id not in self._raw_streams:
                    self._raw_streams[flow_id] = {"to_server": [], "to_client": []}
                
                self._raw_streams[flow_id]["to_server"].append({
                    "seq": tcp.seq,
                    "payload": payload,
                    "time": float(packet.time)
                })
            
                # Reverse flow
                rev_flow_id = (dst_ip, src_ip, dst_port, src_port, protocol)
                if rev_flow_id in self._raw_streams:
                    if tcp.payload:
                        self._raw_streams[rev_flow_id]["to_client"].append({
                            "seq": tcp.seq,
                            "payload": bytes(tcp.payload),
                            "time": float(packet.time)
                        })
        
        # Live detection rules
        for detector in self.plugin_loader.get_detectors():
            if not detector.enabled: continue
            try:
                alerts = detector.detect(packet=packet, flow=flow, domain=identities.get("remote_hostname"))
                for alert in alerts:
                    alert.timestamp = float(packet.time)
                    self.report.add_alert(src_ip, alert)
                    self.db.insert_alert(
                        entity_ip=src_ip, timestamp=alert.timestamp,
                        alert_type=alert.type, severity=alert.severity,
                        score=alert.score, explanation=alert.explanation,
                        evidence=alert.evidence, source=self._source
                    )
                    self.forwarder.forward(alert, src_ip)
            except Exception as e:
                if not self.silent: print(f"Detector error {detector.name}: {e}")

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

    def _finalize_offline_analysis(self):
        """Post-processing: beaconing, lateral movement, reassembly, carving."""
        primary_suspect = None
        max_risk = 0.0

        for flow_id, flow in self.flow_table.items():
            src_ip = flow_id[0]
            
            if src_ip in self.report.entities:
                profile = self.report.entities[src_ip]
                profile.total_packets += flow.packet_count
                profile.total_bytes += flow.byte_count
                profile.unique_destinations.add(flow_id[1])
                profile.flows.append(flow_id)

                # Beaconing and Exfiltration detection
                for detector in self.plugin_loader.get_detectors():
                    if not detector.enabled: continue
                    try:
                        alerts = detector.detect(flow=flow, arrival_times=flow.arrival_times)
                        for alert in alerts:
                            self.report.add_alert(src_ip, alert)
                            self.db.insert_alert(
                                entity_ip=src_ip, timestamp=alert.timestamp,
                                alert_type=alert.type, severity=alert.severity,
                                score=alert.score, explanation=alert.explanation,
                                evidence=alert.evidence, source=self._source
                            )
                            self.forwarder.forward(alert, src_ip)
                    except Exception as e:
                        if not self.silent: print(f"Detector error {detector.name}: {e}")
                    
                # Lateral Movement Detection
                if src_ip.startswith("192.168.") or src_ip.startswith("10."):
                    if len(profile.unique_destinations) > 10:
                        internal_dests = [d for d in profile.unique_destinations if d.startswith("192.168.") or d.startswith("10.")]
                        if len(internal_dests) > 5:
                            lat_alert = ForensicAlert(
                                timestamp=0.0,
                                type="INTERNAL_SCANNING",
                                severity="HIGH",
                                explanation=f"Host is scanning internal network (targets: {len(internal_dests)})",
                                score=40.0
                            )
                            self.report.add_alert(src_ip, lat_alert)
                            self.db.insert_alert(
                                entity_ip=src_ip, timestamp=0.0,
                                alert_type="INTERNAL_SCANNING", severity="HIGH",
                                score=40.0,
                                explanation=lat_alert.explanation,
                                source=self._source
                            )
                            self.forwarder.forward(lat_alert, src_ip)
            
            # Write flow to SQLite
            self.db.upsert_flow(
                src_ip=flow_id[0], dst_ip=flow_id[1],
                src_port=flow_id[2], dst_port=flow_id[3],
                protocol=flow_id[4],
                start_time=flow.start_time, last_seen=flow.last_seen,
                packet_count=flow.packet_count, byte_count=flow.byte_count,
                source=self._source
            )

        # Identify Primary Suspect
        for profile in self.report.entities.values():
            if profile.risk_score > max_risk:
                max_risk = profile.risk_score
                primary_suspect = profile
        
        # Store streams for the report (needed for CLI dive command)
        self.report.streams = self.flow_table

        # Reassemble and carve
        self._reassemble_and_carve(progress_callback=self._current_progress_callback)

        # Calculate summary
        self.report.summary = {
            "total_flows": len(self.flow_table),
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
        if not self._raw_streams:
            return
            
        vt_client = VirusTotalClient()
        total_streams = len(self._raw_streams)
        
        if total_streams > 0:
            if not self.silent: print(f"\n[Forensics] Reassembling {total_streams} TCP streams and carving files...")
        
        for idx, (flow_id, directions) in enumerate(list(self._raw_streams.items())):
            if progress_callback and idx % 10 == 0:
                progress_callback(98 + (idx / total_streams) * 2, 100)

            for dir_key in ["to_server", "to_client"]:
                segments = directions[dir_key]
                if not segments or not isinstance(segments, list):
                    continue
                
                segments.sort(key=lambda x: x["seq"])
                
                chunks = []
                last_seq = -1
                for seg in segments:
                    seq = seg["seq"]
                    payload = seg["payload"]
                    if last_seq == -1:
                        chunks.append(payload)
                        last_seq = seq + len(payload)
                    elif seq == last_seq:
                        chunks.append(payload)
                        last_seq += len(payload)
                    elif seq > last_seq:
                        gap_size = seq - last_seq
                        if gap_size < 1000000:
                            chunks.append(b"\x00" * gap_size)
                            chunks.append(payload)
                            last_seq = seq + len(payload)
                
                reassembled = b"".join(chunks)
                
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
                    self._carve_from_data(reassembled, flow_id, vt_client)

    def _save_carved_file(self, src_ip: str, flow_id: tuple, file_dict: dict):
        """Save a file carved directly by a parser (e.g. SMB)."""
        filename = file_dict.get("filename", "unknown_carved")
        content = file_dict.get("content", b"")
        if not content: return
        
        from core.forensics.utils import get_file_hash
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
                            self.report.add_alert(src_ip, alert)
                            self.db.insert_alert(
                                entity_ip=src_ip, timestamp=time.time(),
                                alert_type="MALICIOUS_FILE", severity="CRITICAL",
                                score=80.0, explanation=alert.explanation,
                                evidence=alert.evidence, source=self._source
                            )
                    
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
