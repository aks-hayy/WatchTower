# core/forensics/models.py

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import time

@dataclass
class ForensicAlert:
    timestamp: float
    type: str  # "BEACONING", "SUSPICIOUS_DNS", "EXFILTRATION", "LATERAL_MOVEMENT", "KNOWN_BAD"
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    score: float
    explanation: str
    evidence: Dict = field(default_factory=dict)

@dataclass
class CarvedFile:
    filename: str
    extension: str
    sha256: str
    size: int
    flow_id: Tuple
    timestamp: float
    vt_results: Optional[Dict] = None
    data: Optional[bytes] = None # Optional because we might not want to keep it in the report object

@dataclass
class EntityProfile:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    full_name: Optional[str] = None
    os: Optional[str] = None
    
    # TLS Fingerprinting
    ja3_hash: Optional[str] = None
    ja4_string: Optional[str] = None
    tls_library: Optional[str] = None
    
    # Kerberos PAC Metadata
    pac_display_name: Optional[str] = None
    pac_logon_time: Optional[str] = None
    pac_groups: List[str] = field(default_factory=list) # List of SIDs


    
    # Aggregated stats
    total_packets: int = 0
    total_bytes: int = 0
    unique_destinations: Set[str] = field(default_factory=set)
    
    # Forensic context
    flows: List[Tuple] = field(default_factory=list) # List of flow_ids
    alerts: List[ForensicAlert] = field(default_factory=list)
    carved_files: List[CarvedFile] = field(default_factory=list)
    risk_score: float = 0.0

@dataclass
class ForensicReport:
    report_id: Optional[int] = None
    case_id: Optional[str] = None
    analysis_id: Optional[str] = None
    pcap_sha256: Optional[str] = None
    capture_started_at: Optional[float] = None
    capture_ended_at: Optional[float] = None
    link_type: Optional[str] = None
    parser_version: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    source: str = "" # PCAP filename or "LIVE"
    entities: Dict[str, EntityProfile] = field(default_factory=dict) # IP -> Profile
    streams: Dict[Tuple, Dict[str, bytes]] = field(default_factory=dict) # flow_id -> {"to_server": b"", "to_client": b""}
    summary: Dict = field(default_factory=dict)
    status: str = "RUNNING"
    analysis_mode: str = "memory"
    bytes_processed: int = 0
    total_bytes: int = 0
    error: Optional[str] = None
    spool_path: Optional[str] = None
    
    def add_alert(self, ip: str, alert: ForensicAlert):
        if ip not in self.entities:
            self.entities[ip] = EntityProfile(ip=ip)
        self.entities[ip].alerts.append(alert)
        self.entities[ip].risk_score += alert.score
