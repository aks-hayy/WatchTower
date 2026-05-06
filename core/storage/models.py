from sqlalchemy import Column, Integer, String, Float, ForeignKey, Boolean, LargeBinary, Text, Index, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
from datetime import date

Base = declarative_base()

class Entity(Base):
    __tablename__ = "entities"
    ip = Column(String, primary_key=True)
    mac = Column(String, index=True)
    hostname = Column(String)
    netbios_name = Column(String)
    username = Column(String)
    full_name = Column(String)
    os = Column(String)
    vendor = Column(String)
    device_type = Column(String)
    asset_role = Column(String) # e.g. "Workstation", "IoT", "Server"
    confidence_score = Column(Float, default=0.0)
    identity_source = Column(String) # e.g. "Passive", "Active:NetBIOS", "Active:DNS"
    ja3_hash = Column(String)
    ja4_string = Column(String)
    tls_library = Column(String)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    first_seen = Column(Float)
    last_seen = Column(Float)
    reverse_dns = Column(String)
    source = Column(String, default="live")

    alerts = relationship("Alert", back_populates="entity", cascade="all, delete-orphan")
    carved_files = relationship("CarvedFile", back_populates="entity", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    timestamp = Column(Float)
    type = Column(String)
    severity = Column(String)
    score = Column(Float)
    explanation = Column(String)
    evidence = Column(Text) # JSON string
    source = Column(String, default="live")
    
    # AI 2.0 Fields
    ai_verdict = Column(String) # THREAT, FALSE_POSITIVE, UNKNOWN
    ai_reasoning = Column(Text)
    ai_status = Column(String, default="PENDING") # PENDING, INVESTIGATING, DONE, ERROR
    ai_cycle = Column(Integer, default=1)
    is_hidden = Column(Boolean, default=False) # For suppressed FPs

    entity = relationship("Entity", back_populates="alerts")

class Flow(Base):
    __tablename__ = "flows"
    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    start_time = Column(Float)
    last_seen = Column(Float)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    tcp_syn_count = Column(Integer, default=0)
    tcp_rst_count = Column(Integer, default=0)
    avg_packet_size = Column(Float, default=0)
    duration = Column(Float, default=0)
    interarrival_mean = Column(Float, default=0)
    interarrival_std = Column(Float, default=0)
    packet_size_variance = Column(Float, default=0)
    l7_metadata = Column(Text) # JSON string
    session_date = Column(String)
    source = Column(String, default="live")

    __table_args__ = (
        UniqueConstraint('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'source', name='_flow_uc'),
    )

class CarvedFile(Base):
    __tablename__ = "carved_files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    filename = Column(String)
    extension = Column(String)
    sha256 = Column(String, unique=True)
    size = Column(Integer)
    flow_src = Column(String)
    flow_dst = Column(String)
    timestamp = Column(Float)
    vt_results = Column(Text) # JSON string
    data = Column(LargeBinary)
    source = Column(String, default="live")

    entity = relationship("Entity", back_populates="carved_files")

class DailyStats(Base):
    __tablename__ = "daily_stats"
    date = Column(String, primary_key=True)
    source = Column(String, primary_key=True, default="live")
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    total_flows = Column(Integer, default=0)
    snapshot_count = Column(Integer, default=0)
    protocol_distribution = Column(Text) # JSON string
    port_distribution = Column(Text) # JSON string
    top_talkers = Column(Text) # JSON string

class Timeline(Base):
    __tablename__ = "timeline"
    timestamp = Column(Integer, primary_key=True)
    source = Column(String, primary_key=True, default="live")
    date = Column(String, nullable=False)
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)

class ForensicReport(Base):
    __tablename__ = "forensic_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String)
    timestamp = Column(Float)
    total_flows = Column(Integer, default=0)
    total_entities = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    summary = Column(Text) # JSON string

class SystemMetadata(Base):
    __tablename__ = "system_metadata"
    key = Column(String, primary_key=True)
    value = Column(String)

# --- AI 2.0 Models ---

class BehavioralBaseline(Base):
    __tablename__ = "behavioral_baselines"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    pattern_key = Column(String, index=True) # e.g. "port_usage", "comm_pair"
    pattern_data = Column(Text) # JSON string
    confidence = Column(Float, default=0.0)
    last_updated = Column(Float)
    source = Column(String, default="live")

class InvestigationStep(Base):
    __tablename__ = "investigation_steps"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    timestamp = Column(Float)
    thought = Column(Text)
    action = Column(String)
    observation = Column(Text)

class AIUserFeedback(Base):
    """Stores user's confirmation or rejection of AI verdicts to prevent redundant re-investigation."""
    __tablename__ = "ai_user_feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String, index=True)
    entity_ip = Column(String, index=True)
    user_verdict = Column(String) # AGREE, DISAGREE
    timestamp = Column(Float)
