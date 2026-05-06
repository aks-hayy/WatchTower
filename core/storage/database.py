import os
import threading
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import date

from sqlalchemy import create_engine, select, update, insert, delete, func, or_
from sqlalchemy.orm import sessionmaker, scoped_session
from core.storage.models import Base, Entity, Alert, Flow, CarvedFile, DailyStats, Timeline, ForensicReport, SystemMetadata
from core.utils.logger import setup_logger
import os

logger = setup_logger("database")

class WatchtowerDB:
    """Thread-safe database manager using SQLAlchemy."""

    def __init__(self, data_dir: str = None):
        from core.context import context
        self.data_dir = Path(data_dir or context.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "watchtower.db"
        
        # SQLITE_URL = f"sqlite:///{self.db_path}"
        # On Windows, need 3 slashes if absolute path, but relative is fine with 2 or 3
        # We'll use absolute path with 4 slashes for reliability
        abs_path = os.path.abspath(self.db_path).replace("\\", "/")
        self.engine = create_engine(
            f"sqlite:///{abs_path}", 
            connect_args={"check_same_thread": False},
            pool_pre_ping=True
        )
        
        # Enable WAL mode for better concurrency on Windows
        from sqlalchemy import event
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()
        
        self.session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(self.session_factory)
        
        self.alert_callback = None
        self._init_schema()

    def _init_schema(self):
        """Create all tables and ensure schema is up-to-date."""
        Base.metadata.create_all(self.engine)
        
        # Ensure new Identity and AI 2.0 columns exist (Safe for existing DBs)
        self._ensure_column_exists("entities", "reverse_dns", "TEXT")
        self._ensure_column_exists("entities", "confidence_score", "REAL DEFAULT 0.0")
        self._ensure_column_exists("entities", "vendor", "TEXT")
        self._ensure_column_exists("entities", "device_type", "TEXT")
        self._ensure_column_exists("entities", "asset_role", "TEXT")
        self._ensure_column_exists("alerts", "ai_verdict", "TEXT")
        self._ensure_column_exists("alerts", "ai_status", "TEXT DEFAULT 'PENDING'")
        self._ensure_column_exists("alerts", "is_hidden", "BOOLEAN DEFAULT 0")

        # Create the missing unique constraint on flows if it doesn't exist
        # SQLite doesn't support ADD CONSTRAINT well, so we use a UNIQUE INDEX
        self._ensure_unique_index("flows", "idx_flow_unique", ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "source"])

    def _ensure_unique_index(self, table: str, index_name: str, columns: list[str]):
        """Ensure a unique index exists on the specified columns."""
        from sqlalchemy import text
        cols_str = ", ".join(columns)
        try:
            with self.engine.connect() as conn:
                # Check if index exists
                cursor = conn.execute(text(f"PRAGMA index_list({table})"))
                indices = [row[1] for row in cursor]
                if index_name not in indices:
                    logger.info(f"Schema update: creating unique index {index_name} on {table}")
                    conn.execute(text(f"CREATE UNIQUE INDEX {index_name} ON {table} ({cols_str})"))
                    conn.commit()
        except Exception as e:
            logger.debug(f"Index creation failed for {table}.{index_name}: {e}")

    def _ensure_column_exists(self, table: str, column: str, col_type: str):
        """Safe utility to add a column if it doesn't exist."""
        from sqlalchemy import text
        try:
            with self.engine.connect() as conn:
                cursor = conn.execute(text(f"PRAGMA table_info({table})"))
                existing = [row[1] for row in cursor]
                if column not in existing:
                    logger.info(f"Schema update: adding {column} to {table}")
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                    conn.commit()
        except Exception as e:
            logger.debug(f"Column check skipped for {table}.{column}: {e}")

    def _get_session(self):
        """Get the current scoped session."""
        return self.Session()

    def commit(self):
        """Commit the current session transaction."""
        self.Session.commit()

    def rollback(self):
        """Rollback the current session transaction."""
        self.Session.rollback()

    def remove(self):
        """Remove the current scoped session."""
        self.Session.remove()

    # ----------------------------------------------------------------
    # Entity Operations
    # ----------------------------------------------------------------

    def upsert_entity(self, ip: str = None, **kwargs):
        """Deprecated: Use bulk_upsert_entities for performance."""
        if ip: kwargs["ip"] = ip
        return self.bulk_upsert_entities([kwargs])

    def bulk_upsert_entities(self, entities: List[Dict]):
        """Perform high-performance bulk upsert for entities using SQLite ON CONFLICT."""
        if not entities: return []
        
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        
        # Column mapping for backward compatibility
        MAPPING = {
            "packets": "total_packets",
            "bytes_count": "total_bytes",
            "timestamp": "last_seen",
            "confidence": "confidence_score",
            "os_info": "os"
        }
        
        # Get valid column names
        valid_cols = {c.name for c in Entity.__table__.columns}
        
        try:
            for entity_data in entities:
                # Sanitize and map input data
                sanitized = {}
                for k, v in entity_data.items():
                    target_k = MAPPING.get(k, k)
                    if target_k in valid_cols:
                        sanitized[target_k] = v
                
                ip = sanitized.get("ip")
                if not ip: continue
                
                stmt = sqlite_insert(Entity).values(**sanitized)
                
                # Define columns to update on conflict
                # Note: confidence_score logic (only update if higher) is harder with raw SQL upsert
                # For now we'll overwrite, or we could use a CASE statement in SET.
                update_cols = {
                    "mac": stmt.excluded.mac,
                    "hostname": stmt.excluded.hostname,
                    "netbios_name": stmt.excluded.netbios_name,
                    "username": stmt.excluded.username,
                    "full_name": stmt.excluded.full_name,
                    "os": stmt.excluded.os,
                    "vendor": stmt.excluded.vendor,
                    "device_type": stmt.excluded.device_type,
                    "confidence_score": stmt.excluded.confidence_score,
                    "identity_source": stmt.excluded.identity_source,
                    "ja3_hash": stmt.excluded.ja3_hash,
                    "ja4_string": stmt.excluded.ja4_string,
                    "tls_library": stmt.excluded.tls_library,
                    "reverse_dns": stmt.excluded.reverse_dns,
                    "total_packets": Entity.total_packets + stmt.excluded.total_packets,
                    "total_bytes": Entity.total_bytes + stmt.excluded.total_bytes,
                    "risk_score": Entity.risk_score + stmt.excluded.risk_score,
                    "last_seen": func.max(Entity.last_seen, stmt.excluded.last_seen),
                }
                
                upsert_stmt = stmt.on_conflict_do_update(
                    index_elements=['ip'],
                    set_=update_cols
                )
                session.execute(upsert_stmt)
            
            session.commit()
            return []
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk entity upsert failed: {e}")
            raise e

    def get_entity(self, ip: str) -> Optional[Dict]:
        """Get a single entity by IP."""
        session = self._get_session()
        entity = session.query(Entity).filter_by(ip=ip).first()
        if entity:
            # Convert to dict for backward compatibility
            return {c.name: getattr(entity, c.name) for c in entity.__table__.columns}
        return None

    def get_all_entities(self, source: str = None) -> List[Dict]:
        """Get all entities, optionally filtered by source, with counts."""
        session = self._get_session()
        
        # Optimized query to get entities + alert counts + carved file counts in one go
        from sqlalchemy import select, func, outerjoin
        
        # Subqueries for counts
        alert_counts = session.query(
            Alert.entity_ip, func.count(Alert.id).label("alert_count")
        ).group_by(Alert.entity_ip).subquery()
        
        carved_counts = session.query(
            CarvedFile.entity_ip, func.count(CarvedFile.id).label("carved_count")
        ).group_by(CarvedFile.entity_ip).subquery()
        
        query = session.query(
            Entity, 
            func.coalesce(alert_counts.c.alert_count, 0).label("alert_count"),
            func.coalesce(carved_counts.c.carved_count, 0).label("carved_file_count")
        ).outerjoin(alert_counts, Entity.ip == alert_counts.c.entity_ip)\
         .outerjoin(carved_counts, Entity.ip == carved_counts.c.entity_ip)
        
        if source:
            query = query.filter(Entity.source == source)
            
        entities = query.order_by(Entity.risk_score.desc()).all()
        
        result = []
        for e, alert_count, carved_count in entities:
            d = {c.name: getattr(e, c.name) for c in e.__table__.columns}
            d["alert_count"] = alert_count
            d["carved_file_count"] = carved_count
            # active_risk still needs to be computed or fetched
            d["active_risk"] = e.risk_score # Fallback
            result.append(d)
            
        return result

    # ----------------------------------------------------------------
    # Alert Operations
    # ----------------------------------------------------------------

    def insert_alert(self, entity_ip: str, timestamp: float, alert_type: str,
                     severity: str, score: float, explanation: str,
                     evidence: Dict = None, source: str = "live", commit: bool = True):
        """Insert an alert and update entity risk score."""
        session = self._get_session()
        alert = Alert(
            entity_ip=entity_ip, timestamp=timestamp, type=alert_type,
            severity=severity, score=score, explanation=explanation,
            evidence=json.dumps(evidence) if evidence else None, source=source
        )
        session.add(alert)
        
        from core.storage.models import Entity
        # Also bump entity risk score (ensure entity exists first)
        entity = session.query(Entity).filter_by(ip=entity_ip).first()
        if not entity:
            # Create a placeholder entity if it doesn't exist
            entity = Entity(ip=entity_ip, risk_score=0.0, source=source)
            session.add(entity)
            session.flush()
        
        entity.risk_score = (entity.risk_score or 0.0) + score
            
        if commit:
            session.commit()
            
        if self.alert_callback:
            try:
                self.alert_callback({
                    "id": alert.id,
                    "entity_ip": entity_ip, "timestamp": timestamp,
                    "type": alert_type, "severity": severity,
                    "score": score, "explanation": explanation,
                    "evidence": evidence, "source": source
                })
            except Exception:
                pass

    def get_alerts(self, entity_ip: str = None, source: str = None, limit: int = 100) -> List[Dict]:
        """Get alerts, optionally filtered."""
        session = self._get_session()
        query = session.query(Alert)
        if entity_ip:
            query = query.filter_by(entity_ip=entity_ip)
        if source:
            if source == "live":
                from sqlalchemy import or_
                query = query.filter(Alert.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        
        alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
        result = []
        for a in alerts:
            d = {c.name: getattr(a, c.name) for c in a.__table__.columns}
            if d.get("evidence"):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    def update_alert_ai(self, alert_id: int, verdict: str = None, reasoning: str = None, 
                        status: str = None, cycle: int = None, is_hidden: bool = None):
        """Update AI metadata for an alert."""
        session = self._get_session()
        alert = session.query(Alert).filter_by(id=alert_id).first()
        if alert:
            if verdict: alert.ai_verdict = verdict
            if reasoning: alert.ai_reasoning = reasoning
            if status: alert.ai_status = status
            if cycle is not None: alert.ai_cycle = cycle
            if is_hidden is not None: alert.is_hidden = is_hidden
            session.commit()

    def recalibrate_risk_from_alert(self, alert_id: int, multiplier: float = -1.0):
        """
        Adjust entity risk score based on an alert (usually to subtract for FPs).
        multiplier: -1.0 to completely undo the score, or 0.5 to halve it, etc.
        """
        session = self._get_session()
        alert = session.query(Alert).filter_by(id=alert_id).first()
        if alert and alert.entity_ip:
            entity = session.query(Entity).filter_by(ip=alert.entity_ip).first()
            if entity:
                adjustment = (alert.score or 0.0) * multiplier
                entity.risk_score = max(0.0, (entity.risk_score or 0.0) + adjustment)
                session.commit()
                logger.info(f"Recalibrated risk for {alert.entity_ip}: {adjustment:+.1f} (Alert ID: {alert_id})")

    # ----------------------------------------------------------------
    # AI Feedback & Baselines
    # ----------------------------------------------------------------

    def log_investigation_step(self, alert_id: int, thought: str, action: str, observation: str):
        """Log a single step of the AI investigation for transparency."""
        from core.storage.models import InvestigationStep
        session = self._get_session()
        step = InvestigationStep(
            alert_id=alert_id, timestamp=time.time(),
            thought=thought, action=action, observation=observation
        )
        session.add(step)
        session.commit()

    def check_user_feedback(self, alert_type: str, entity_ip: str) -> Optional[str]:
        """Check if the user has already approved/rejected this type of alert for this entity."""
        from core.storage.models import AIUserFeedback
        session = self._get_session()
        fb = session.query(AIUserFeedback).filter_by(
            alert_type=alert_type, entity_ip=entity_ip
        ).order_by(AIUserFeedback.timestamp.desc()).first()
        return fb.user_verdict if fb else None

    def upsert_user_feedback(self, alert_type: str, entity_ip: str, verdict: str):
        from core.storage.models import AIUserFeedback
        session = self._get_session()
        fb = AIUserFeedback(
            alert_type=alert_type, entity_ip=entity_ip,
            user_verdict=verdict, timestamp=time.time()
        )
        session.add(fb)
        session.commit()

    def get_investigation_steps(self, alert_id: int) -> List[Dict]:
        from core.storage.models import InvestigationStep
        session = self._get_session()
        steps = session.query(InvestigationStep).filter_by(alert_id=alert_id).order_by(InvestigationStep.timestamp.asc()).all()
        return [{c.name: getattr(s, c.name) for c in s.__table__.columns} for s in steps]

    # ----------------------------------------------------------------
    # Flow Operations
    # ----------------------------------------------------------------

    def upsert_flow(self, **kwargs):
        """Deprecated: Use bulk_upsert_flows for high-performance capture."""
        return self.bulk_upsert_flows([kwargs])

    def bulk_upsert_flows(self, flows: List[Dict]):
        """Perform high-performance bulk upsert using SQLite ON CONFLICT."""
        if not flows: return []
        
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        today_str = date.today().isoformat()
        
        # Get valid column names
        valid_cols = {c.name for c in Flow.__table__.columns}
        
        try:
            for flow_data in flows:
                # Sanitize and handle defaults
                sanitized = {}
                for k, v in flow_data.items():
                    if k in valid_cols:
                        sanitized[k] = v
                
                if "session_date" not in sanitized:
                    sanitized["session_date"] = today_str
                
                # Handle JSON serialization for l7_metadata
                if "l7_metadata" in sanitized and isinstance(sanitized["l7_metadata"], dict):
                    sanitized["l7_metadata"] = json.dumps(sanitized["l7_metadata"])

                stmt = sqlite_insert(Flow).values(**sanitized)
                
                # Define columns to update on conflict
                update_cols = {
                    "last_seen": stmt.excluded.last_seen,
                    "packet_count": stmt.excluded.packet_count,
                    "byte_count": stmt.excluded.byte_count,
                    "tcp_syn_count": stmt.excluded.tcp_syn_count,
                    "tcp_rst_count": stmt.excluded.tcp_rst_count,
                    "avg_packet_size": stmt.excluded.avg_packet_size,
                    "duration": stmt.excluded.duration,
                    "interarrival_mean": stmt.excluded.interarrival_mean,
                    "interarrival_std": stmt.excluded.interarrival_std,
                    "packet_size_variance": stmt.excluded.packet_size_variance,
                    "l7_metadata": stmt.excluded.l7_metadata,
                }
                
                upsert_stmt = stmt.on_conflict_do_update(
                    index_elements=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'source'],
                    set_=update_cols
                )
                session.execute(upsert_stmt)
            
            session.commit()
            return []
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk flow upsert failed: {e}")
            raise e

    def get_flows(self, source: str = None, limit: int = 50) -> List[Dict]:
        """Get flow records."""
        session = self._get_session()
        query = session.query(Flow)
        if source:
            if source == "live":
                query = query.filter(Flow.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        
        flows = query.order_by(Flow.packet_count.desc()).limit(limit).all()
        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try:
                    d["l7_metadata"] = json.loads(d["l7_metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            d["flow_id"] = f"{d['src_ip']}:{d['src_port']}->{d['dst_ip']}:{d['dst_port']}/{d['protocol']}"
            result.append(d)
        return result

    def get_filtered_flows(self, src_ip: str = None, dst_ip: str = None, 
                           port: int = None, protocol: str = None, 
                           source: str = None, limit: int = 100) -> List[Dict]:
        """Powerful flow query tool for AI investigation and CLI parity."""
        session = self._get_session()
        query = session.query(Flow)
        
        if src_ip: query = query.filter(Flow.src_ip == src_ip)
        if dst_ip: query = query.filter(Flow.dst_ip == dst_ip)
        if port:
            from sqlalchemy import or_
            query = query.filter(or_(Flow.src_port == port, Flow.dst_port == port))
        if protocol: query = query.filter(Flow.protocol == protocol)
        if source: query = query.filter(Flow.source == source)
        
        flows = query.order_by(Flow.last_seen.desc()).limit(limit).all()
        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try: d["l7_metadata"] = json.loads(d["l7_metadata"])
                except: pass
            result.append(d)
        return result

    def get_entity_flows(self, ip: str, limit: int = 50) -> List[Dict]:
        """Get flows involving a specific IP."""
        session = self._get_session()
        flows = session.query(Flow).filter(
            or_(Flow.src_ip == ip, Flow.dst_ip == ip)
        ).order_by(Flow.packet_count.desc()).limit(limit).all()
        
        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try:
                    d["l7_metadata"] = json.loads(d["l7_metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            d["flow_id"] = f"{d['src_ip']}:{d['src_port']}->{d['dst_ip']}:{d['dst_port']}/{d['protocol']}"
            result.append(d)
        return result

    # ----------------------------------------------------------------
    # Carved File Operations
    # ----------------------------------------------------------------

    def insert_carved_file(self, entity_ip: str, filename: str, extension: str,
                           sha256: str, size: int, flow_src: str = None,
                           flow_dst: str = None, timestamp: float = 0.0,
                           vt_results: Dict = None, data: bytes = None,
                           source: str = "live", commit: bool = True):
        """Insert a carved file using SQLAlchemy (deduplicates by sha256)."""
        session = self._get_session()
        existing = session.query(CarvedFile).filter_by(sha256=sha256).first()
        if not existing:
            cf = CarvedFile(
                entity_ip=entity_ip, filename=filename, extension=extension,
                sha256=sha256, size=size, flow_src=flow_src, flow_dst=flow_dst,
                timestamp=timestamp, vt_results=json.dumps(vt_results) if vt_results else None,
                data=data, source=source
            )
            session.add(cf)
            if commit:
                session.commit()

    def get_carved_files(self, entity_ip: str = None, source: str = None) -> List[Dict]:
        """Get carved files, optionally filtered."""
        session = self._get_session()
        query = session.query(CarvedFile)
        if entity_ip:
            query = query.filter_by(entity_ip=entity_ip)
        if source:
            if source == "live":
                query = query.filter(CarvedFile.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        
        files = query.order_by(CarvedFile.timestamp.desc()).all()
        result = []
        for f in files:
            # Exclude binary data from list view
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns if c.name != "data"}
            if d.get("vt_results"):
                try:
                    d["vt_results"] = json.loads(d["vt_results"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    # ----------------------------------------------------------------
    # Daily Stats & Timeline Operations
    # ----------------------------------------------------------------

    def merge_daily_stats(self, packets: int, bytes_count: int, flows: int,
                          protocol_dist: Dict, port_dist: Dict, top_talkers: Dict,
                          source: str = "live", commit: bool = True):
        """Merge a snapshot into today's daily stats using SQLAlchemy."""
        session = self._get_session()
        today_str = date.today().isoformat()
        stats = session.query(DailyStats).filter_by(date=today_str, source=source).first()

        if stats:
            old_proto = json.loads(stats.protocol_distribution or "{}")
            old_port = json.loads(stats.port_distribution or "{}")
            old_talkers = json.loads(stats.top_talkers or "{}")

            for k, v in protocol_dist.items():
                old_proto[k] = old_proto.get(k, 0) + v
            for k, v in port_dist.items():
                old_port[str(k)] = old_port.get(str(k), 0) + v
            for k, v in top_talkers.items():
                old_talkers[k] = old_talkers.get(k, 0) + v

            stats.total_packets = (stats.total_packets or 0) + packets
            stats.total_bytes = (stats.total_bytes or 0) + bytes_count
            stats.total_flows = flows
            stats.snapshot_count = (stats.snapshot_count or 0) + 1
            stats.protocol_distribution = json.dumps(old_proto)
            stats.port_distribution = json.dumps(old_port)
            stats.top_talkers = json.dumps(old_talkers)
        else:
            stats = DailyStats(
                date=today_str, source=source, total_packets=packets,
                total_bytes=bytes_count, total_flows=flows, snapshot_count=1,
                protocol_distribution=json.dumps(protocol_dist),
                port_distribution=json.dumps(port_dist),
                top_talkers=json.dumps(top_talkers)
            )
            session.add(stats)

        if commit:
            session.commit()

    def merge_timeline(self, timeline_buckets: Dict, source: str = "live", commit: bool = True):
        """Merge timeline buckets into the timeline table using SQLAlchemy."""
        session = self._get_session()
        today_str = date.today().isoformat()
        for bucket_key, bucket_val in timeline_buckets.items():
            ts = int(bucket_key)
            item = session.query(Timeline).filter_by(timestamp=ts, source=source).first()
            if item:
                item.packets = (item.packets or 0) + bucket_val["packets"]
                item.bytes = (item.bytes or 0) + bucket_val["bytes"]
            else:
                item = Timeline(
                    timestamp=ts, date=today_str, source=source,
                    packets=bucket_val["packets"], bytes=bucket_val["bytes"]
                )
                session.add(item)
        if commit:
            session.commit()

    def get_today_stats(self, source: str = "live") -> Dict:
        """Get today's aggregated stats. Handles generic 'live' source by summing across all interfaces."""
        session = self._get_session()
        today_str = date.today().isoformat()
        
        if source == "live":
            rows = session.query(DailyStats).filter(DailyStats.date == today_str, DailyStats.source.like("live%")).all()
        else:
            rows = session.query(DailyStats).filter_by(date=today_str, source=source).all()

        if not rows:
            return {
                "date": today_str, "total_packets": 0, "total_bytes": 0,
                "total_flows": 0, "snapshot_count": 0,
                "protocol_distribution": {}, "port_distribution": {},
                "top_talkers": {}, "traffic_timeline": {},
                "flow_records": [], "recent_alerts": [],
                "global_threat_map": []
            }

        # Aggregate multiple rows if needed
        stats = {
            "date": today_str, "total_packets": 0, "total_bytes": 0,
            "total_flows": 0, "snapshot_count": 0,
            "protocol_distribution": {}, "port_distribution": {},
            "top_talkers": {}
        }
        
        for row in rows:
            stats["total_packets"] += row.total_packets
            stats["total_bytes"] += row.total_bytes
            stats["total_flows"] += row.total_flows
            stats["snapshot_count"] += row.snapshot_count
            
            for key, target in [("protocol_distribution", "protocol_distribution"), 
                                ("port_distribution", "port_distribution"), 
                                ("top_talkers", "top_talkers")]:
                val = getattr(row, key)
                if val:
                    try:
                        d = json.loads(val)
                        for k, v in d.items():
                            stats[target][k] = stats[target].get(k, 0) + v
                    except: pass

        # Fetch aggregated timeline
        if source == "live":
            tl_rows = session.query(Timeline).filter(Timeline.date == today_str, Timeline.source.like("live%")).all()
        else:
            tl_rows = session.query(Timeline).filter_by(date=today_str, source=source).all()
        
        timeline = {}
        for r in tl_rows:
            ts_str = str(r.timestamp)
            if ts_str not in timeline:
                timeline[ts_str] = {"time": r.timestamp, "packets": 0, "bytes": 0}
            timeline[ts_str]["packets"] += r.packets
            timeline[ts_str]["bytes"] += r.bytes
        
        stats["traffic_timeline"] = dict(sorted(timeline.items(), key=lambda x: int(x[0]), reverse=True)[:60])
        stats["flow_records"] = self.get_flows(source=source, limit=50)
        stats["recent_alerts"] = self.get_alerts(source=source, limit=100)
        stats["global_threat_map"] = self._build_threat_map(source=source)

        return stats

    def _build_threat_map(self, source: str = "live") -> List[Dict]:
        """Build threat map from today's flows only."""
        session = self._get_session()
        today_str = date.today().isoformat()
        # Filter flows with l7_metadata
        if source == "live":
            flows = session.query(Flow).filter(
                Flow.l7_metadata.isnot(None),
                Flow.session_date == today_str,
                Flow.source.like("live%")
            ).limit(500).all()
        else:
            flows = session.query(Flow).filter(
                Flow.l7_metadata.isnot(None),
                Flow.session_date == today_str,
                Flow.source == source
            ).limit(500).all()
        
        threat_map = {}
        from core.packet_engine.utils import is_internal
        for f in flows:
            try:
                meta = json.loads(f.l7_metadata) if f.l7_metadata else {}
                geo = meta.get("geoip", {})
                if geo and geo.get("lat") is not None:
                    # Identify which IP is the external one
                    ext_ip = f.src_ip if not is_internal(f.src_ip) else f.dst_ip
                    if is_internal(ext_ip): continue # Both internal
                    
                    lat = float(geo.get("lat", 0.0))
                    lng = float(geo.get("lng", 0.0))
                    if lat == 0.0 and lng == 0.0: continue
                    
                    if ext_ip not in threat_map:
                        threat_map[ext_ip] = {
                            "ip": ext_ip, "lat": lat, "lng": lng,
                            "country": geo.get("country", "Unknown"), "count": 1
                        }
                    else:
                        threat_map[ext_ip]["count"] += 1
            except (json.JSONDecodeError, TypeError):
                pass
        return list(threat_map.values())

    def get_timeline(self, limit: int = 60, source: str = "live") -> List[Dict]:
        """Get recent timeline data points."""
        session = self._get_session()
        today_str = date.today().isoformat()
        rows = session.query(Timeline).filter_by(date=today_str, source=source).order_by(Timeline.timestamp.desc()).limit(limit).all()
        result = [{"time": r.timestamp, "packets": r.packets, "bytes": r.bytes} for r in rows]
        result.sort(key=lambda x: x["time"])
        return result

    # ----------------------------------------------------------------
    # System Metadata
    # ----------------------------------------------------------------

    def set_metadata(self, key: str, value: str):
        """Set a system metadata value."""
        session = self._get_session()
        meta = session.query(SystemMetadata).filter_by(key=key).first()
        if meta:
            meta.value = value
        else:
            meta = SystemMetadata(key=key, value=value)
            session.add(meta)
        session.commit()

    def get_metadata(self, key: str, default: str = None) -> str:
        """Get a system metadata value."""
        session = self._get_session()
        meta = session.query(SystemMetadata).filter_by(key=key).first()
        return meta.value if meta else default

    # ----------------------------------------------------------------
    # Forensic Report Operations
    # ----------------------------------------------------------------

    def create_report(self, source: str, timestamp: float) -> int:
        """Create a new forensic report and return its ID."""
        session = self._get_session()
        report = ForensicReport(source=source, timestamp=timestamp)
        session.add(report)
        session.commit()
        return report.id

    def update_report(self, report_id: int, total_flows: int = 0,
                      total_entities: int = 0, total_alerts: int = 0,
                      summary: Dict = None):
        """Update a forensic report with final results."""
        session = self._get_session()
        report = session.query(ForensicReport).filter_by(id=report_id).first()
        if report:
            report.total_flows = total_flows
            report.total_entities = total_entities
            report.total_alerts = total_alerts
            report.summary = json.dumps(summary) if summary else None
            session.commit()

    def get_reports(self) -> List[Dict]:
        """List all forensic reports."""
        session = self._get_session()
        reports = session.query(ForensicReport).order_by(ForensicReport.timestamp.desc()).all()
        result = []
        for r in reports:
            d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
            if d.get("summary"):
                try:
                    d["summary"] = json.loads(d["summary"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    def get_report(self, report_id: int) -> Optional[Dict]:
        """Get a single forensic report."""
        session = self._get_session()
        r = session.query(ForensicReport).filter_by(id=report_id).first()
        if r:
            d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
            if d.get("summary"):
                try:
                    d["summary"] = json.loads(d["summary"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return d
        return None

    # ----------------------------------------------------------------
    # Cleanup
    # ----------------------------------------------------------------

    def clear_source(self, source: str):
        """Remove all data from a specific source."""
        session = self._get_session()
        session.query(Alert).filter_by(source=source).delete()
        session.query(CarvedFile).filter_by(source=source).delete()
        session.query(Flow).filter_by(source=source).delete()
        session.query(Entity).filter_by(source=source).delete()
        session.commit()

    def close(self):
        """Remove the scoped session and dispose the engine."""
        self.Session.remove()
        self.engine.dispose()

    def decay_risk_scores(self, factor: float = 0.9):
        """Reduces all entity risk scores by a decay factor."""
        session = self._get_session()
        session.query(Entity).update({Entity.risk_score: Entity.risk_score * factor})
        session.query(Entity).filter(Entity.risk_score < 0.1).update({Entity.risk_score: 0.0})
        session.commit()

    def reset_all(self) -> dict:
        """Drop all data tables and reinitialize the schema. Returns row counts deleted."""
        session = self._get_session()
        counts = {}
        for model in [Alert, CarvedFile, Flow, Entity, DailyStats, Timeline, ForensicReport]:
            counts[model.__tablename__] = session.query(model).count()
            session.query(model).delete()
        
        session.commit()
        # VACUUM is specific to SQLite, we can still run it via engine
        from sqlalchemy import text
        with self.engine.connect() as conn:
            conn.execute(text("VACUUM"))
            conn.commit()
        return counts

    def get_active_risk(self, ip: str, window_hours: int = 24) -> float:
        """Calculate active risk for an IP within a time window."""
        session = self._get_session()
        start_ts = time.time() - (window_hours * 3600)
        res = session.query(func.sum(Alert.score)).filter(
            Alert.entity_ip == ip,
            Alert.timestamp > start_ts
        ).scalar()
        return float(res) if res else 0.0

