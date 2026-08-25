"""
Daily stats accumulator — now backed by SQLite.

- Merges each WindowSnapshot into SQLite tables
- At midnight boundary, encrypts the day's data → data/archives/YYYY-MM-DD.enc
- Provides helpers to list / decrypt archives
- Maintains backward-compatible API for existing consumers (server.py, flow_worker.py)
"""

import json
import os
import math
from datetime import date
from pathlib import Path
from cryptography.fernet import Fernet
from core.storage.database import WatchtowerDB
from core.utils.logger import setup_logger

logger = setup_logger("persistence")


class DailyAccumulator:
    """SQLite-backed daily stats accumulator with encrypted archival."""

    def __init__(self, data_dir: str = None):
        from core.context import context
        self.data_dir = Path(data_dir or context.data_dir)
        self.archive_dir = self.data_dir / "archives"
        self.key_file = self.data_dir / "secret.key"

        # ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        # load or generate encryption key
        self._fernet = self._init_fernet()

        # SQLite database — shared across all consumers
        self.db = WatchtowerDB(data_dir=data_dir)

        # Track current date for rollover
        self._current_date = date.today().isoformat()

    # ------------------------------------------------------------------ key
    def _init_fernet(self) -> Fernet:
        if self.key_file.exists():
            key = self.key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
        return Fernet(key)

    # ----------------------------------------------------------- archiving
    def _check_rollover(self):
        """Check if the day has changed and archive if needed."""
        today_str = date.today().isoformat()
        if self._current_date != today_str:
            self._archive(self._current_date)
            self._current_date = today_str

    def _archive(self, day: str):
        """Encrypt the day's stats and save per interface."""
        # Use text() for raw SQL queries in SQLAlchemy
        from sqlalchemy import text
        with self.db.session_scope() as session:
            rows = session.execute(
                text(
                    "SELECT DISTINCT source FROM daily_stats "
                    "WHERE date = :day AND source LIKE 'live%'"
                ),
                {"day": day},
            ).fetchall()
        sources = [r[0] for r in rows]
        if not sources:
            sources = ["live"]
            
        for src in sources:
            stats = self.db.get_today_stats(source=src)
            stats["date"] = day
            stats["source"] = src
            plaintext = json.dumps(stats, default=str).encode("utf-8")
            
            if src == "live":
                enc_path = self.archive_dir / f"{day}.enc"
            else:
                iface = src.replace("live_", "")
                enc_path = self.archive_dir / f"{day}_{iface}.enc"
            
            enc_path.write_bytes(self._fernet.encrypt(plaintext))

    # -------------------------------------------------------- public API
    def merge(self, snapshot, flow_table: dict | None = None, source: str = "live",
              stats_source: str = None, capture_origin: dict = None, stats_snapshot=None):
        """Merge a WindowSnapshot into SQLite using high-performance bulk operations."""
        self._check_rollover()

        try:
            # 1. Merge aggregate daily stats & timeline
            aggregate_source = stats_source or source
            metrics = stats_snapshot or snapshot
            self.db.merge_daily_stats(
                packets=metrics.total_packets, bytes_count=metrics.total_bytes,
                flows=metrics.total_flows, protocol_dist=metrics.protocol_distribution,
                port_dist=metrics.port_distribution, top_talkers=metrics.top_talkers,
                source=aggregate_source, commit=False
            )
            if metrics.traffic_timeline:
                self.db.merge_timeline(metrics.traffic_timeline, source=aggregate_source, commit=False)

            # 2. Merge alerts
            if snapshot.alerts:
                for alert in snapshot.alerts:
                    alert_dict = alert.__dict__ if hasattr(alert, "__dict__") else alert
                    self.db.insert_alert(
                        entity_ip=alert_dict.get("entity_id", "unknown"),
                        timestamp=alert_dict.get("timestamp", 0.0),
                        alert_type=alert_dict.get("type", alert_dict.get("entity_type", "UNKNOWN")),
                        severity=alert_dict.get("severity", "MEDIUM"),
                        score=alert_dict.get("final_score", alert_dict.get("score", 0.0)),
                        explanation=alert_dict.get("explanation", ""),
                        evidence=alert_dict.get("evidence"),
                        source=source, commit=False,
                        capture_session_id=(capture_origin or {}).get("session_id"),
                        capture_interface=(capture_origin or {}).get("device_id"),
                        capture_backend=(capture_origin or {}).get("backend"),
                        capture_type=(capture_origin or {}).get("source_type", "network"),
                    )

            # 3. Batch build flow and entity records
            if flow_table is not None:
                flow_batch = []
                entity_map = {} # IP -> data for batch-internal deduplication

                def get_entity(ip):
                    if ip not in entity_map:
                        entity_map[ip] = {"ip": ip, "source": source, "risk_score": 0.0, "total_packets": 0, "total_bytes": 0, "last_seen": 0.0}
                    return entity_map[ip]

                today_str = date.today().isoformat()

                for flow_id, f in flow_table.items():
                    src_ip, dst_ip, src_port, dst_port, protocol = flow_id
                    
                    # Prepare Flow Data
                    flow_batch.append({
                        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                        "protocol": protocol, "start_time": f.start_time, "last_seen": f.last_seen,
                        "packet_count": f.packet_count, "byte_count": f.byte_count,
                        "tcp_syn_count": f.tcp_syn_count, "tcp_rst_count": f.tcp_rst_count,
                        "avg_packet_size": round(sum(f.packet_sizes)/len(f.packet_sizes), 2) if f.packet_sizes else 0,
                        "duration": round(f.last_seen - f.start_time, 2),
                        "l7_metadata": json.dumps(f.l7_metadata) if f.l7_metadata else None,
                        "session_date": today_str,
                        "source": source,
                        "capture_session_id": (capture_origin or {}).get("session_id"),
                        "capture_interface": (capture_origin or {}).get("device_id"),
                        "capture_backend": (capture_origin or {}).get("backend"),
                        "capture_type": (capture_origin or {}).get("source_type", "network"),
                    })

                    # Update Entity Data in Map
                    src_e = get_entity(src_ip)
                    src_e["total_packets"] += f.packet_count
                    src_e["total_bytes"] += f.byte_count
                    src_e["last_seen"] = max(src_e["last_seen"], f.last_seen)

                    dst_e = get_entity(dst_ip)
                    dst_e["last_seen"] = max(dst_e["last_seen"], f.last_seen)

                    # Extract identity from l7_metadata
                    if f.l7_metadata:
                        def _s(v):
                            if isinstance(v, list): return ", ".join(str(x) for x in v) if v else None
                            return v
                        
                        meta = f.l7_metadata
                        h, u, fn, m = _s(meta.get("local_hostname")), _s(meta.get("local_username") or meta.get("smb_user")), _s(meta.get("full_name")), _s(meta.get("mac"))
                        if h: src_e["hostname"] = h
                        if u: src_e["username"] = u
                        if fn: src_e["full_name"] = fn
                        if m: src_e["mac"] = m

                # Execute Bulk Upserts
                self.db.bulk_upsert_flows(flow_batch)
                self.db.bulk_upsert_entities(list(entity_map.values()))
            
            self.db.commit()
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Merge transaction failed: {e}")
            raise e

    def get_today(self, source: str = "live") -> dict:
        """Return today's cumulative stats from SQLite."""
        self._check_rollover()
        return self.db.get_today_stats(source=source)

    def list_archives(self) -> list[str]:
        """Return list of archived dates (sorted newest first)."""
        dates = []
        for f in self.archive_dir.glob("*.enc"):
            dates.append(f.stem)  # YYYY-MM-DD
        dates.sort(reverse=True)
        return dates

    def read_archive(self, date_str: str) -> dict | None:
        """Decrypt and return an archived day's stats."""
        enc_path = self.archive_dir / f"{date_str}.enc"
        if not enc_path.exists():
            return None
        try:
            plaintext = self._fernet.decrypt(enc_path.read_bytes())
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            return None
