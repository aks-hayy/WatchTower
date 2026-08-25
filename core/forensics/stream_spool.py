"""Disk-backed, bounded TCP segment storage for streaming PCAP analysis."""

import json
from pathlib import Path
import sqlite3
from typing import Dict, Iterable, Tuple

from core.constants import MAX_STREAM_BYTES, MAX_STREAM_SEGMENTS


class SegmentSpool:
    def __init__(self, path, max_bytes=MAX_STREAM_BYTES, max_segments=MAX_STREAM_SEGMENTS):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.max_segments = max_segments
        self.connection = sqlite3.connect(str(self.path))
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS segments (flow TEXT, direction TEXT, sequence INTEGER, "
            "timestamp REAL, payload BLOB, PRIMARY KEY(flow, direction, sequence))"
        )
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_segments_flow ON segments(flow, direction, sequence)")
        self._usage: Dict[Tuple[str, str], Tuple[int, int]] = {}
        self.truncated_segments = 0
        self.truncated_bytes = 0

    @staticmethod
    def key(flow_id) -> str:
        return json.dumps(list(flow_id), separators=(",", ":"))

    @staticmethod
    def flow_id(key: str):
        values = json.loads(key)
        return (values[0], values[1], int(values[2]), int(values[3]), values[4])

    def append(self, flow_id, direction: str, sequence: int, payload: bytes, timestamp: float) -> bool:
        key = self.key(flow_id)
        usage_key = (key, direction)
        if usage_key not in self._usage:
            count, used = self.connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM segments WHERE flow=? AND direction=?",
                usage_key,
            ).fetchone()
            self._usage[usage_key] = (int(count), int(used))
        count, used = self._usage[usage_key]
        if count >= self.max_segments or used >= self.max_bytes:
            self.truncated_segments += 1
            self.truncated_bytes += len(payload)
            return False
        bounded = payload[:self.max_bytes - used]
        if len(bounded) < len(payload):
            self.truncated_bytes += len(payload) - len(bounded)
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO segments(flow,direction,sequence,timestamp,payload) VALUES(?,?,?,?,?)",
            (key, direction, int(sequence), float(timestamp), bounded),
        )
        if cursor.rowcount:
            self._usage[usage_key] = (count + 1, used + len(bounded))
        return bool(cursor.rowcount)

    def flow_ids(self) -> Iterable[tuple]:
        for (key,) in self.connection.execute("SELECT DISTINCT flow FROM segments ORDER BY flow"):
            yield self.flow_id(key)

    def flow_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(DISTINCT flow) FROM segments").fetchone()[0])

    def load(self, flow_id):
        key = self.key(flow_id)
        result = {"to_server": [], "to_client": []}
        for direction, sequence, timestamp, payload in self.connection.execute(
            "SELECT direction,sequence,timestamp,payload FROM segments WHERE flow=? ORDER BY direction,sequence", (key,)
        ):
            result[direction].append({"seq": sequence, "time": timestamp, "payload": bytes(payload)})
        return result

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.commit()
        self.connection.close()

    def cleanup(self):
        self.close()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists(): candidate.unlink()
