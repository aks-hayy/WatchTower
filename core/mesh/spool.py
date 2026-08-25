"""Encrypted, bounded local telemetry spool for disconnected sensor nodes."""

from __future__ import annotations

from cryptography.fernet import Fernet
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional


class EncryptedMeshSpool:
    def __init__(self, path: str, key: bytes, max_bytes: int = 1024 * 1024 * 1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cipher = Fernet(key)
        self.max_bytes = max(16 * 1024 * 1024, int(max_bytes))
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("CREATE TABLE IF NOT EXISTS spool (sequence INTEGER PRIMARY KEY, priority INTEGER NOT NULL, created_at REAL NOT NULL, size INTEGER NOT NULL, payload BLOB NOT NULL)")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def enqueue(self, sequence: int, payload: Dict[str, Any], priority: int = 0) -> Dict[str, int]:
        encrypted = self.cipher.encrypt(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        size = len(encrypted)
        dropped = self._make_room(size, priority)
        self.connection.execute("INSERT OR REPLACE INTO spool(sequence, priority, created_at, size, payload) VALUES (?, ?, ?, ?, ?)", (int(sequence), int(priority), time.time(), size, encrypted))
        self.connection.commit()
        return {"dropped": dropped, "queued_bytes": self.bytes_pending()}

    def next(self) -> Optional[Dict[str, Any]]:
        row = self.connection.execute("SELECT sequence, payload FROM spool ORDER BY sequence ASC LIMIT 1").fetchone()
        if not row:
            return None
        return json.loads(self.cipher.decrypt(row[1]).decode("utf-8"))

    def acknowledge(self, sequence: int) -> None:
        self.connection.execute("DELETE FROM spool WHERE sequence <= ?", (int(sequence),))
        self.connection.commit()

    def bytes_pending(self) -> int:
        return int(self.connection.execute("SELECT COALESCE(SUM(size), 0) FROM spool").fetchone()[0] or 0)

    def count_pending(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM spool").fetchone()[0] or 0)

    def _make_room(self, incoming: int, priority: int) -> int:
        dropped = 0
        while self.bytes_pending() + incoming > self.max_bytes:
            row = self.connection.execute("SELECT sequence FROM spool WHERE priority <= ? ORDER BY priority ASC, sequence ASC LIMIT 1", (int(priority),)).fetchone()
            if not row:
                row = self.connection.execute("SELECT sequence FROM spool ORDER BY priority ASC, sequence ASC LIMIT 1").fetchone()
            if not row:
                break
            self.connection.execute("DELETE FROM spool WHERE sequence = ?", (row[0],))
            dropped += 1
        return dropped
