"""Cross-process audit registry for WatchTower-generated active probes."""

import json
from pathlib import Path
import tempfile
import threading
import time


class ProbeRegistry:
    def __init__(self, data_dir="data"):
        self.path = Path(data_dir) / "survey-probes.json"
        self._cache, self._mtime = [], 0.0
        self._cache_keys = set()
        self._next_refresh = 0.0
        # A probe registration updates the local cache immediately.  Other
        # processes are observed at this modest cadence rather than causing a
        # filesystem stat for every captured packet.
        self._refresh_interval = 0.5
        self._lock = threading.Lock()

    def register(self, src_ip, dst_ip, src_port, dst_port, protocol, ttl=300.0):
        with self._lock:
            now = time.time()
            records = self._read(force=True)
            records = [item for item in records if item.get("expires_at", 0) >= now]
            records.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": int(src_port),
                "dst_port": int(dst_port), "protocol": protocol.upper(),
                "created_at": now, "expires_at": now + ttl, "generated_by": "WatchTower",
            })
            records = records[-10_000:]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(f".{next(tempfile._get_candidate_names())}.tmp")
            temporary.write_text(json.dumps(records, separators=(",", ":")), encoding="utf-8")
            for attempt in range(8):
                try:
                    temporary.replace(self.path)
                    break
                except PermissionError:
                    if attempt == 7: raise
                    time.sleep(0.01 * (attempt + 1))
            self._cache = records
            self._mtime = self.path.stat().st_mtime
            self._cache_keys = {
                (str(item.get("src_ip")), str(item.get("dst_ip")), int(item.get("src_port", 0)),
                 int(item.get("dst_port", 0)), str(item.get("protocol", "")).upper())
                for item in records if item.get("expires_at", 0) >= now
            }
            self._next_refresh = now + self._refresh_interval

    def matches(self, src_ip, dst_ip, src_port, dst_port, protocol, timestamp=None):
        now = time.time()
        self._read(now=now)
        return (
            str(src_ip), str(dst_ip), int(src_port), int(dst_port), str(protocol).upper()
        ) in self._cache_keys

    def _read(self, force=False, now=None):
        now = time.time() if now is None else float(now)
        if not force and now < self._next_refresh:
            return self._cache
        self._next_refresh = now + self._refresh_interval
        if not self.path.exists():
            self._cache, self._cache_keys, self._mtime = [], set(), 0.0
            return self._cache
        mtime = self.path.stat().st_mtime
        if not force and mtime == self._mtime: return self._cache
        try:
            self._cache = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._cache = []
        self._mtime = mtime
        self._cache_keys = {
            (str(item.get("src_ip")), str(item.get("dst_ip")), int(item.get("src_port", 0)),
             int(item.get("dst_port", 0)), str(item.get("protocol", "")).upper())
            for item in self._cache if item.get("expires_at", 0) >= now
        }
        return self._cache
