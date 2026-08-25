"""Bounded background materializer for the Neo4j evidence graph."""

from __future__ import annotations

import threading
import time
import uuid


class GraphMaterializerWorker:
    def __init__(self, service, interval: float = 2.0, batch_size: int = 250):
        self.service = service
        self.interval = max(0.5, float(interval))
        self.batch_size = max(1, min(int(batch_size), 1000))
        self.owner = f"graph-worker-{uuid.uuid4()}"
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._last_run = None
        self._last_result = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="watchtower-graph-materializer", daemon=True)
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=max(0.1, float(timeout)))
        self._thread = None

    def status(self) -> dict:
        return {
            "worker_state": "running" if self._thread and self._thread.is_alive() else "stopped",
            "worker_owner": self.owner,
            "last_run_at": self._last_run,
            "last_result": self._last_result,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._last_result = self.service.materialize(self.batch_size, owner=self.owner)
                self._last_run = time.time()
            except Exception as exc:
                self._last_result = {"materialized": 0, "error": str(exc)[:500]}
                self._last_run = time.time()
            self._wake.wait(self.interval)
            self._wake.clear()

