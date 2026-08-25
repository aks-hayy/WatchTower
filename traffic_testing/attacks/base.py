"""
Base class for all attack modules.

Every attack inherits from BaseAttack and implements execute().
The runner calls start() to run the attack in a background thread,
and stop() to terminate it cleanly.
"""

import abc
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from traffic_testing.config import LOG_DIR


class AttackResult:
    def __init__(self, attack_name: str, category: str):
        self.attack_name = attack_name
        self.category = category
        self.started_at: Optional[datetime] = None
        self.stopped_at: Optional[datetime] = None
        self.packets_sent: int = 0
        self.errors: List[str] = []
        self.metadata: Dict[str, Any] = {}
        self.status: str = "pending"

    def to_dict(self) -> dict:
        return {
            "attack_name": self.attack_name,
            "category": self.category,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "packets_sent": self.packets_sent,
            "errors": self.errors,
            "metadata": self.metadata,
            "status": self.status,
        }


class BaseAttack(abc.ABC):
    def __init__(self, name: str, category: str, target_ip: str = "127.0.0.1"):
        self.name = name
        self.category = category
        self.target_ip = target_ip
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.result = AttackResult(name, category)
        self.logger = logging.getLogger(f"tt.{category}.{name}")
        self._packet_log_path = os.path.join(
            LOG_DIR, f"{category}_{name}_packets.jsonl"
        )

    @abc.abstractmethod
    def execute(self) -> None:
        pass

    def setup(self) -> None:
        pass

    def teardown(self) -> None:
        pass

    def start(self) -> None:
        self._stop_event.clear()
        self.result.started_at = datetime.now(timezone.utc)
        self.result.status = "running"
        self.logger.info(f"Starting attack: {self.name}")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self.setup()
            self.execute()
        except Exception as e:
            self.result.errors.append(str(e))
            self.result.status = "error"
            self.logger.error(f"Attack {self.name} failed: {e}")
        finally:
            try:
                self.teardown()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.result.stopped_at = datetime.now(timezone.utc)
        self.result.status = "completed"
        self.logger.info(
            f"Stopped attack: {self.name} (sent {self.result.packets_sent} packets)"
        )

    def wait(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def log_packet(self, packet_info: Dict[str, Any]) -> None:
        self.result.packets_sent += 1
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack": self.name,
            **packet_info,
        }
        try:
            with open(self._packet_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def wait_for_stop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(0.5)
