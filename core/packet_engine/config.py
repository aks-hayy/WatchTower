from dataclasses import dataclass, field
from core.backend_policy import backend_policy
from core.runtime_paths import RuntimePaths
import scapy.all as scapy


def auto_detect_interface() -> str:
    """Pick the first interface with a non-zero IP address."""
    try:
        for iface in scapy.conf.ifaces.values():
            if iface.ip and iface.ip != "0.0.0.0" and iface.ip != "127.0.0.1":
                return str(iface.name)
    except Exception:
        pass
    return "auto"

import os

@dataclass
class PacketEngineConfig:
    interface: str = "auto"  # Auto-detect on startup
    window_size: int = 10  # seconds
    step_size: int = 5  # seconds (50% overlap)
    worker_count: int = 2
    monitoring_mode: str = "HYBRID"  # GLOBAL | PER_DEVICE | HYBRID
    max_flow_table_size: int = 100000
    packet_queue_size: int = 50000
    snapshot_queue_size: int = 256
    evidence_queue_size: int = 256
    control_queue_size: int = 32
    packet_batch_size: int = 2048
    drain_timeout_seconds: float = 60.0
    capture_backend: str = None
    source_type: str = "network"
    data_dir: str = field(default_factory=lambda: str(RuntimePaths.from_environment().data))
    active_probing: bool = os.getenv("WATCHTOWER_ACTIVE_PROBING", "ON").upper() == "ON"
    silent: bool = False

    def __post_init__(self):
        self.capture_backend = backend_policy.capture_backend(
            source_type=self.source_type,
            requested_backend=self.capture_backend,
        )

    def resolve_interface(self) -> str:
        """Resolve 'auto' to a real interface name."""
        if self.interface == "auto":
            self.interface = auto_detect_interface()
        return self.interface

    def validate(self, raise_on_error: bool = True) -> list[str]:
        errors = []
        if self.window_size <= 0:
            errors.append("window_size must be greater than zero")
        if self.step_size <= 0 or self.step_size > self.window_size:
            errors.append("step_size must be greater than zero and no larger than window_size")
        if self.worker_count < 1:
            errors.append("worker_count must be at least 1")
        if self.max_flow_table_size < 100:
            errors.append("max_flow_table_size must be at least 100")
        if self.packet_queue_size < 100:
            errors.append("packet_queue_size must be at least 100")
        if self.snapshot_queue_size < 8:
            errors.append("snapshot_queue_size must be at least 8")
        if self.evidence_queue_size < 8:
            errors.append("evidence_queue_size must be at least 8")
        if self.control_queue_size < 2:
            errors.append("control_queue_size must be at least 2")
        if self.drain_timeout_seconds < 1:
            errors.append("drain_timeout_seconds must be at least 1")
        if self.packet_batch_size < 1:
            errors.append("packet_batch_size must be at least 1")
        if self.capture_backend not in {"python", "rust"}:
            errors.append("capture_backend must be python or rust")
        if self.source_type not in {"network", "bluetooth"}:
            errors.append("source_type must be network or bluetooth")
        if self.monitoring_mode not in {"GLOBAL", "PER_DEVICE", "HYBRID"}:
            errors.append("monitoring_mode must be GLOBAL, PER_DEVICE, or HYBRID")
        if not os.path.isabs(self.data_dir):
            errors.append("data_dir must be an absolute path")
        if errors and raise_on_error:
            raise ValueError("Invalid packet engine configuration: " + "; ".join(errors))
        return errors
