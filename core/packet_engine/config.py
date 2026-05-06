from dataclasses import dataclass
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
    data_dir: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
    active_probing: bool = os.getenv("WATCHTOWER_ACTIVE_PROBING", "ON").upper() == "ON"
    silent: bool = False

    def resolve_interface(self) -> str:
        """Resolve 'auto' to a real interface name."""
        if self.interface == "auto":
            self.interface = auto_detect_interface()
        return self.interface
