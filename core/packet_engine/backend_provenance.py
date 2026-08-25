"""Backend versions reported by the capture and replay engines."""

from typing import Optional

from core.packet_engine.rust_capture import rust_sensor_version


def reported_backend_version(backend: str) -> Optional[str]:
    selected = str(backend or "").strip().lower()
    if selected == "python":
        import scapy

        return str(getattr(scapy, "__version__", "") or "") or None
    if selected == "rust":
        return rust_sensor_version()
    return None
