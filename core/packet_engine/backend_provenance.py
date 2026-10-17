"""Backend versions reported by the capture and replay engines."""

import os
import subprocess
from typing import Optional

from core.packet_engine import rust_capture


def _rust_sensor_version() -> Optional[str]:
    binary = rust_capture.sensor_binary()
    if not binary.is_file():
        return None
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            env=rust_capture._sensor_environment(),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    prefix = "watchtower-sensor "
    value = result.stdout.strip()
    return value[len(prefix):].strip() if result.returncode == 0 and value.startswith(prefix) else None


def reported_backend_version(backend: str) -> Optional[str]:
    selected = str(backend or "").strip().lower()
    if selected == "python":
        import scapy

        return str(getattr(scapy, "__version__", "") or "") or None
    if selected == "rust":
        return _rust_sensor_version()
    return None
