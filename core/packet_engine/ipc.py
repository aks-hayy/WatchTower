# core/packet_engine/ipc.py
"""
IPC key management for Watchtower's inter-process communication.

Generates a random auth key on first run and stores it in data/ipc.key.
All processes (engine, CLI, server) share this key for secure local IPC.
"""

import os
import secrets
from pathlib import Path

IPC_PORT = 9999
_KEY_FILENAME = "ipc.key"


def get_ipc_key(data_dir: str = "data") -> bytes:
    """Get or generate the IPC authentication key."""
    key_path = Path(data_dir) / _KEY_FILENAME
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        return key_path.read_bytes()

    key = secrets.token_bytes(32)
    key_path.write_bytes(key)
    return key
