"""Stable locations for shipped and managed Sigma rule files."""

from pathlib import Path


def default_sigma_data_dir() -> Path:
    """Return the historical application data path, independent of process CWD."""
    return Path(__file__).resolve().parents[2] / "data" / "sigma"


def default_sigma_builtin_dir() -> Path:
    """Return the Sigma rules shipped with the installed WatchTower package."""
    return Path(__file__).resolve().parent / "plugins" / "sigma"
