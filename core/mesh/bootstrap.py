"""Narrow, machine-readable bootstrap helpers for managed mesh deployments.

This module is intentionally separate from the interactive CLI.  It is used by
the supported hybrid Windows launcher to provision a loopback controller and a
single-use enrollment package without scraping Rich terminal output.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from core.mesh.runtime import MeshRuntimeManager
from core.mesh.service import MeshControllerService
from core.storage.database import WatchtowerDB


def provision_local_controller(
    data_dir: str,
    address: str = "127.0.0.1",
    node_name: str = "local-sensor",
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Configure and start a local controller, then issue one join package.

    The caller is responsible for keeping the returned package private and for
    consuming it immediately.  It is deliberately short lived and single use.
    """
    controller = ensure_local_controller(data_dir, address)
    db = WatchtowerDB(data_dir=data_dir)
    try:
        service = MeshControllerService(db)
        enrollment = service.create_enrollment(
            name=node_name,
            ttl_seconds=max(60, min(int(ttl_seconds), 3600)),
            max_uses=1,
            created_by="hybrid-runtime",
        )
        return {
            "controller": enrollment["controller"],
            "ca_fingerprint": enrollment["ca_fingerprint"],
            "expires_at": enrollment["expires_at"],
            "join_code": enrollment["join_code"],
            "runtime": controller["runtime"],
        }
    finally:
        db.close()


def ensure_local_controller(data_dir: str, address: str = "127.0.0.1") -> dict[str, Any]:
    """Configure and start the local controller without creating an enrollment."""
    db = WatchtowerDB(data_dir=data_dir)
    try:
        service = MeshControllerService(db)
        service.setup("local", address)
        runtime = MeshRuntimeManager(str(db.data_dir))
        return {"controller": address, "runtime": runtime.start_controller()}
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="WatchTower managed mesh bootstrap")
    parser.add_argument("command", choices=["ensure-local-controller", "provision-local-controller"])
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--node-name", default="local-sensor")
    parser.add_argument("--ttl", type=int, default=900)
    args = parser.parse_args()

    if args.command == "ensure-local-controller":
        result = ensure_local_controller(args.data_dir, args.address)
    else:
        result = provision_local_controller(args.data_dir, args.address, args.node_name, args.ttl)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
