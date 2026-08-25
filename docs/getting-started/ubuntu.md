# Ubuntu 22.04 or 24.04

Install the native prerequisites and capture permission, then start the
hybrid runtime:

```bash
./scripts/setup.sh --install-prerequisites --grant-capture
./watchtower.sh start
```

The script creates `.venv`, installs `requirements/runtime.lock`, builds the
Rust sensor, and validates the UI toolchain. Native capture uses libpcap and
may require the configured capture group or capabilities. Docker-only mode is
also supported for offline PCAP work and controller workflows:

```bash
./scripts/container.sh init --with-mesh
./scripts/container.sh up --with-mesh --linux-sensor
```

Use `./watchtower.sh status`, `logs`, and `repair` to inspect or rebuild the
local runtime.
