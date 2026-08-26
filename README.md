# WatchTower V2

WatchTower is a local-first network detection and forensic investigation platform. It combines a Rust packet engine, conversation-aware detection, evidence-backed endpoint identity, offline PCAP investigation, sensor mesh support, and an optional AI analyst behind one CLI and web UI.

WatchTower is intended for networks and captures you own or are authorized to investigate. The V2 rewrite is currently published as release candidate software; the older V1 product remains on the `v1-maintenance` branch.

## Project status

WatchTower is an experimental first attempt and a research project. It is being built to explore practical network detection, forensics, identity resolution, sensor mesh, and analyst workflows in one open-source platform. Expect rough edges, incomplete coverage, and mistakes as the project evolves. Please forgive the gaps, and constructive feedback and contributions are very welcome.

## What ships

- Rust-first live capture and offline replay, with Python available as a secondary backend.
- Session-, interface-, source-, and sensor-scoped flows and findings.
- Protocol parsers, stateful detectors, Behavioral Scoring V2, and historical Sigma hunting.
- Offline forensic cases with immutable analysis IDs, SHA-256 identity, conversations, findings, entities, topology, timeline, streams, artifacts, and evidence references.
- Internal and external endpoint identity with provenance and confidence.
- Windows Sysmon process and service attribution.
- Local and remote sensor fleet management with encrypted enrollment and telemetry spooling.
- Optional Neo4j evidence projection while SQLite remains the source of truth.
- A local-first AI analyst with Ollama support and explicit OpenAI opt-in.
- A React/TypeScript UI and Rich terminal interface over the same local services.

## Supported hosts

- Windows 11 with Npcap.
- Ubuntu 22.04 or 24.04 with libpcap.

Other platforms may run parts of the Python analysis stack but are not release-tested capture targets.

## Install from a clone

### Windows

Open PowerShell. The prerequisite option installs missing Python, Node.js, Rust, and Visual C++ build tools through `winget`, downloads the pinned Npcap SDK, and opens the official Npcap installer for the required interactive license step.

```powershell
git clone -b v2-rewrite https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

If the prerequisites already exist:

```powershell
.\scripts\setup.ps1 -NpcapSdk C:\path\to\npcap-sdk-1.16
```

### Debian or Ubuntu

```bash
git clone -b v2-rewrite https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
chmod +x scripts/setup.sh
./scripts/setup.sh --install-prerequisites --grant-capture
./watchtower.sh start
```

The installer creates `.venv`, builds the Rust sensor and production UI, configures local operator access, and runs `tower doctor`.

## Run with Docker Compose

The hybrid Compose deployment packages the controller and UI for reproducible
offline analysis and fleet control. It publishes only the loopback UI, while
Windows capture and Sysmon remain native-host features.

```powershell
.\scripts\container.ps1 init
.\scripts\container.ps1 up
```

Open `http://127.0.0.1:4173`. See [container deployment](docs/containers.md)
for persistent data, encrypted credentials, optional Ollama/Neo4j, mesh, and
the Linux sensor profile.

## Easiest Windows setup: hybrid runtime

For a Windows workstation, the supported one-command path keeps the Rust
packet sensor on the host and runs the controller and UI in Docker. The first
command installs or builds the native sensor, creates the local controller
configuration, and builds the container images. Npcap still requires accepting
its official installer once when it is not already present.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
.\watchtower.ps1 start
```

The runtime enrolls the host sensor with the local controller over loopback
mTLS, opens the UI and a companion `tower` command window, and forwards flows,
findings, endpoint attribution, and health telemetry to
`http://127.0.0.1:4173`. It does not capture until the user selects an
interface and presses Start in either surface. Raw captures and local evidence
remain on the host by default.

```powershell
.\watchtower.ps1 ui       # UI only
.\watchtower.ps1 cli      # CLI only
.\watchtower.ps1 stop
.\watchtower.ps1 uninstall
```

`start` launches the complete local runtime. `ui` and `cli` launch only the
requested operator surface while reusing the same runtime. `stop` drains
capture and shuts down WatchTower-owned services. `uninstall` stops the
runtime and removes generated dependencies, containers, volumes, and local
sensor state after an explicit confirmation. Advanced repair and diagnostics
remain available under `scripts/`.

The sensor's private runtime is stored under
`%LOCALAPPDATA%\WatchTower\hybrid-sensor`; the controller state remains in the
Docker volume. The controller UI and companion CLI share one eight-hour
controller session: unlocking either one unlocks the other, and locking either
one locks both. See [hybrid containers](docs/containers.md#windows-hybrid-runtime)
for scope and recovery details.

Use the companion CLI window opened by `watchtower.ps1 start` for controller
operations and the UI PIN. The standalone `.venv\Scripts\tower.exe` process is
sensor-scoped in the hybrid deployment, so its local trust store is intentionally
separate from the controller PIN.

## Start using WatchTower

Windows:

```powershell
.\watchtower.ps1 start
.\watchtower.ps1 ui
.\watchtower.ps1 cli
```

Linux:

```bash
.venv/bin/tower sources
.venv/bin/tower start -i eth0
.venv/bin/tower ui
```

Offline PCAP analysis does not require a live capture session:

```text
tower analyze evidence.pcap --mode auto --backend rust
```

## Documentation

Start at [docs/README.md](docs/README.md). The documentation covers installation, live monitoring, forensic cases, identity, AI, mesh operation, plugins, architecture, development, testing, security, and troubleshooting.

Useful entry points:

- [Getting started](docs/getting-started.md)
- [Container deployment](docs/containers.md)
- [User guide](USAGE.md)
- [Offline forensics](docs/forensics.md)
- [Architecture](docs/architecture.md)
- [Developer guide](docs/development.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Data and privacy

Runtime state is stored outside the repository by default: `%LOCALAPPDATA%\WatchTower` on Windows and XDG state/config directories on Linux. Captures, databases, credentials, logs, and case exports are ignored by Git. AI provider credentials use the operating-system credential store and are not written to YAML, SQLite, logs, or browser storage.

## License

WatchTower source code is licensed under the [MIT License](LICENSE). Third-party components and synchronized rule content retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
