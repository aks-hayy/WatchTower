# WatchTower V2

WatchTower is a local-first network monitoring and investigation platform. It captures authorized traffic, turns it into scoped conversations and findings, and lets an operator inspect that evidence through a web UI or terminal CLI.

WatchTower V2 is release-candidate software. Expect rough edges and verify findings against the underlying evidence. Use it only on networks and captures you own or are authorized to monitor.

## Fresh install

### Windows 11

Install the current V2 branch in PowerShell:

```powershell
git clone --branch major_upgrade https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

The installer checks/installs prerequisites and selects **hybrid** only when local Docker Desktop, Compose, and its Linux engine are ready; otherwise it selects **native**. Automatic mode does not install Docker. Explicit `-Mode hybrid` may install Docker Desktop through `winget` when prerequisites are enabled. Npcap uses its official interactive installer and requires accepting its license. To choose deliberately, use `.\install.ps1 -Mode hybrid` or `.\install.ps1 -Mode native`.

For hybrid, start the local controller, UI, and host sensor:

```powershell
.\watchtower.ps1 start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173), complete first-run operator setup, select an interface, and explicitly press **Start** to begin capture. Starting the application does not start capture by itself.

For native mode, run the UI/API and CLI in separate PowerShell windows:

```powershell
.\.venv\Scripts\tower.exe ui
# In another PowerShell window:
.\.venv\Scripts\tower.exe
```

If all prerequisites are already installed, the lower-level installer is `.\scripts\setup.ps1`. See [Windows installation](docs/getting-started/windows.md) for options and prerequisites.

### Debian or Ubuntu

```bash
git clone --branch major_upgrade https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
chmod +x scripts/setup.sh
./scripts/setup.sh --install-prerequisites --grant-capture
```

Then run `tower doctor`, inspect interfaces with `tower sources`, and start the UI with `tower ui`. `--grant-capture` grants the Rust sensor only the packet-capture capabilities it needs; omit it if you use another privilege model. See [Linux installation](docs/getting-started/ubuntu.md).

## First checks and capture

```text
tower doctor
tower sources
tower start -i "INTERFACE NAME"
tower status
tower flows
tower alerts
tower stop -i "INTERFACE NAME"
```

Copy the interface name from `tower sources`. Stop capture through WatchTower so queues drain and the session can record whether processing completed. Packet capture requires the relevant host permissions and captures only what is visible from the selected sensor vantage point.

## What WatchTower does

- **Monitor:** Rust-first live capture, conversations, flow summaries, pipeline health, and session-scoped telemetry.
- **Detect:** protocol and behavioral detections with evidence, confidence, and a separate investigation-priority score.
- **Investigate:** endpoint identity and enrichment, alert review, network relationships, timelines, evidence, and PCAP cases.
- **Hunt:** run compatible Sigma rules against historical WatchTower data; Sigma is not a live packet detector.
- **Extend:** inspect parser/detector plugins and their coverage and calibration state.
- **Coordinate sensors:** optionally enroll remote sensors over mutually authenticated TLS; raw PCAP stays on its originating node unless explicitly exported.
- **Ask the Analyst:** use local Ollama by default for scoped, evidence-backed assistance; hosted-provider use is opt-in and sensitive context is approval-gated.
- **Project relationships:** optionally materialize evidence relationships in Neo4j; SQLite remains the local source of truth.

## Documentation

- [Complete WatchTower guide](docs/user-guide/README.md) — UI sections, CLI paths, features, architecture, data flow, security, deployments, and limitations.
- [Getting started](docs/getting-started.md) · [Container deployment](docs/containers.md) · [Operations and backups](docs/operations.md)
- [Live detection](docs/live-detection.md) · [Forensics](docs/forensics.md) · [Identity and enrichment](docs/identity-enrichment.md)
- [AI Analyst](docs/ai-analyst.md) · [Sensor mesh](docs/sensor-mesh.md) · [Sysmon attribution](docs/sysmon.md)
- [Plugins](docs/plugins.md) · [Calibration and trust](docs/calibration.md) · [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Data and privacy

Runtime state is stored outside the checkout by default: `%LOCALAPPDATA%\WatchTower` on Windows and XDG state/configuration locations on Linux. `WATCHTOWER_HOME` can select a portable isolated runtime. Captures, case databases, credentials, and runtime reports are private operational data and must not be committed. The standard uninstall preserves stored data; `uninstall -Purge` removes WatchTower runtime data and is destructive.

## License

WatchTower source code is MIT-licensed. Third-party components and synchronized rule content may have separate terms; see [third-party notices](THIRD_PARTY_NOTICES.md).
