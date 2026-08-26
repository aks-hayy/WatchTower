# Getting Started

## Choose a host

Windows is the primary endpoint-attribution platform because it supports Npcap and Sysmon. Debian and Ubuntu are supported capture and analysis platforms. A modern x64 machine with at least 8 GB RAM and 10 GB free storage is recommended; large retained cases require additional disk space.

## Windows installation

For the recommended desktop experience, use the unified installer. It builds
the controller/UI container, installs the native Rust sensor, and leaves
capture selection to the UI or companion CLI after startup:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
.\watchtower.ps1 start
```

The UI opens at `http://127.0.0.1:4173` and a controller-backed `tower` CLI
opens alongside it. Operator authentication is shared between them for the
same eight-hour session.

Use the focused launch commands when only one surface is needed:

```powershell
.\watchtower.ps1 ui
.\watchtower.ps1 cli
.\watchtower.ps1 stop
.\watchtower.ps1 uninstall
```

### Advanced native-only installation

Prerequisites can be installed through the setup script when `winget` is available:

```powershell
git clone https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1 -InstallPrerequisites
```

The script installs missing language toolchains, opens the official Npcap installer, downloads and verifies the pinned Npcap SDK, creates `.venv`, builds the Rust sensor, builds the UI, configures authentication, and runs diagnostics. Npcap is intentionally interactive because the free installer cannot be silently redistributed.

Useful options:

```text
-Development           Install Python development tools.
-DisableAuth           Explicitly disable application authentication.
-SkipRust              Install without the Rust sensor.
-SkipUI                Install a headless CLI/API environment.
-WithSysmon            Apply the supplied Sysmon policy.
-WithNeo4j             Start the optional loopback Neo4j container.
-NpcapSdk PATH         Use an existing extracted Npcap SDK.
```

Sysmon itself is operator-installed. Pass its executable when it is not on `PATH`:

```powershell
.\scripts\setup.ps1 -WithSysmon -SysmonExecutable C:\Tools\Sysmon64.exe
```

## Debian or Ubuntu installation

```bash
git clone https://github.com/aks-hayy/WatchTower---Network-Monitoring-and-Forensics.git
cd WatchTower---Network-Monitoring-and-Forensics
chmod +x scripts/setup.sh
./scripts/setup.sh --install-prerequisites --grant-capture
```

`--grant-capture` assigns only `cap_net_raw` and `cap_net_admin` to the built Rust sensor. Omit it if capture will run under a separately managed service account or with another privilege model.

Headless and development options mirror Windows:

```text
--development
--disable-auth
--skip-rust
--skip-ui
--skip-diagnostics
--with-neo4j
```

## Verify installation

```text
tower doctor
tower sources
tower plugins test
tower plugins calibration verify
```

`doctor` checks configuration, storage, schema, backend availability, disk space, and runtime health. Optional integrations can report unavailable without preventing local capture or offline analysis.

## First capture

List interfaces and copy the displayed name exactly:

```text
tower sources
tower start -i "Ethernet"
tower status
tower flows --interface "Ethernet"
tower alerts --interface "Ethernet"
```

Stop capture with an ordered drain:

```text
tower stop -i "Ethernet"
```

The session is complete only after packet processing and persistence acknowledge the drain. A timeout is stored as partial with a reason and pending count.

## Launch the UI

```text
tower ui
```

The launcher starts the loopback API and production UI bundle, selects an available port when needed, and prints the URL. Use `tower ui --no-open` on a headless desktop session.

## Analyze a PCAP

```text
tower analyze evidence.pcap --mode auto --backend rust
```

Use `streaming` for explicitly bounded memory on large files. Open the Forensic Suite in the UI to inspect the same persisted analysis.
