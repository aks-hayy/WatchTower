# WatchTower User Guide

Run `tower --help` or enter `tower` for the interactive shell. The examples below omit `.venv` paths for readability.

## First run

```text
tower auth setup
tower sources
tower doctor
tower ui
```

The supported V2 release workflow is `install.ps1` plus `watchtower.ps1 start`
on Windows, or `scripts/setup.sh` plus `watchtower.sh start` on Ubuntu.

Authentication can be explicitly disabled during setup with `tower auth setup --disable`. An authenticated session lasts eight hours from successful authentication. Sensitive operations can require a recent step-up proof.

## Live monitoring

```text
tower start -i "Ethernet"
tower start -i "Wi-Fi" --backend rust
tower status
tower flows --interface "Ethernet"
tower alerts --interface "Ethernet"
tower stats --interface "Ethernet"
tower stop -i "Ethernet"
```

Rust is the default network backend. Python remains available with `--backend python`. Bluetooth HCI is a separate source where supported:

```text
tower start --source-type bluetooth -i hci0
```

## Investigation

```text
tower lookup 8.8.8.8
tower dive 192.168.1.20
tower graph
tower scoring explain 192.168.1.20
tower identity status
tower enrich status
```

Identity cards distinguish address coverage, evidence-backed identity, actionable identity, and strong identity. Missing evidence remains visible as a limitation.

## Offline forensics

```text
tower analyze evidence.pcap --mode auto --backend rust
tower analyze large-evidence.pcap --mode streaming --backend rust
tower analyze tls.pcap --keylog sslkeys.log
```

The UI Forensic Suite exposes the same immutable analysis and adds investigation pivots, topology filtering, and timeline playback. Uploaded PCAPs are removed after processing by default unless retention is explicitly selected.

## Historical Sigma hunts

```text
tower plugins sigma status
tower plugins sigma sync
tower plugins sigma list
tower hunt --source evidence.pcap
```

Sigma synchronization only manages the rule corpus. Rules are evaluated against stored historical traffic only when `hunt` is invoked.

## Plugins and calibration

```text
tower plugins list
tower plugins test
tower plugins calibration status
tower plugins calibration verify
```

Calibration runs and promotions are deliberate write operations. See [docs/calibration.md](docs/calibration.md).

## AI analyst

Ollama is the local default. OpenAI is an explicit connection using the OS credential store:

```text
tower ai status
tower ai provider connect ollama
tower ai models list --provider ollama
tower chat
```

Read-only investigation is automatic. Actions with side effects require approval, and private network context requires confirmation before external research.

## Sensor mesh

```text
tower mesh controller setup --mode local
tower mesh controller start
tower mesh nodes add --name branch-sensor
tower mesh nodes list
```

For internet-connected nodes, use VPN-overlay mode. See [docs/sensor-mesh.md](docs/sensor-mesh.md).

## Runtime locations

- Windows: `%LOCALAPPDATA%\WatchTower`
- Linux state: `$XDG_STATE_HOME/watchtower` or `~/.local/state/watchtower`
- Linux configuration: `$XDG_CONFIG_HOME/watchtower` or `~/.config/watchtower`
- Portable override: `WATCHTOWER_HOME=/path/to/runtime`

Never commit the runtime directory.
