# Watchtower — Complete User Guide

> **Version:** 1.0.0  
> **Last Updated:** May 6, 2026  

---

## Table of Contents

- [Getting Started](#getting-started)
- [Authentication & Security](#authentication--security)
- [CLI Command Reference](#cli-command-reference)
- [Live Packet Capture](#live-packet-capture)
- [Forensic PCAP Analysis](#forensic-pcap-analysis)
- [Deep Dive Investigation](#deep-dive-investigation)
- [Database Management](#database-management)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites

| Requirement | Version | How to Install |
|---|---|---|
| **Python** | 3.9+ | [python.org](https://python.org) |
| **Npcap** (Windows) | Latest | [npcap.com](https://npcap.com) — enable "WinPcap API-compatible Mode" |
| **libpcap** (Linux) | Latest | `sudo apt install libpcap-dev` |
| **Admin/Root** | — | Required for live packet capture |

### Installation

```bash
# 1. Clone and enter the project
git clone https://github.com/AkshaySatasworkar/watchtower.git
cd watchtower

# 2. Install the backend
pip install -e .

# 3. Launch the Watchtower Shell to begin setup
tower shell
```

---

## Authentication & Security

Watchtower heavily enforces authentication boundaries. The interactive shell is protected by a master credential vault.

### First Run (Setup)
Before using Watchtower, you **must** launch the shell (`tower shell`) to configure your master credentials.
Your password is computationally hashed using `bcrypt` and stored in `data/auth_creds.enc`.

### CLI Auth Gate
Every time you open the interactive CLI (`tower shell`), you must unlock the vault:
```text
Watchtower Vault is locked.
Username: admin
Password: ••••••••
Access granted.
```

### Session Persistence
A JWT-based session token with a 6-hour expiration is used to maintain forensic access within your terminal session.

---

## CLI Command Reference

### Quick Reference

| Command | Description | Example |
|---|---|---|
| `start [iface]` | Tell the background daemon to start a capture engine | `start Wi-Fi` |
| `background` | Interactive selector for persistent background monitoring | `background` |
| `stop` | Stop all engines via graceful daemon IPC | `stop` |
| `status` | Check daemon and engine status | `status` |
| `stats` | Show live statistics | `stats` |
| `analyze <pcap>` | Forensic PCAP analysis | `analyze traffic.pcap` |
| `dive <IP>` | Investigate an IP | `dive 192.168.1.50` |
| `flows` | List recent flows | `flows` |
| `alerts` | List security alerts | `alerts` |
| `lookup <IP>` | GeoIP lookup | `lookup 8.8.8.8` |
| `graph` | Topology visualization (HTML artifact) | `graph` |
| `clean` | Reset database | `clean` |
| `logout` | End session and lock vault | `logout` |

### Direct CLI Usage
You can run commands directly without dropping into the interactive shell:
```bash
tower start                    # Start capture
tower background               # Interactive background setup
tower stop                     # Stop capture
tower analyze suspicious.pcap  # Analyze a PCAP
tower status                   # Check engine health
```

---

## Live Packet Capture & Background Mode

The Watchtower Admin Daemon handles all capture processes securely in the background.

### Starting the Engine

```text
tower > start
```

Watchtower auto-selects your primary network interface (the one with an active IP). To specify an interface:

```text
tower > start Wi-Fi
tower > start Ethernet
```

### Persistent Background Monitoring

If you want Watchtower to continuously monitor multiple interfaces in the background, use the interactive background setup:

```text
tower > background
```

This opens an interactive table of all available network adapters. Selecting an adapter here will instruct the daemon to launch persistent capture engines for those interfaces. These engines will survive shell exit and user logouts, continuously logging forensic data to SQLite.

The engine runs as a background process and continuously:
1. **Captures packets** on the selected interface using Scapy multiprocessing.
2. **Aggregates flows** & **Extracts identities** (NTLM, Kerberos, DHCP).
3. **Fingerprints TLS** (JA3/JA4) & **Detects anomalies** (Z-Score Behavioral Analytics).
4. Writes securely to `watchtower.db` in WAL mode.

### Stopping the Engine

```text
tower > stop
```

Stopping sends a graceful `SIGTERM` stop-event to the daemon. It flushes all packets to SQLite and cleanly releases the network adapter.

---

## Forensic PCAP Analysis

Watchtower maintains **strict isolation** between live traffic and offline PCAP uploads to ensure your session data remains pure.

### Running an Analysis (CLI)
```text
tower > analyze suspicious_traffic.pcap
```

The PCAP engine runs the full pipeline:
- Complete Identity Extraction
- Beaconing, DNS Entropy, and Lateral Movement Detection
- Full Bidirectional TCP Stream Reassembly
- File Carving (PE, ELF, ZIP, PNG) with automatic VirusTotal SHA-256 lookups

### TLS Decryption
If you have an `SSLKEYLOGFILE`:
```text
tower > analyze traffic.pcap --keylog /path/to/sslkeys.log
```

---

## Deep Dive Investigation

### Basic Deep Dive
```text
tower > dive 192.168.1.50
```

Displays a comprehensive profile showing Host Identification (JA3/JA4, OS), Carved Files (with VT scores), Malware Behavior Alerts, and Top Destinations.

### TCP Stream Following
Reassemble and export TCP conversations:
```text
tower > dive 192.168.1.50 --stream --port 445
```
Exports the binary/ASCII protocol stream to `data/dive_{ip}_{port}.txt`.

### Network Topology Graph
```text
tower > graph
```
Generates an interactive HTML visualization (`data/topology.html`) using Cytoscape.js and opens it in your default browser.

---

---

## 🔌 Modular Plugin Architecture

Watchtower's forensic capabilities are powered by a hot-swappable plugin system. Every protocol parser and threat detector is isolated, ensuring that a failure in one module does not impact the stability of the entire engine.

### Auditing Active Plugins
You can list all forensic modules currently loaded into your session by running:
```text
tower > plugins
```
This will display a list of all active parsers (responsible for identity and metadata extraction) and detectors (responsible for risk scoring and alerts).

### Types of Plugins
1. **Protocol Parsers**: These modules perform deep-packet inspection (DPI) to extract forensic metadata (e.g., `smb_parser.py` extracts filenames and NTLM credentials).
2. **Threat Detectors**: These modules analyze the extracted metadata to identify malicious patterns (e.g., `beaconing_detector.py` looks for C2 heartbeats).
3. **Identity Scrapers**: These modules actively probe or passively listen for host-identifying information (e.g., `infrastructure_parser.py` performs NetBIOS/mDNS probes).

---

## 🛡️ Sigma Rules Integration

Watchtower integrates the industry-standard **Sigma Rules** format for log and traffic correlation. This enables you to apply community-driven detection logic to your local forensic database.

### Running a Sigma Hunt
You can scan your historical data for specific Sigma matches using the `hunt` command:
```text
tower > hunt malicious_ja3
```
If no rule name is provided, Watchtower will run all active rules in the `core/forensics/plugins/sigma/` directory against the current data source.

### Listing Sigma Matches
To see a summary of all Sigma matches found in your Evidence Vault:
```text
tower > hunt --list
```

### Writing Custom Rules
Sigma rules are stored as YAML files in `core/forensics/plugins/sigma/`. You can create your own rules targeting the following fields:
- `src_ip`, `dst_ip`
- `src_port`, `dst_port`
- `protocol`
- `ja3_hash`, `ja4_string`
- `identity` (Username/Hostname)

---

## Database Management

### Clean Database (Start Fresh)

**CLI:**
```text
tower > clean
⚠️  This will DELETE ALL captured data. Are you sure? (yes/N): yes
✅ Database wiped clean.
```

This completely drops the `flows`, `entities`, `alerts`, `carved_files`, and `timeline` tables. Master credentials and sessions are preserved.

---

## Troubleshooting

### "Permission denied" on capture
Run the console / terminal as Administrator (Windows) or Root (Linux/macOS) to allow packet capture.

### Zombie Processes / High Memory
If an engine crashes, run `tower stop` to issue a global kill order to the Daemon, or use `tower clean` to purge any hanging SQLite WAL locks.

### Database is locked
Ensure no other process is currently writing to the database. Running `tower stop` usually resolves background contention.
