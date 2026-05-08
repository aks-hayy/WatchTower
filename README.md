<p align="center">
  <h1 align="center">🏰 Watchtower</h1>
  <p align="center">
    <strong>Network Forensics & Traffic Analysis Platform</strong>
  </p>
  <p align="center">
    <a href="#-features">Features</a> ·
    <a href="#-quick-start">Quick Start</a> ·
    <a href="USAGE.md">User Guide</a> ·
    <a href="#-architecture">Architecture</a> ·
    <a href="PRODUCTION_READINESS.md">Production Readiness</a> ·
    <a href="#-contributing">Contributing</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
    <img src="https://img.shields.io/badge/status-beta-yellow.svg" alt="Beta">
  </p>
</p>

---

**Watchtower** is a modular network forensics platform that combines **live traffic capture** with **deep offline PCAP analysis**. It provides a rich interactive CLI for forensic investigation, backed by a high-performance SQLite database.

Built for security researchers, SOC analysts, and network engineers who need to understand *what's happening on the wire* — and *who's doing it*.

---

## 🏰 The Identity-Aware Forensic Engine

Watchtower is an **Identity-First** forensic platform. It doesn't just see packets; it understands the **who** and the **what** behind every bit of data.

### Key Advanced Capabilities:
- **Deep Asset Profiling** — Automatic hardware vendor resolution (OUI) and device role discovery (e.g., IoT, Server, Workstation) via mDNS, SSDP, and NetBIOS.
- **Behavioral Peer Matrix** — Persistent historical baselines that distinguish routine communications from anomalous first-time peer connections.
- **Subnet-Aware Triage** — Dynamic risk scoring based on network zones, with automatic sensitivity multipliers for trusted discovery segments.

| Capability | Watchtower | Traditional SIEM |
|---|:---:|:---:|
| Identity Attribution | ✅ Native | ⚠️ Rule-based |
| Hardware Fingerprinting | ✅ Native | ❌ External |
| Behavioral Baselines | ✅ Native | ❌ Database-linked |

---

## ✨ Features

### 🔬 Deep Packet Forensics
- **Identity Attribution** — Extracts usernames, hostnames, and full names from NTLM, Kerberos, NBNS, DHCP, and LDAP traffic
- **TLS Fingerprinting** — JA3/JA4 hash extraction with known malware client library identification (Cobalt Strike, Metasploit, Empire)
- **File Carving** — Automatic extraction of PE, ELF, ZIP, and PNG files from reassembled TCP streams
- **VirusTotal Integration** — SHA-256 hash lookups for carved files against 70+ AV engines
- **Stream Reassembly** — Full bidirectional TCP stream reconstruction with protocol identification

### 🚨 Threat Detection
- **Beaconing Detection** — Statistical analysis of connection timing regularity (C2 callback patterns)
- **DNS Anomaly Detection** — Shannon entropy scoring of domain names (DGA/tunneling detection)
- **Lateral Movement Alerts** — Internal network scanning and enumeration detection
- **Suspicious File Transfer** — Detection of PE/executable transfers over non-standard ports
- **Data Exfiltration** — High-volume outbound transfer alerting

### 🖥️ Secure Architecture
- **Admin Daemon** — Privileged background daemon handling all capture logic to keep user-facing tools safe
- **Strict Data Isolation** — Offline PCAP analysis streams are isolated from live telemetry

A UI AND AI LAYER WILL BE ADDED SOON.
---

## 🔌 Modular Plugin Architecture

Watchtower is built on a highly extensible plugin-based architecture. Every protocol parser and threat detector is a hot-swappable module, allowing the engine to adapt to new network environments and evolving threats.

### 🔬 Active Forensic Modules:
- **Protocol Parsers**: Deep-packet inspection for **SMB, Kerberos, NTLM, TLS (JA3/JA4), HTTP, FTP, DHCP, and DNS**.
- **Identity Scrapers**: Passive and active discovery of hostnames, user accounts, and full names via **NBNS, SSDP, mDNS, and Kerberos**.
- **Threat Detectors**: Automated anomaly detection for **C2 Beaconing, DNS Tunneling (DGA), Data Exfiltration, and Lateral Movement**.

To audit your active forensic modules, use the `plugins` command in the Watchtower shell.

---

### 🛡️ Sigma Rules Integration

Watchtower natively supports the **Sigma Rules** standard for network-centric threat hunting. This allows you to leverage industry-standard YAML signatures to detect complex behavioral patterns, known malicious TLS fingerprints, and suspicious protocol usage across your forensic data.

- **Standardized Detection**: Use any standard Sigma rule targeting `network_identity` or `flow` categories.
- **Historical Hunting**: Run the `hunt` command to scan your entire historical database for Sigma matches.
- **Risk Score Correlation**: Sigma matches are automatically linked to entity profiles, contributing to their global risk score.

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.9+**
- **Npcap** (Windows) — [Download](https://npcap.com/) with "WinPcap API-compatible Mode"
- **Admin/Root privileges** for packet capture

### Install & Run

```bash
# Clone the repository
git clone https://github.com/aks-hayy/WatchTower.git
cd WatchTower

# Install in development mode (registers the 'tower' command)
pip install -e .
```

> **Note:** If the `tower` command is not recognized after installation, ensure your Python `Scripts` directory is in your system `PATH`, or run the command within an activated virtual environment.

### First Steps

1. Start the background engine securely:

```bash
# In the terminal:
tower start          # Begin capturing packets on primary interface
tower status         # Check engine status
tower shell          # Enter the interactive forensic shell (requires login)
```

### Forensic Workflow

```bash
# Inside the secure 'tower shell':
tower > analyze suspicious_traffic.pcap     # Full PCAP analysis
tower > dive 192.168.1.50                   # Investigate a suspect IP
tower > dive 192.168.1.50 --stream          # Follow TCP streams
tower > graph                               # Visualize network topology
tower > clean                               # Wipe the database
```

For the complete command reference, see the **[User Guide](USAGE.md)**.

---

## 🏗️ Architecture

```text
                     ┌──────────────────────────────────────────────┐
                     │                 Watchtower                   │
                     └──────────────────────────────────────────────┘
                                          │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
    ┌────▼─────┐                  ┌──────▼──────┐                 ┌──────▼──────┐
    │  CLI     │    IPC Sockets   │  Admin      │   IPC Sockets   │  Analytics  │
    │  Shell   ├─────────────────►│  Daemon     │◄────────────────┤  Worker     │
    │  (Rich)  │                  │  (server.py)│                 │             │
    └────┬─────┘                  └──────┬──────┘                 └──────┬──────┘
         │                               │                               │
         │                        ┌──────▼───────┐                       │
         │                        │  Capture     │                       │
         │                        │  Process     │                       │
         │                        └──────┬───────┘                       │
         │                               │ Packet Queue                  │
         │                        ┌──────▼───────┐                       │
         │                        │  Flow Worker │                       │
         │                        │  (Forensics) │                       │
         │                        └──────┬───────┘                       │
         │                               │                               │
         │                        ┌──────▼──────┐                        │
         └────────────────────────┤   SQLite    ├────────────────────────┘
                                  │  (WAL mode) │
                                  └─────────────┘
```

**Key design decisions:**
- **Daemon IPC** — The privileged Daemon handles process execution; CLI acts as an unprivileged client
- **Multiprocessing** — Capture (`scapy.sniff`) and flow analysis run in separate processes to bypass the GIL
- **Graceful Termination** — IPC uses robust event signaling for clean network socket release and database flushing
- **SQLite with WAL** — Enables concurrent reads while the engine writes


## 📚 Documentation

| Document | Description |
|---|---|
| [**User Guide**](USAGE.md) | Complete CLI reference |
| [**Contributing**](CONTRIBUTING.md) | Development setup and contribution guidelines |
| [**Security Policy**](SECURITY.md) | Vulnerability reporting process |

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
