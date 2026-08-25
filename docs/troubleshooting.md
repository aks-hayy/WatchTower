# Troubleshooting

Start with:

```text
tower doctor
tower status
tower sources
```

## No interfaces or packets

- Confirm Npcap is installed on Windows or libpcap is available on Linux.
- Use the exact interface name shown by `tower sources`.
- Check capture privileges. On Linux, rerun setup with `--grant-capture` or use an approved service-account policy.
- Confirm that a VPN, Hyper-V, or virtual interface was not selected accidentally.
- Inspect the active capture session rather than a stale historical session.

## UI does not launch

- Rerun the setup script or `npm ci && npm run build` under `ui`.
- Use `tower ui --no-open` and open the printed loopback URL manually.
- If a port is occupied by a non-WatchTower service, select another with `tower ui --port PORT --api-port API_PORT`.
- Read the launcher error and request ID; do not terminate unrelated processes by port alone.

## Authentication blocks commands

Run `tower auth status`, then `tower auth unlock`. Sessions expire exactly eight hours after authentication. Sensitive operations can request step-up after five minutes without ending the main session.

Use the recovery code for normal recovery. OS-administrator reset is a last resort and is audited.

## Rust backend unavailable

Windows requires Npcap, the Npcap SDK used at build time, Rust stable, Visual C++ x64 build tools, and a Windows SDK. Rerun `scripts/setup.ps1 -InstallPrerequisites` or pass an extracted SDK path.

Linux requires Rust, `pkg-config`, and libpcap development headers. Run `cargo test --locked --manifest-path rust/watchtower-sensor/Cargo.toml` for a focused diagnosis.

An explicit Rust request never silently falls back. Use `--backend python` only as an intentional diagnostic or compatibility choice.

## PCAP appears stuck

Check the analysis job state, byte progress, queue lag, free disk, and spool directory. Corrupt, cancelled, truncated, or disk-exhausted analyses should be partial or failed, never complete. Streaming analysis needs temporary disk space even when memory is bounded.

## No process attribution

Run `tower endpoint sysmon status`. Sysmon installation alone is insufficient if Event IDs 1 and 3 are absent, the collector bookmark is stale, or the capture occurred before endpoint telemetry. Attribution cannot be reconstructed from packets alone.

## Neo4j unavailable

Capture, SQLite investigations, fleet inventory, and compatibility topology remain available. Check Docker, `WATCHTOWER_NEO4J_PASSWORD`, loopback ports 7474/7687, and graph outbox lag. Neo4j outages queue projection work rather than changing evidence records.

## Getting support safely

Provide the WatchTower commit, operating system, command, request ID, terminal status, and sanitized health output. Do not publish PCAPs, runtime databases, credentials, private keys, internal hostnames, or case bundles.
