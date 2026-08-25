# Developer Guide

## Environment

Use the setup script in development mode and isolate runtime state:

Windows:

```powershell
.\scripts\setup.ps1 -Development -DisableAuth -NpcapSdk C:\path\to\npcap-sdk-1.16
$env:WATCHTOWER_HOME = (Join-Path (Get-Location) '.test-runtime')
```

Linux:

```bash
./scripts/setup.sh --development --disable-auth
export WATCHTOWER_HOME="$PWD/.test-runtime"
```

The Python package is installed editable. The UI and Rust sensor still require explicit rebuilds after changes.

## Repository layout

```text
core/                    Python product code
  ai/                    Analyst orchestration and providers
  api/                   FastAPI schemas, handlers, and projections
  auth/                  Local operator security
  capture_sources/       Hardware/source plugin contracts
  cli/                   Rich CLI and shell
  daemon/                Local process lifecycle and control
  detection/             Findings, stateful detection, scoring, baselines
  endpoint/              Sysmon and process attribution
  forensics/             PCAP analysis, parsers, detectors, artifacts
  graph/                 Neo4j outbox projection
  intelligence/          Identity and enrichment
  investigation/         Cases and exports
  mesh/                  Sensor fleet protocols and lifecycle
  packet_engine/         Live pipeline and Rust adapters
  storage/               Models, repositories, migrations, backups
calibration/             Scenario corpora and reviewed attestations
config/                  Shipped operator integration configuration
deploy/                  Optional service definitions
docs/                    Maintained documentation
rust/watchtower-sensor/  Rust capture and replay binary
scripts/                 Setup, benchmarks, corpus generation, acceptance
tests/                   Grouped Python tests
tools/                   Release and workspace tooling
traffic_testing/         Authorized synthetic traffic framework
ui/                      React/TypeScript operator interface
```

## Design rules

- Let the owning service enforce behavior; keep API and CLI layers thin.
- Use repository methods and short-lived database sessions.
- Treat source, interface, session, node, and analysis identity as data keys.
- Preserve backward projections without making legacy fields authoritative.
- Make queues, state, samples, excerpts, result limits, and retries bounded.
- Make shutdown and long-running jobs explicit state machines.
- Redact before persistence and before external provider calls.
- Report unsupported, stale, partial, and ambiguous states directly.
- Keep Rust/Python wire contracts versioned and validate every length.

## Storage changes

Schema changes are additive by default. Add model fields/tables, migration code, repository methods, backup behavior, and upgrade tests together. Never require users to clean the database to adopt a normal release.

Use SQLite's backup API for migration safety. A migration test should cover an existing populated database, interrupted work, restart reconciliation, and `quick_check`.

## API changes

Add typed schemas, service methods, bounded pagination, request-ID errors, and tests. New investigation data belongs under `/api/v2`; `/api/v1` is a compatibility surface. UI SSR should request only summary data and lazily fetch large lists or graphs.

## UI changes

The UI uses React, TypeScript, TanStack, and the existing WatchTower visual language. Preserve the persistent node/source/session scope. Route-addressable selection is preferred for investigation detail. Tables must paginate or virtualize rather than rendering unbounded rows.

Required checks:

```text
npm run lint
npm run typecheck
npm run build
```

## Rust changes

The Rust sensor is intentionally narrow: capture/replay, L2-L4 decode, aggregation, filtering, metrics, and validated event transport. Canonical findings and scoring remain in Python. Update protocol fixtures and parity tests whenever the wire contract changes.

Windows builds must use `scripts/build_rust_sensor.ps1`; Linux uses Cargo directly.

## Test organization

- `tests/ai`: providers, tools, approvals, citations, and policy.
- `tests/api`: endpoints, pagination, PCAP jobs, and local UI service.
- `tests/capture`: capture contracts, reliability, and backend selection.
- `tests/detection`: scoring, detector behavior, Sigma, and calibration.
- `tests/forensics`: PCAP, Rust parity, streams, index, triage, and cases.
- `tests/identity`: enrichment, local assets, endpoint telemetry, and investigation.
- `tests/platform`: storage, auth, mesh, graph, survey, and shell/UI behavior.
- `tests/release`: installers, source hygiene, calibration orchestration, and release tools.

See [testing-release.md](testing-release.md) for the promotion gates.
