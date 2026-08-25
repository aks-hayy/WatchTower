# Maintainer Guide

This document is the operational map for continuing WatchTower development without relying on prior chat context.

## Product invariants

1. A behavioral score is investigation priority, not compromise probability.
2. SQLite evidence is authoritative; Neo4j and UI projections are derived.
3. Findings are detector evidence; detectors do not control final scoring.
4. Every live record retains node, source, interface, session, and backend scope.
5. Every offline record retains analysis ID and PCAP SHA-256 identity.
6. Rust is the default network engine; Python is an explicit secondary path.
7. Sigma runs only against stored historical traffic through `hunt`.
8. Missing evidence, unsupported hardware, processing loss, and partial completion stay visible.
9. Credentials, packet secrets, hidden model reasoning, and unredacted external context are never persisted.
10. New detector trust requires reproducible evidence and reviewed promotion.

## Where to make changes

- Capture speed or packet decoding: `rust/watchtower-sensor`, then Rust adapter and parity tests.
- Queueing, shutdown, flow persistence, live telemetry: `core/packet_engine` and `core/daemon`.
- Protocol understanding: `core/forensics/plugins/parsers`.
- Detection logic: active detector under `core/forensics/plugins/detectors` or `core/detection/stateful.py`.
- Score behavior: `core/detection/scoring.py`, policy/profile YAML, and scoring tests.
- PCAP case behavior: `core/forensics/engine.py`, packet index, stream spool, triage, and `core/api/pcap_jobs.py`.
- Identity: `core/intelligence`; process attribution: `core/endpoint`.
- UI behavior: `ui/src`; API projection: `core/api`.
- Mesh: `core/mesh`; graph projection: `core/graph`.
- AI: `core/ai`, with tool behavior delegated to owning services.

## Safe change sequence

1. Reproduce the issue with a focused fixture or synthetic scenario.
2. Identify the owning contract and persistence boundary.
3. Add a failing focused test.
4. Implement the smallest compatible change.
5. Run the focused group.
6. Run calibration if detector, parser-to-detector input, scoring, conversation, or backend behavior changed.
7. Run Rust parity if packet or replay behavior changed.
8. Run UI checks if any API response used by the UI changed.
9. Run the source-tree checker and grouped release gates.
10. Update the relevant document and changelog.

## Detector lifecycle

Do not add a second detector that emits the same signal without a migration plan. Prefer adding a finding type to the consolidated family when state and correlation are shared. Retired detectors should be disabled but visible until compatibility removal is documented.

Use `tower plugins scaffold detector`, implement the complete test matrix, add corpus YAML, run calibration, inspect integrated confusion matrices, and promote only with reviewer identity and reason. Commit source, corpus, profile, and referenced attestation together.

## Release workflow

The release tool scans source versus local evidence, creates a hashed source/evidence archive outside the repository, and removes only manifest-approved generated paths. Never use broad Git cleanup commands on a development workspace.

```text
python tools/release.py workspace scan
python tools/release.py workspace archive --destination PATH_OUTSIDE_REPO
python tools/release.py workspace apply --manifest PATH_TO_MANIFEST --dry-run
python tools/release.py gate run --state-dir .release-state
```

Before cleanup, stop WatchTower-owned services so SQLite and spool files are stable. Verify the archive manifest has no skipped files. Preserve the archive until the release is pushed and a clean clone is validated.

## Versioning

Update together:

- `pyproject.toml` project version.
- `rust/watchtower-sensor/Cargo.toml` version.
- API/wire/model versions if their contracts changed.
- `CHANGELOG.md`.
- Calibration attestations when relevant hashes change.

Database migration versions and detector semantic versions are independent of the product version.

## Performance work

Measure packet throughput, queue lag, drops, RSS, disk growth, flow cardinality, detector overhead, and persistence latency separately. Low-cardinality bulk traffic is not a substitute for a 100,000-conversation benchmark. Keep benchmark generation deterministic and keep generated PCAPs out of Git.

## Incident response for WatchTower itself

If evidence integrity or credential handling may be compromised, stop exposed control services, preserve the runtime directory, hash relevant files, revoke mesh certificates/provider credentials, and use the private security reporting path. Do not clean the database before preserving evidence.

## Known extension boundaries

- Authentication currently protects one local operator, not a hostile local administrator.
- Remote UI/API access is outside the default security model.
- Sysmon installation and policy deployment remain operator-managed.
- Neo4j is optional and eventually consistent.
- External AI providers are optional and cannot alter findings or scores without approved WatchTower actions.
- Mobile sensors and Anthropic/MCP provider attachment are future extensions, not implied by current contracts.
