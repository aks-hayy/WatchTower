# Testing and Release

## Focused development checks

Run the test group that owns the change. Use `WATCHTOWER_HOME` pointing to an isolated directory.

```text
python -m pytest tests/detection -q
python -m pytest tests/forensics -q
python -m pytest tests/api -q
```

## Full source checks

```text
python -m pytest -q
tower plugins test
tower plugins calibration verify
python tools/check_release_tree.py
cargo test --locked --manifest-path rust/watchtower-sensor/Cargo.toml
```

UI:

```text
cd ui
npm ci
npm run lint
npm run typecheck
npm run build
```

Container descriptors are checked separately. A host with Docker Compose can
validate the resolved deployment and build the AMD64 images locally:

```text
scripts/container.ps1 init
scripts/container.ps1 config
scripts/container.ps1 build
```

The `container-images` workflow runs the Compose contract check on every
container-relevant change, builds controller and UI images for `linux/amd64`,
and publishes provenance and SBOM attestations only for version tags.

The grouped runner is resumable:

```text
python tools/release.py gate run --state-dir .release-state
```

## Detector gates

Calibrated high/critical built-ins target at least 90 percent precision and 80 percent recall, zero critical benign findings, and no more than 0.1 high false alerts per monitored host-day. Parity must match canonical finding types, fingerprints, and evidence hashes where a backend is supported.

## Reliability gates

- Complete capture sessions satisfy received = emitted = processed, zero pending, and persistence acknowledgements.
- Forced termination produces partial state with exact pending count and reason.
- API connection pools return to baseline after sequential and concurrent request tests.
- No unexplained downstream loss or stale analytics interval beyond two snapshot steps.
- Runtime memory remains bounded under million-packet and high-cardinality replay.

## Performance gates

- 25 MB forensic replay: under 10 seconds on the reference workstation.
- Low-cardinality 1 GB Rust sensor/replay: under 15 seconds.
- Realistic 100,000-flow 1 GB persisted analysis: under 60 seconds and 1.5 GiB peak RSS.
- Sensor drops below 0.1 percent under the reference load.
- Warm UI navigation p95 below 1.5 seconds and cold launcher readiness below 10 seconds.

Hardware-dependent gates must name the tested hardware. Fixture-only Sysmon, Bluetooth, mesh, or Neo4j results cannot be described as field-verified.

## Clean-clone gate

1. Run `python tools/check_release_tree.py --strict-workspace` after archiving and removing local runtime artifacts.
2. Create a verified source snapshot with `tools/release.py workspace archive`.
3. Install from the snapshot into a new virtual environment.
4. Build Rust and UI from that snapshot.
5. Run `tower doctor`, `tower sources`, plugin tests, and calibration verification.
6. Launch the UI and verify API health.
7. Analyze a generated PCAP and verify the terminal report.
8. Confirm no runtime artifact appears as a source file.

## Publication checklist

- No PCAP, database, key, certificate, credential, log, cache, field bundle, runtime report, or generated traffic log is tracked.
- Documentation links resolve and license policy is consistent.
- Active profile attestations exist and are valid.
- Setup scripts match supported hosts and pinned external downloads use hashes.
- Compose exposes only the loopback UI, container credentials use a mounted
  installation key, and optional profiles are tested before a release tag.
- CI passes on the exact commit.
- The acceptance report states unresolved limitations.
- The default branch and release tag point to the verified commit.
