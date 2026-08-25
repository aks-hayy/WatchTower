# Contributing to WatchTower

Thank you for improving WatchTower. Contributions should preserve evidence integrity, source/session boundaries, bounded processing, and honest operator-facing health states.

## Before opening a change

1. Open or reference an issue for substantial behavior changes.
2. Keep captured traffic, databases, credentials, field bundles, logs, and runtime reports out of Git.
3. Read [docs/development.md](docs/development.md) and [AGENTS.md](AGENTS.md).
4. Detector work must also follow the authoring and calibration playbooks under `docs/agents/`.

## Development setup

Windows:

```powershell
.\scripts\setup.ps1 -InstallPrerequisites -Development -DisableAuth
$env:WATCHTOWER_HOME = (Join-Path (Get-Location) '.test-runtime')
```

Debian or Ubuntu:

```bash
./scripts/setup.sh --install-prerequisites --development --disable-auth
export WATCHTOWER_HOME="$PWD/.test-runtime"
```

Use a dedicated `WATCHTOWER_HOME` during tests. Never point tests at an operator's normal WatchTower data directory.

## Required checks

Run focused tests while developing, then run the release checks before requesting review:

```text
python -m pytest -q
tower plugins test
tower plugins calibration verify
python tools/check_release_tree.py
```

UI changes must pass:

```text
cd ui
npm ci
npm run lint
npm run typecheck
npm run build
```

Rust changes must pass:

```text
cargo test --locked --manifest-path rust/watchtower-sensor/Cargo.toml
cargo build --locked --release --manifest-path rust/watchtower-sensor/Cargo.toml
```

Windows Rust builds use `scripts/build_rust_sensor.ps1` so the Npcap SDK and Visual C++ environment are configured consistently.

## Engineering expectations

- Keep changes scoped and compatible with existing CLI and API behavior unless a migration is documented.
- Add tests proportional to the risk and blast radius.
- Use repositories for storage access and short-lived database sessions.
- Bound queues, plugin state, response sizes, excerpts, and analysis samples.
- Preserve node, source, interface, session, and backend provenance.
- Never persist credentials, raw authorization values, model hidden reasoning, or arbitrary packet payloads.
- Findings require deterministic fingerprints and structured evidence references.
- Unsupported or incomplete behavior must be reported explicitly, not approximated.

## Detector and parser contributions

Parser correctness and detector trust are separate. A new detector starts uncalibrated, even if its unit tests pass. It must provide a V2 manifest, bounded state, reset/finalize behavior, redacted evidence, deterministic fingerprints, and a labeled corpus. Only `tower plugins calibration promote` may change scoring trust.

See [docs/plugins.md](docs/plugins.md), [docs/calibration.md](docs/calibration.md), and the two detector playbooks.

## Pull requests

- Target `v2-rewrite`, the V2 default branch, for new development. V1 maintenance
  changes belong on `v1-maintenance`.
- Explain the user-visible behavior, data migration, and operational risks.
- Include the exact verification commands and results.
- Call out unsupported hardware or operating systems honestly.
- Avoid unrelated formatting, generated output, or dependency churn.

Use clear imperative commit subjects, for example `Fix conversation finalization during capture drain`.

## Security reports

Do not disclose suspected vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the repository's MIT License.
