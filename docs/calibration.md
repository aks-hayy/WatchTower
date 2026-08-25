# Detector Calibration

Calibration measures each finding type independently. It is a scoring trust control, not a statement that a plugin loaded successfully.

## Trust levels

- `UNCALIBRATED`: maximum 5 points per finding and 10 combined.
- `CORPUS_VALIDATED`: maximum 20 points per finding and 35 combined; cannot independently produce HIGH.
- `FIELD_CALIBRATED`: configured full contribution cap.

Disabled compatibility detectors and Sigma may remain uncalibrated. The active consolidated detector family carries trust for the canonical finding types it owns.

## Corpus

A corpus is a declarative set of labeled scenarios, not merely a YAML checklist. Scenario YAML defines traffic intent, expected finding type, labels, variants, malformed behavior, backend applicability, and thresholds. The calibration engine deterministically generates packets, executes the production pipeline, and compares observed findings with labels.

Committed corpora live under `calibration/corpus/`. Real captures, credentials, field bundles, and raw runtime reports must not be committed.

## Run calibration

```text
tower plugins calibration run DETECTOR --finding-type TYPE --backend all
tower plugins calibration status DETECTOR
```

Running calibration creates a report and candidate attestation. It never changes scoring trust.

Corpus validation requires at least 10 positive and 30 benign labeled cases, at least 90 percent precision, at least 80 percent recall, zero critical benign findings, deterministic fingerprints, exact supported-backend parity, bounded state, complete evidence, and no secret persistence.

## Promotion

```text
tower plugins calibration promote REPORT --reviewer NAME --reason TEXT
tower plugins calibration verify
```

Promotion revalidates the report, records reviewer identity and reason, writes a content-addressed attestation, and updates the matching profile. Direct edits cannot establish trust. The scoring profile and its referenced attestation must be committed together.

Attestations include detector source, manifest, corpus, production pipeline, scoring policy, backend versions, metrics, environment, timestamp, and resulting trust tier. Changes to any relevant hash make the trust stale automatically.

## Field calibration

Future detector plugins require 30 relevant benign host-days from complete captures with sensor drops below 0.1 percent, no unresolved HIGH/CRITICAL findings, zero critical false alerts, and no more than 0.1 high false alerts per host-day. Every high or critical field finding requires disposition.

WatchTower 2.0's initial active built-in detector set was promoted through a reviewed bootstrap policy. That exception does not apply to future plugins.

## CI

Pull requests run contracts, focused scenarios, profile/attestation verification, and regressions. Changes to detectors, corpora, scoring, pipeline, or Rust adapters trigger the complete corpus. Rust parity and bounded-memory runs execute nightly and on demand.
