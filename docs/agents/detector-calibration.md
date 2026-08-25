# Detector Calibration Playbook

Calibration is a reproducible measurement and review workflow. Agent judgment, unit-test success, and manifest flags are not calibration evidence.

## 1. Establish identity

Record detector ID/version, finding type, manifest hash, source hash, corpus hash, production pipeline hash, scoring-policy hash, supported backends, and runner version. A change to a relevant hash invalidates prior trust.

## 2. Validate labels

For every scenario, confirm that the generated traffic satisfies the documented threshold and subject/direction assumptions. Positive fixtures that do not reach threshold must be corrected, not counted as detector misses. Benign fixtures must represent realistic lookalikes rather than empty traffic.

## 3. Run isolation diagnostics

Isolation helps locate detector defects and state leaks. It is diagnostic only. It cannot produce the authoritative confusion matrix because it bypasses production parsing, conversation, persistence, or scoring behavior.

## 4. Run integrated paths

Execute applicable cases through:

- Python live replay.
- Rust live replay.
- Python memory PCAP.
- Python streaming PCAP.
- Rust offline replay.

Unsupported paths must be declared in the manifest and report. They cannot be silently skipped.

## 5. Inspect metrics

Review confusion matrix, precision, recall, false-alert rate, evidence completeness, execution time, peak state size, backend parity, deterministic fingerprints, and secret-redaction checks for each finding type independently.

Corpus validation requires:

- At least 10 positive and 30 benign labeled cases.
- Precision at least 90 percent.
- Recall at least 80 percent.
- Zero critical benign findings.
- Exact supported-backend findings and evidence-hash parity.
- State within manifest limits.
- No persisted credential or payload secret.

A weak finding type does not block an unrelated finding type in the same plugin, but it remains at its own lower trust tier.

## 6. Remediate failures

- False positives: tighten semantic validation, direction, threshold, exclusions, or corroboration.
- False negatives: verify fixture validity, parser output, conversation state, finalization, and threshold boundaries.
- Parity mismatch: compare decoded lengths, flags, ordering, timestamps, canonical endpoints, and evidence normalization.
- Nondeterminism: remove processing order, random IDs, wall-clock time, or generation counters from fingerprints/evidence.
- Memory failure: add eviction, cap cardinality, or reduce retained evidence.
- Secret failure: redact before the finding sink, not only in API projection.

Rerun the complete applicable corpus after remediation.

## 7. Field evidence

Future plugins require 30 relevant benign host-days from complete captures with less than 0.1 percent sensor drops. Field bundles contain aggregated observations and analyst dispositions only. They never contain packet payloads, credentials, raw PCAPs, or private keys.

All high/critical findings require disposition. Unresolved findings block field promotion. Zero critical false alerts and at most 0.1 high false alerts per host-day are required.

## 8. Promote explicitly

```text
tower plugins calibration promote REPORT --reviewer NAME --reason TEXT
```

Promotion revalidates the report, creates a content-addressed attestation, records reviewer metadata, and updates the profile. Commit the detector/corpus changes, referenced attestation, and profile together.

## 9. Verify before review

```text
tower plugins calibration verify
python tools/check_release_tree.py
python -m pytest tests/detection tests/release -q
```

If verification reports stale trust, do not suppress the result. Recalibrate or accept the conservative cap until valid evidence exists.
