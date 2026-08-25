# Plugin Development

WatchTower has four extension surfaces:

- Protocol parsers convert bounded packet or stream data into normalized observations.
- Detectors convert packet, stream, conversation, session, or metadata inputs into typed findings.
- Capture sources represent network interfaces, Bluetooth HCI, and future hardware inputs.
- Sigma rules are synchronized historical rules evaluated only by `tower hunt`.

## Plugin inventory

```text
tower plugins list
tower plugins test
```

Inventory includes contract version, plugin version, supported inputs, link types, capture sources, health, finding types, calibration level, effective cap, attestation, and staleness reason.

Disabled legacy detector entries can remain visible for auditability. They must not execute alongside a consolidated detector that emits the same canonical finding family.

## Parser contract

A parser declares a stable ID and version, supported link/application protocols, input requirements, bounded state, reset/finalize behavior, and output observation schema. It must tolerate malformed, truncated, reordered, and retransmitted traffic without throwing into the pipeline.

Parsers should identify protocols from validated structure, not ports alone. Nonstandard ports are supported when semantic validation succeeds. Parsers do not assign investigation priority.

## Detector contract

`DetectorManifestV2` declares:

- Stable detector ID, semantic version, and contract version.
- Packet, flow, stream, conversation, session, or metadata inputs.
- Supported protocols, link types, and capture sources.
- Emitted canonical finding types and required evidence.
- State scope, memory limits, reset, and finalize behavior.
- Signal family and correlation group.
- Backend support and calibration candidacy.

`DetectionFindingV2` includes category, type, detector identity, subject, target/flow, complete scope, event window, occurrence count, deterministic fingerprint, impact, confidence, evidence references, explanation, action, and optional MITRE technique.

Detector code never sets final risk and cannot self-certify calibration.

## Scaffold a detector

```text
tower plugins scaffold detector --id watchtower.example --finding-type example.suspicious --input conversation
```

The scaffold creates a detector module, manifest, focused test module, scenario corpus, and bounded-state hooks. It remains uncalibrated.

## Required tests

Every parser and detector needs positive, benign negative, malformed, truncated, fragmented, retransmitted, reordered, directional, reset/finalize, deterministic fingerprint, secret-redaction, and bounded-memory coverage where applicable.

Run:

```text
tower plugins test
python -m pytest tests/detection -q
```

Then follow [calibration.md](calibration.md) and the agent playbooks.

## Capture sources

Capture-source plugins emit versioned origins, packet batches or hardware observations, and health metrics. They declare devices, addresses, backend support, link types, privilege requirements, and unsupported states. A source must implement bounded backpressure and terminal signaling.

Windows Bluetooth HCI must report unavailable rather than pretending capture works. Linux implementations should use BlueZ HCI and recorded fixtures for tests.

## Sigma

Custom WatchTower rules remain separate from synchronized SigmaHQ rules. Synchronization uses a managed staged checkout, validates paths and YAML, records the commit, filters compatibility, and atomically activates or rolls back. Unsupported conditions are rejected rather than approximated.
