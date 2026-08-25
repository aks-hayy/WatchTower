# Detector Authoring Playbook

Use this playbook for every new or materially changed detector. The goal is a deterministic evidence producer that remains safe under malformed traffic and composes with unknown future plugins.

## 1. Define the signal

Write down:

- The canonical finding type and category.
- The subject whose investigation priority may change.
- The minimum observable evidence.
- A concrete threshold and time window.
- Benign lookalikes and policy exceptions.
- Required packet, stream, conversation, session, or metadata inputs.
- Supported protocols, link types, capture sources, and backends.
- A signal family and correlation group.

Do not begin from a port number or severity. Begin from evidence and analyst action.

## 2. Choose ownership

Search the active plugin inventory. Extend an existing consolidated family when it already owns the state or canonical signal. A second plugin emitting the same signal can create duplicate findings and scoring inflation even when fingerprints differ.

Compatibility plugins can remain registered but disabled. Document which active plugin replaces them.

## 3. Scaffold

```text
tower plugins scaffold detector --id watchtower.example --finding-type example.suspicious --input conversation
```

The scaffold must remain uncalibrated. Manifests may declare a calibration candidate but cannot assign trust.

## 4. Implement the V2 manifest

Declare stable detector ID, semantic version, contract version, inputs, protocols, link types, sources, finding types, required evidence fields, state scope, reset/finalize behavior, memory limits, backend support, signal family, and correlation group.

Version behavior changes. Keep IDs stable across refactors that preserve meaning. Create a new finding type when the analyst interpretation changes materially.

## 5. Implement bounded state

- Key state by complete scope and detector subject.
- Use explicit time windows and eviction.
- Bound segment maps, peer sets, samples, and evidence references.
- Deduplicate retransmissions and deterministic repeats.
- Handle out-of-order data without unbounded buffering.
- Implement reset for analysis isolation and finalize for terminal evidence.
- Exclude incomplete or drop-heavy windows from baseline learning.

Never use process-global mutable detector state.

## 6. Emit safe findings

Populate the full `DetectionFindingV2` scope. Fingerprints must be deterministic from stable semantic fields and must not include processing order, volatile generation numbers, raw secrets, or arbitrary payload text.

Evidence references should identify native records, hashes, direction, counts, timing, parser result, and truncation state. Redact credentials, authorization values, tokens, command lines, and sensitive payload bytes before persistence.

Detector confidence describes certainty that the observed evidence matches the detector condition. It is not final risk and not probability of compromise.

## 7. Build the test matrix

Add focused cases for:

- Multiple positive examples at and above threshold.
- Benign lookalikes and boundary negatives.
- Malformed and truncated packets.
- Fragmented, reordered, and retransmitted traffic.
- Initiator/responder direction.
- Reset and finalize behavior.
- Event-order and window-boundary stability.
- Duplicate fingerprint suppression.
- State eviction and declared memory bound.
- Secret redaction.
- Python/Rust parity where supported.

Tests should assert the exact finding type, subject, scope, fingerprint stability, evidence shape, and absence of leaked secrets.

## 8. Add a corpus

Create or extend `calibration/corpus/DETECTOR.yaml`. Include at least 10 positive and 30 benign labeled cases for each finding type, plus relevant matrix variants. Scenarios must actually satisfy the documented detector threshold.

Use deterministic generated traffic. Never commit a real capture or field packet data.

## 9. Validate

```text
python -m pytest tests/detection -q
tower plugins test
tower plugins calibration run DETECTOR --finding-type TYPE --backend all
```

Inspect integrated production-path metrics, not only detector isolation. The production path must include conversation tracking, parser observations, finding validation, persistence, and scoring recomputation.

## 10. Review

Document false-positive controls, operational limits, backend support, performance, and the analyst's recommended next action. Follow the calibration playbook for promotion. Never edit the scoring profile to bypass a failed or stale attestation.
