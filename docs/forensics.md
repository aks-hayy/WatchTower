# Offline Forensics

The Forensic Suite treats each PCAP as an immutable case input. CLI and UI projections use the same analysis identifier and stored report rather than independently reprocessing the file.

## Analysis modes

```text
tower analyze FILE --mode auto|memory|streaming --backend rust|python
```

- `auto` selects an appropriate mode from file size and available implementation.
- `memory` favors interactive analysis for smaller captures.
- `streaming` uses periodic persistence, idle-flow eviction, bounded samples, and disk-backed stream spooling.

Rust is the default replay backend. Python is retained for explicit compatibility and parity testing.

## Case identity and custody

A case records the PCAP SHA-256, byte size, capture time range, link-layer and parser details, backend, analysis mode, terminal status, completeness, visibility limitations, and chain-of-custody events. Successful completion reaches 100 percent byte progress only after persistence completes. Corruption, cancellation, truncation, or resource exhaustion produces a partial or failed state with a reason.

## Investigation workspace

The UI provides:

- Overview and concise case summary.
- Findings and alert projection.
- Source-scoped entities and identities.
- Bidirectional conversations and compatibility flow rows.
- Protocol and application observations.
- Evidence-backed topology and temporal playback.
- DNS, TLS, authentication, file, finding, and connection timeline events.
- Redacted stream excerpts, hashes, carved artifacts, and evidence references.
- Visibility limits and exportable case bundles.

## Conversations

Conversation rows preserve initiator and responder, directional packet and byte totals, TCP state, timestamps, retransmission metadata, application protocol, source/interface/session provenance, and process attribution where available. Use conversations for investigation; directional flow rows exist primarily for compatibility.

## Topology

The topology is an analyst view, not a packet hairball. Start with local anchors and ranked edges, then filter by protocol, finding, entity, time, or scope. External peers are clustered and expanded on demand. Playback supports cumulative first-seen growth and active-only connection views.

## Findings

A useful finding must answer:

- What happened and why it crossed the detector threshold.
- Which subject and conversation it belongs to.
- Which detector version emitted it.
- What evidence references support it.
- What confidence, impact, and calibration trust apply.
- Which false-positive controls should be checked.
- What the analyst should do next.

Unsupported or incomplete evidence cannot be converted into a confident finding.

## TLS key logs

Use `--keylog FILE` only with lawfully obtained session keys. Temporary key material is handled separately from the PCAP and deleted after processing unless retention is explicitly requested. Keys and decrypted secrets must never be committed or included in ordinary case exports.

## Case export

Exports are hashed bundles containing report projections, evidence references, dispositions, provenance, and visibility limits. Raw PCAPs, artifacts, and node-local excerpts are included only when explicitly selected and approved.

## Performance expectations

The Rust fast path is intended for rapid triage. Deep protocol decoding is bounded and lazy where possible. High-cardinality captures cost more than low-cardinality bulk traffic because each conversation and identity has persistence overhead. Use streaming mode when memory predictability matters more than immediate random access.
