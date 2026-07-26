# WatchTower Offline Forensic Case Design

## Goal

Turn the offline PCAP workflow into a case-oriented forensic workspace whose CLI and UI expose the same immutable, source-scoped evidence while preserving the current CLI commands and presentation.

## Context

The current Rust offline engine extracts useful flows and entities in memory, but the UI reads incomplete source projections. Entity persistence is keyed by IP while UI queries are source-scoped, so repeated PCAP analyses can collide and return zero entities. The topology is built directly from conversations and can therefore display nodes even when the entity view is empty. Findings, artifacts, streams, and evidence are also exposed through separate projections that do not provide one consistent case context.

## Decisions

### Case Boundary

Every uploaded or directly analyzed PCAP creates one immutable forensic case. The case receives a stable case ID and analysis ID. Multiple PCAP grouping is deferred until the single-PCAP case path is reliable.

The case records:

- PCAP SHA-256, filename, byte size, and retained-input policy
- Capture start and end timestamps, timezone, link type, and parser/backend versions
- Processing state, byte progress, packet progress, warnings, truncation, and visibility limitations
- Chain-of-custody events and a content hash of the completed report
- Source-scoped conversations, entities, findings, alerts, artifacts, streams, evidence links, topology, and timeline

### Scope and Persistence

All offline records are scoped by case ID. Endpoint identity is keyed by `(case_id, ip)` and retains field-level provenance and confidence. Existing live data and CLI-compatible tables remain available. Compatibility projections map the existing CLI commands to the selected or explicit case without changing command names or Rich styling.

The canonical forensic projection is read-only after analysis completion. Re-running a PCAP creates a new case unless the caller explicitly requests a verified replacement of the same content hash.

### Canonical Evidence

The engine emits bidirectional conversations with initiator/responder, directional bytes and packets, TCP state, retransmission counts, first/last observation, application protocol, and evidence references. Findings contain canonical type, detector, threshold, observed values, confidence, evidence hash/reference, and false-positive controls.

The pipeline preserves redaction. Stream excerpts are bounded and protocol-aware. Credentials, tokens, authorization values, and arbitrary sensitive payloads are never persisted. Carved artifacts retain hashes, metadata, and bounded evidence references.

### Detection and Enrichment

Offline detection runs through the same canonical finding sink used by live processing. Suspicious infrastructure is identified through explicit IOC/reputation evidence, protocol anomalies, unusual behavior, or corroborating traffic. A public IP alone is not treated as malicious.

Endpoint enrichment is evidence-backed and separates address-only, observed, inferred, and externally researched identity. Public enrichment may include reverse DNS, ASN, organization, geolocation, certificate, domain, and reputation data when available. Every field includes source, retrieval time where applicable, confidence, and native evidence references.

### Analyst UI

The Forensics page becomes a case workspace with Overview, Findings, Entities, Conversations, Timeline, Topology, Artifacts, Streams, Evidence, and Export views. The case ID remains visible and addressable in the URL.

The overview prioritizes local assets, external peers, protocol mix, top conversations, findings, anomalies, processing completeness, and visibility limitations. Entity and finding rows link directly to related conversations, domains, certificates, ASN data, evidence, and timeline events.

Topology defaults to an analyst view: local assets are anchors, external peers are clustered by domain/ASN/certificate where supported, broadcast/multicast/control traffic is suppressed by default, and edges are ranked by findings, bytes, recurrence, and novelty. Analysts can expand neighborhoods, disable suppression, filter by protocol/finding/entity/time, and replay cumulative or active-only connections.

### CLI and UI Parity

The API and CLI consume the same `ForensicCaseProjection` service. The UI receives paginated case-scoped data. The CLI retains current commands and output style, using compatibility adapters over the same case projection. Parity tests compare counts, canonical IDs, findings, evidence references, entity identity fields, timeline bounds, and topology relationships.

## Delivery Gates

1. Additive case schema and source-scoped entity regression tests reproduce and fix the current UI-zero-entities defect.
2. CLI and UI report projections return identical immutable case metrics and canonical records.
3. Detection and enrichment produce explainable findings and identity provenance for all captured endpoints.
4. UI case workspace, evidence pivots, and ranked topology are usable on the supplied PCAP corpus.
5. All supplied PCAPs pass Rust CLI/UI parity, detection review, performance, and export acceptance tests.

## Out of Scope

- Reworking the existing CLI aesthetic or command names
- Multi-PCAP case grouping in the first pass
- AI-driven investigation or autonomous remediation
- Remote mesh behavior
- Arbitrary external scanning or unsafe reputation lookups
