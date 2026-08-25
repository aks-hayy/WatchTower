# Architecture

WatchTower is a local-first modular monolith with isolated capture workers, a versioned Rust wire protocol, SQLite evidence storage, a loopback API, and a separately built web UI.

## Major components

```text
Capture sources
  -> Rust sensor or Python capture
  -> bounded packet batches
  -> canonical conversation tracker
  -> protocol parser observations
  -> packet/stream/conversation/session detectors
  -> validated DetectionFindingV2 sink
  -> Behavioral Scoring V2
  -> repository-backed SQLite persistence
  -> API/CLI/UI projections
  -> optional Neo4j outbox projection
```

## Source ownership

- `core/packet_engine`: capture orchestration, workers, persistence, Rust adapters, and compatibility flow processing.
- `core/capture_sources`: pluggable network and hardware inputs.
- `core/forensics`: PCAP engines, parsers, detectors, packet index, stream spool, triage, artifacts, and Sigma synchronization.
- `core/detection`: finding contracts, conversation/stateful detection, scoring, baselines, and policy.
- `core/storage`: SQLAlchemy models, repositories, migrations, and backup operations.
- `core/intelligence`: evidence-backed endpoint identity, lookup, enrichment, and local asset context.
- `core/endpoint`: Sysmon collection and process/service attribution.
- `core/api`: loopback FastAPI application, projections, PCAP jobs, and SSE.
- `core/ai`: providers, tools, policy, research, redaction, approvals, and orchestration.
- `core/mesh`: enrollment, mTLS transport, spool, sequencing, and node lifecycle.
- `core/graph`: SQLite outbox and optional Neo4j materialization.
- `core/investigation`: investigations and hashed exports.
- `core/auth`: local operator factors, sessions, throttling, recovery, and step-up.
- `core/cli`: Rich command modules and the interactive shell.
- `ui`: React/TypeScript application built as the production operator surface.
- `rust/watchtower-sensor`: packet capture, replay, decode, aggregation, filtering, and metrics.

## Provenance boundaries

Every live record is scoped by sensor node, source, interface, capture session, and backend. Conversations add canonical endpoints and protocol. Offline records add immutable analysis and PCAP identities. These dimensions are part of storage and detector keys, not display-only labels.

## Rust/Python boundary

Rust performs high-rate capture and L2-L4 processing. It emits validated length-prefixed event batches and retains frame data required by Python plugins. Python owns protocol plugins, canonical findings, Behavioral Scoring V2, persistence, API projections, and investigation services. This keeps one scoring implementation across capture backends.

Explicit backend selection is strict. Rust failure does not silently switch to Python. Parity fixtures compare canonical findings, fingerprints, evidence hashes, flows, and terminal status.

## Storage

SQLite is the source of truth for local evidence, findings, risk snapshots, identities, sessions, jobs, approvals, mesh state, and graph outbox records. Storage access should use repository methods and short-lived context-managed sessions. Runtime schema changes are additive and must preserve existing data.

Neo4j is a derived temporal evidence index. It can be stale or unavailable without changing capture truth.

## Reliability model

Queues are bounded and expose drops. Session completion is based on ordered end-of-stream handling plus worker, evidence, and persistence acknowledgements. Forced shutdown produces a partial state with pending counts. Health never infers completeness from process exit alone.

## Security model

The API and UI bind to loopback by default. Authentication has an immutable eight-hour absolute session lifetime. Mesh nodes use enrollment-bound certificates and typed commands. Provider secrets stay in the OS credential store. Evidence excerpts are bounded and redacted. External research receives public indicators automatically only when enabled; private context requires approval.
