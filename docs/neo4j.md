# Why WatchTower Uses Neo4j

SQLite remains WatchTower's evidence source of truth. Neo4j is optional because it solves a different investigation problem: traversing many typed, temporal relationships across sensors, identities, processes, services, domains, certificates, findings, artifacts, rules, and cases.

## What the graph adds

- Bounded neighborhood expansion around an endpoint or finding.
- Shortest evidence paths between entities.
- Temporal relationship pivots across sessions and sensor vantage points.
- Process-to-service-to-flow-to-domain investigation paths.
- Cross-case and cross-node relationship discovery without packet-level graph explosion.

High-volume traffic is aggregated into bounded conversation/time buckets. Packets do not become graph nodes.

## Why it is not primary storage

Capture persistence, scoring, case custody, and audit writes need predictable transactions and local operation. SQLite provides that foundation. Graph materialization uses an idempotent SQLite outbox; an unavailable graph accumulates work and exposes a freshness watermark. It never causes evidence loss or changes a finding.

## Deployment

Set a password only in the current shell, then request the optional setup:

```text
WATCHTOWER_NEO4J_PASSWORD=...
scripts/setup.sh --with-neo4j
```

Windows uses `$env:WATCHTOWER_NEO4J_PASSWORD` and `scripts/setup.ps1 -WithNeo4j`. The supplied Compose definition binds Neo4j only to loopback.

## Operations

Monitor outbox depth, oldest pending item, materialization failures, and graph freshness. When graph projection is stale, investigation views must display that state and offer SQLite-backed compatibility topology where possible.
