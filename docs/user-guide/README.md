# WatchTower: Complete User and Technical Guide

This guide explains how to use WatchTower, what each major screen and feature does, and how the system processes and stores evidence. It is an orientation and architecture guide—not a substitute for authorization, local operating procedures, or the focused references linked throughout.

WatchTower V2 is release-candidate software. Use it only for networks and captures you own or are authorized to inspect. Treat alerts and priority scores as investigation leads; verify important conclusions against their evidence.

## 1. The WatchTower mental model

WatchTower turns traffic observed by a sensor into evidence that can be searched and investigated:

```text
authorized traffic or PCAP
  → sensor/source and capture or analysis scope
  → packets, conversations, protocol observations
  → typed findings and identity evidence
  → SQLite records and audit/provenance
  → UI, CLI, investigations, optional graph projection
```

The **scope** explains where a record came from. Live records carry sensor node, source, interface, capture session, and backend. Offline records carry an immutable analysis ID and PCAP identity. These are real filters and detector boundaries, not just labels. If a screen has no evidence in its selected scope, that means “no data in this scope,” not “the network is safe.”

The system separates four ideas that should not be conflated:

- **Observation:** what the sensor or parser saw, with time, subject, and provenance.
- **Finding:** a detector’s evidence-backed statement that behavior met a rule or threshold.
- **Priority:** how urgently evidence should be investigated. Behavioral Scoring V2 is not a probability of compromise.
- **Identity and context:** names, ownership, service/process attribution, or external reputation, each with its own source and confidence. Context does not automatically become a finding.

## 2. Installation and first run

The short install path is in the [repository README](../../README.md). The detailed platform and option matrix is in [Getting Started](../getting-started.md); deployment tradeoffs are in [Containers](../containers.md).

In brief:

- **Windows:** `install.ps1` selects the hybrid controller/UI plus native Rust sensor when local Docker Desktop is ready; otherwise it chooses native single-host mode. Npcap is installed through its official interactive installer. The default installer may install missing prerequisites; Docker Desktop itself is not silently installed by automatic mode.
- **Debian/Ubuntu:** `scripts/setup.sh --install-prerequisites --grant-capture` installs the supported toolchain and gives the Rust sensor its required capture capabilities. Omit the capability grant when using a separately managed privilege model.
- **Hybrid containers:** the controller/UI and persisted state run in Compose; the native Windows sensor remains on the host. The controller UI is published on loopback. Windows capture and Sysmon are not container capabilities.

After installation, run `tower doctor`, inspect interfaces with `tower sources`, complete the first-run operator setup, and open the UI or CLI. Starting WatchTower does **not** begin capturing. Select the interface and explicitly start a capture. First-run authentication and the session/step-up controls protect operator actions; disabling authentication is an explicit installation choice, not a default recommendation.

The standard uninstall removes generated application components but preserves runtime evidence and configuration. `-Purge` is destructive and removes stored WatchTower data; back up first. See [Uninstall](../getting-started/uninstall.md).

## 3. The web UI, section by section

The sidebar groups operator work into Overview, Monitor, Alerts, Investigate, and Settings. Simple, Standard, and Analyst experience modes change how much navigation is presented; they do not change detector policy or evidence.

| UI section | Purpose and typical use |
|---|---|
| **Overview** | A current-state landing page: see whether WatchTower has data, whether capture/services are ready, and what needs attention. Use it to orient and move to capture or an alert. Empty evidence is not a green verdict. |
| **Capture** | Choose an available source/interface, inspect readiness, and explicitly start or stop a scoped live session. Review capture engine, session state, and processing/queue health. Stop normally so packet processing and persistence can drain. |
| **Connections** | Explore conversations and flow summaries with direction, endpoints, protocol, timing, byte/packet volume, and provenance. Filter to the correct sensor/source/interface/session before drawing conclusions. Conversations are the primary behavioral unit; directional compatibility rows are not independent incidents. |
| **Devices** | Review endpoint cards and identity evidence. Distinguish an address being observed from an endpoint having an evidence-backed or strong identity. Pivot from an endpoint to its connections, findings, related names, attribution, and timeline. |
| **Network map** | Explore evidence-backed relationships and time evolution. Filter by scope, time, protocol, entity, or finding; expand external peers on demand. It is an analyst view, not a literal rendering of every packet. |
| **Sensors** | Inspect local and enrolled sensor health, capabilities, telemetry freshness, ingestion lag, spool/queue pressure, gaps, drops, clock skew, and certificate state. A connected sensor is not necessarily delivering complete telemetry. |
| **Alert queue** | Triage typed findings. Inspect the subject, detector, time window, evidence, confidence, impact, priority rationale, scope, and next step. Dispositions are auditable; false-positive/expected-benign dispositions suppress current contribution but do not erase the record. |
| **Detection rules** | Inspect synchronized Sigma rules, compatibility, and coverage. Synchronization loads rule content; it does not itself run a hunt or turn Sigma into a live detector. |
| **Cases** | Open offline PCAP analyses as durable investigations. Review case summary, findings, entities, conversations, topology, timeline, artifacts, streams, and evidence within the same analysis identity. Check completeness and visibility limits before exporting conclusions. |
| **Search** | Look up an endpoint or public indicator and inspect observed identity, ownership, names, services, and related evidence. External reputation is contextual; private/local context must not be treated as public data. |
| **Hunts** | Run compatible Sigma rules against stored historical WatchTower metadata. Review the exact time/data scope, rule compatibility, results, and coverage limitations. An empty result is only meaningful for the telemetry and period actually present. |
| **Evidence** | Inspect evidence references and provenance behind records and investigations. Use it to validate an alert or AI claim rather than relying on a summary alone. |
| **System settings** | Review host/runtime telemetry and resource use; operator session, authentication factors, recovery, and step-up controls; AI provider connection/model readiness; mesh controller/enrollment/node controls; and capture-source readiness. Optional service readiness is separate from core capture readiness. |
| **Extensions** | Inspect parser/detector/source contracts, versions, supported inputs, validity, health, findings, tests, and calibration/trust evidence. A loaded or passing plugin is not automatically calibrated or trustworthy. |
| **Analyst** | Ask natural-language questions in the configured AI mode, review activity and cited evidence, and approve any gated action or disclosure. Local Ollama is the default provider; hosted providers require explicit setup/consent. |

### UI navigation patterns

Start with a selected scope, then pivot. A device or finding is useful only with its source, time, and evidence attached. When moving from a live capture to a PCAP case, the scope changes; the UI should make that change visible. Review any “partial,” “unsupported,” “unavailable,” or “stale” status instead of reading it as zero or success.

For screen-specific workflows, see [Operations](../operations.md), [Live Detection](../live-detection.md), [Forensics](../forensics.md), [Identity and Enrichment](../identity-enrichment.md), and [AI Analyst](../ai-analyst.md).

## 4. CLI: the same evidence through commands

The `tower` CLI and web UI use the same local services and persisted session/case records. The CLI is useful for repeatable commands, automation, and operator workflows that are faster in a terminal. Begin with `tower --help`; use `tower help --all` for advanced/compatibility commands and `tower <task> --help` for task options.

| Task | Common commands | What they do |
|---|---|---|
| Readiness and sources | `tower doctor`, `tower sources`, `tower status` | Diagnose local prerequisites and service health, enumerate capture sources, and inspect runtime/session state. |
| Live capture | `tower start -i INTERFACE`, `tower flows`, `tower alerts`, `tower stop -i INTERFACE` | Start a specific capture, query its records, and stop with an orderly drain. Choose the interface by the exact name reported by `sources`. |
| Endpoint investigation | `tower lookup IP`, `tower dive IP`, `tower scoring explain IP`, `tower identity status` | Inspect identity/context, relationships, findings, priority rationale, and identity coverage. |
| Offline cases | `tower analyze FILE --mode auto --backend rust` | Process a PCAP into a durable case; use streaming mode when bounded memory is preferred. |
| Historical rules | `tower plugins sigma status`, `tower plugins sigma sync`, `tower hunt --source FILE` | Check/synchronize Sigma content, then run a supported historical hunt. |
| Extensions and trust | `tower plugins list`, `tower plugins test`, `tower plugins calibration verify` | Inspect plugin contracts/health and verify that scoring trust still matches its reviewed evidence. |
| AI | `tower ai status`, `tower chat` | Check provider readiness and use the Analyst. Scope, privacy, and approval requirements still apply. |
| Sensors | `tower mesh controller status`, `tower mesh nodes list` | Inspect controller and node state where mesh is configured. |

The examples are starting points, not a substitute for each command’s help. A command’s result remains subject to capture scope, source capabilities, backend support, and retained telemetry. The [CLI workflow reference](../../USAGE.md) has more examples.

## 5. Feature paths in depth

### 5.1 Capture and session lifecycle

Capture begins at an explicit source and interface. The Rust sensor is the default network backend; a Python backend remains available for explicit compatibility and diagnostics. The chosen backend is reported. A failed explicit Rust run does not silently switch backends, because doing so would make evidence provenance misleading.

Packets are processed in bounded batches through tracking, parser and detector work, scoring, and persistence. Queues have limits and expose drops/lag; a session is not “complete” merely because the capture process exited. Normal stop drains capture, queued work, final detector state, and writes before recording terminal status. Forced termination may leave a partial session with pending-work reasons.

Use capture status and health counters together: received, emitted, processed, dropped, pending, and queue depth describe different stages. Unsupported is not the same as zero. Visibility is limited to packets reaching that sensor and source.

### 5.2 Detection and Behavioral Scoring V2

Detectors emit typed findings, not final risk scores. A finding identifies its detector/version, subject, scope, time window, evidence, confidence, impact, fingerprint, and explanation. Behavioral Scoring V2 combines evidence quality, recurrence/recency, asset context, correlation bounds, and calibration trust to produce an investigation-priority index.

The displayed bands are LOW 0–19, MEDIUM 20–49, HIGH 50–79, and CRITICAL 80–100. This score is neither a probability of compromise nor a substitute for examining evidence. Calibration levels constrain contribution, and invalid/stale/missing attestation makes trust unknown or uncalibrated rather than silently trusting a number. Dispositions are auditable and known benign activity should be managed through reviewed controls rather than by deleting findings.

Active detection families include cleartext credentials, authentication bursts, ARP/NDP conflicts, untrusted DHCP/IPv6 routers, reconnaissance, SYN floods, administrative fanout, beaconing, DNS/ICMP tunneling, directional exfiltration, TLS mismatch, nonstandard services, executable transfer, and unsafe IoT/OT behavior. Exact coverage depends on protocols, vantage point, parsers, and backend. See [detection and scoring](../live-detection.md) and [calibration](../calibration.md).

### 5.3 Sigma rules and hunts

Sigma is a historical hunt path. WatchTower synchronizes managed rule content, validates it, records the source revision, and rejects unsupported conditions instead of approximating them. A hunt evaluates compatible rules against stored metadata for the selected historical source/time range. Rule sync is not a hunt, and a hunt result cannot say anything about absent telemetry. See [plugin and Sigma behavior](../plugins.md).

### 5.4 Endpoint identity and enrichment

Identity separates observed behavior from claims about an endpoint. A generic IP card is address coverage only. Stronger identity may combine MAC/vendor, ARP/NDP, DHCP, DNS/PTR, mDNS/LLMNR/NBNS, LLDP/CDP, service discovery, TLS names/certificates, local inventory, process telemetry, and relationship evidence. Every attribute should retain source, confidence, scope, and first/last observation.

External endpoints may have RDAP/RIR ownership, ASN/organization, geolocation, public reputation, certificate, and observed service context. External reputation is context, not an automatic finding. A common pivot is IP → identity → conversations → names/certificate/ASN → related endpoints → finding → evidence. Rebuild operations derive records from stored evidence and should not invent names. See [Identity and Enrichment](../identity-enrichment.md).

### 5.5 Offline forensics and case custody

`tower analyze` accepts a PCAP and a selected analysis mode/backend. Auto mode chooses based on input and implementation; memory mode favors smaller interactive files; streaming mode uses bounded samples, periodic persistence, idle-flow eviction, and disk-backed stream spooling. Rust replay is the default, with explicit Python mode for compatibility/parity work.

Each case records a PCAP SHA-256 and byte size, time range, link/parser details, backend, mode, terminal state, completeness, limitations, and custody events. UI and CLI reference the same immutable analysis ID and stored report. A case can include summary, findings, entities, conversations, topology, timeline, redacted stream excerpts, artifacts, and evidence references. Exported bundles are hashed; raw PCAPs/artifacts are included only when selected and approved. TLS key logs are sensitive and must be lawfully obtained; they are kept separate from ordinary exports. See [Offline Forensics](../forensics.md).

### 5.6 Network map and graph projection

The network map presents evidence-backed relationships and temporal views. It should help answer “what is related to this entity, in this scope and period?” rather than showing every packet as a node. SQLite stores authoritative evidence. Optional Neo4j materializes bounded temporal relationships through an idempotent outbox; it can be stale or unavailable without changing capture truth. Views should disclose graph freshness and use SQLite-backed alternatives where available. See [Neo4j’s role](../neo4j.md).

### 5.7 Sensor mesh

An optional controller coordinates local or remote sensors. Agents connect outbound over mutually authenticated TLS, use one-time enrollment packages and verified controller fingerprints, and spool telemetry while offline. Controller commands are typed/versioned—not arbitrary shell execution. Sensor/source provenance remains attached to records; sequence gaps, queue pressure, lag, clock skew, certificate expiry, and drops are visible.

The default hybrid bridge is local-only. For remote sensors, prefer a VPN overlay and explicitly configure the mesh address and ports; public exposure is an advanced, separately hardened choice. Metadata/findings/health are centralized; raw PCAP, artifacts, and excerpts remain on the sensor unless a hashed case export is explicitly approved. See [Sensor Mesh](../sensor-mesh.md) and [Container deployment](../containers.md).

### 5.8 Windows Sysmon attribution

When separately installed/configured, Sysmon Event IDs 1 and 3 can correlate process creation and network connection telemetry to a flow. Attribution is classified as exact, socket fallback, ambiguous, or unattributed. The method and provenance matter: ambiguous candidates are not exact identity, and missing attribution does not mean no process used the network. Command lines are redacted; credentials and packet payloads are not attribution evidence. See [Sysmon attribution](../sysmon.md).

### 5.9 AI Analyst

The Analyst is an evidence-constrained support interface, not a packet classifier and not a scoring authority. Ollama is the local-first provider. Hosted providers require explicit configuration; there is no silent provider fallback. General conversation is data-free, while investigation mode needs explicit scope. The answer should distinguish native evidence, interpretation, external sources, unknowns, and incomplete work.

Read-only investigation may query scoped WatchTower data. Public-indicator research is separate from permission to send capture context; private addresses, hostnames, payload-derived text, and case context require confirmation before leaving the machine. Tool/data content is untrusted and cannot override policy. State-changing actions require exact operation/scope approval and may require step-up authentication. Interrupted actions are not replayed automatically. See [AI Analyst](../ai-analyst.md).

### 5.10 Plugins, calibration, and trust

The extension model has four surfaces: bounded protocol parsers, typed detectors, capture sources, and historical Sigma rules. Contracts declare versions, inputs, supported protocols/sources, state bounds, health, outputs, and failure behavior. Detector code cannot assign final risk or self-certify trust.

Calibration runs compare deterministic labeled scenarios against production pipelines and supported backends. A run creates a report; it does not grant trust. Promotion revalidates evidence, records reviewer/reason, writes a content-addressed attestation, and updates the scoring profile. The profile and referenced attestation must be delivered together. A changed source, corpus, scoring policy, runtime version, or backend hash can make trust stale. See [Plugin Development](../plugins.md) and [Calibration](../calibration.md).

## 6. Architecture and data flow

WatchTower is a local-first modular monolith with isolated capture workers, versioned Rust/Python boundaries, SQLite evidence storage, a loopback API, and a separately built React/TypeScript UI. The CLI and UI are clients of shared services and records.

```text
Network interface / hardware / PCAP
  → Rust capture and L2–L4 decode (or explicitly selected Python path)
  → bounded packet batches and canonical conversation tracking
  → Python protocol parsers and typed detection pipeline
  → evidence validation and Behavioral Scoring V2
  → repository-backed SQLite writes and session/case audit state
  → local FastAPI projections consumed by UI and CLI
  → optional SQLite-outbox-to-Neo4j materialization
```

### Component responsibilities

| Area | Responsibility |
|---|---|
| `rust/watchtower-sensor` | Capture/replay, decode and aggregate packets, filter, report metrics, and emit versioned bounded events. |
| `core/capture_sources` | Normalize network and supported hardware inputs and their capability/health declarations. |
| `core/packet_engine` | Coordinate capture workers, batch processing, persistence, adapters, and session drain. |
| `core/forensics` | PCAP jobs, parsers/detectors, indexing, stream spool, artifacts, triage, and Sigma synchronization. |
| `core/detection` | Finding contracts, detector state, scoring policy, baselines, fingerprints, and calibration profile use. |
| `core/storage` | SQLAlchemy models, repositories, additive migrations, and backup operations. |
| `core/intelligence` and `core/endpoint` | Evidence-backed endpoint identity/enrichment and optional Windows process/service attribution. |
| `core/api` | Loopback FastAPI routes, health and evidence projections, jobs, and event streaming. |
| `core/cli` and `ui` | Rich terminal workflows and React/TypeScript operator views over shared services. |
| `core/ai` | Providers, scoped tools, planner/orchestration, redaction, external research, approvals, and audit records. |
| `core/mesh` | Enrollment, mTLS transport, sequencing, spooling, typed commands, and node lifecycle. |
| `core/graph` | Durable SQLite outbox and optional Neo4j projection; never the source of truth. |

Rust owns high-rate capture and L2–L4 work. Python owns protocol plugins, canonical findings, scoring, persistence, API projections, and investigations. Keeping one scoring implementation avoids backend-specific risk semantics. Backend selection is explicit; a failed Rust run is not silently retried on Python. Parity tests compare canonical findings, evidence hashes, flows, and terminal status.

### Storage, provenance, and failures

SQLite is authoritative for local evidence, findings, sessions, identities, jobs, approvals, mesh state, and graph outbox records. Access goes through repositories and short-lived sessions. Schema changes are additive so an upgrade can retain operator data. Use WatchTower backup procedures rather than copying a live database file.

Live records are scoped by sensor node, source, interface, session, and backend; offline records by analysis/PCAP identity. Detectors and views should preserve these dimensions so records from unrelated sessions are not merged. Queues are bounded and drops are observable. End-of-session completeness requires ordered drain and persistence acknowledgements. Forced shutdown yields an explicit partial state, not a fabricated success.

Neo4j is an optional derived view. Failed graph writes remain queued in SQLite and expose lag/freshness. Provider outages, missing graph service, unsupported rules, and incomplete telemetry should be reported as limitations, not translated into a clean verdict.

## 7. Security, privacy, and operating boundaries

- The UI/API bind to loopback by default. The container controller API is internal to Compose; the UI is published on loopback.
- Authentication has an eight-hour absolute session lifetime; sensitive operations can demand recent step-up proof. Disabling auth is an explicit, security-sensitive setup option.
- Mesh uses enrollment-bound certificates, TLS, typed commands, and explicit lifecycle controls. Prefer VPN networking for remote nodes.
- Provider credentials use the operating-system credential store or the encrypted container vault. Container state and its installation key must be backed up together.
- External research treats web pages as untrusted; private/local context is not sent without confirmation. Public indicator research and hosted capture-context sharing are separate decisions.
- Captures, case databases, packet payloads, credentials, field bundles, and runtime reports are private operational artifacts. Do not commit them. Case exports are hashed and explicitly scoped.
- Capture sees only traffic delivered to the selected sensor/interface. It cannot prove the absence of behavior outside that vantage point, recover packets dropped before capture, infer a process without endpoint telemetry, or inspect encrypted application data without appropriate keys.

## 8. Deployment choices and lifecycle

| Deployment | Appropriate when | Important boundary |
|---|---|---|
| Native Windows | One Windows host and direct Npcap/Rust capture, with optional Sysmon. | UI/API and CLI run locally; the sensor requires host capture capability. |
| Windows hybrid | Windows capture with reproducible controller/UI containers. | Controller/UI live in Docker; sensor and Sysmon stay native. Compose UI is loopback-published. |
| Native Debian/Ubuntu | Linux capture and analysis with libpcap/Rust. | Grant capture capability deliberately or use a separately managed service account. |
| Controller plus remote mesh | Several sensor vantage points and centralized investigation. | Prefer VPN; raw packet/case data remain node-local unless explicitly exported. |
| Optional Neo4j/Ollama | Graph relationship traversal or local AI service. | Both are optional; core SQLite evidence/capture should remain useful without them. |

For upgrades, stop capture and mesh cleanly, back up runtime state, install the new source revision, run setup/doctor and calibration verification, then perform a short capture and check provenance and completion. For container deployments, preserve the state volume and encryption key together. A normal uninstall keeps data; purge only after a verified backup and an intentional decision to remove it. See [Operations](../operations.md), [Containers](../containers.md), and [Uninstall](../getting-started/uninstall.md).

## 9. What results can and cannot establish

WatchTower prioritizes observable, attributable, auditable evidence. It cannot conclude that a network is clean when there is no data, that an endpoint is compromised from volume or reputation alone, or that a Sigma hunt covered telemetry it never received. Identity may remain unknown; graph projection can be stale; capture can be incomplete; a provider can be unavailable. Those are meaningful outcomes and should stay visible in an investigation.

When writing a report, state the sensor/source/session or PCAP case, time range, evidence references, completeness, identity confidence, score meaning, external-source retrieval time, and limitations. Separate direct observation from interpretation and recommendations.

## 10. Further reading

- [Install and first capture](../getting-started.md) · [Platform installation details](../getting-started/README.md)
- [Command examples](../../USAGE.md) · [Operations, backups, upgrades](../operations.md)
- [Live detection and scoring](../live-detection.md) · [Forensics and custody](../forensics.md)
- [Identity and enrichment](../identity-enrichment.md) · [AI Analyst](../ai-analyst.md)
- [Sensor mesh](../sensor-mesh.md) · [Containers](../containers.md) · [Sysmon](../sysmon.md)
- [Plugins](../plugins.md) · [Calibration](../calibration.md) · [Architecture](../architecture.md)
- [API](../api.md) · [Troubleshooting](../troubleshooting.md) · [Security](../../SECURITY.md)
