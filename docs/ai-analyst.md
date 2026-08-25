# AI Analyst

WatchTower's AI layer is an evidence-constrained analyst, not a packet classifier and not an authority over scoring. It uses typed tools, scoped context, citations, policy checks, approvals, and audit records.

## Providers

Ollama is the default local provider. OpenAI is opt-in per configuration and conversation. Provider failures are visible and never trigger silent fallback.

```text
tower ai status
tower ai provider connect ollama
tower ai models list --provider ollama
tower ai model set MODEL --provider ollama
tower chat
tower chat --mode general
tower chat --mode investigate --source live --interface Ethernet --session SESSION_ID
```

## Analyst modes and readiness

`general` is an intentionally data-free conversation. It cannot inherit the
current UI scope or invoke a WatchTower tool. `investigate` requires an
explicit source, interface, session, node, case, or endpoint scope. `auto`
selects between those modes from the prompt, but the UI exposes the selector
so operators can make the boundary explicit. Action-capable prompts use the
separate approval policy and never run before confirmation.

Provider reachability is not the same as agentic readiness. Run:

```text
tower ai provider test ollama
```

The result includes a harmless native-tool capability probe. A provider may
remain available for general chat while its agentic mode is marked unavailable.
No silent provider fallback occurs.

To connect OpenAI:

```text
tower ai provider connect openai
```

ChatGPT subscriptions and OpenAI API billing are separate. The API key is accepted through a masked prompt and stored in the operating-system credential manager. It is not written to `.env`, YAML, SQLite, logs, prompts, or browser storage.

## Investigation tools

Read-only tools cover flows, conversations, assets, endpoint identities, findings, score explanations, timelines, topology, PCAP reports, pipeline health, plugin inventory, calibration status, historical Sigma hunt previews, evidence excerpts, process attribution, mesh health, and graph paths.

Network-specific claims require native WatchTower evidence citations. External claims require a source URL, retrieval time, category, and content hash. Analyst inference is labeled separately.

Every completed answer passes deterministic claim validation. Unsupported IP
addresses and concrete numeric claims are removed, textual tool calls are never
executed as prose, and the run is marked `DEGRADED` with a visible warning when
the evidence is incomplete. The run ledger records rounds, tool calls, context
size, citation coverage, validation status, supported/inferred/blocked claims,
and numeric accuracy.

## Research privacy

Public IPs, domains, URLs, hashes, certificate fingerprints, ASNs, and public software versions may be researched automatically when enabled. Internal addresses, MACs, hostnames, private domains, packet-derived text, case content, and operator context require confirmation before leaving the machine.

Fetched pages are untrusted evidence. They cannot instruct the agent, invoke tools, or override policy. URL access is HTTPS-only, blocks private and metadata destinations after resolution, validates redirects, and applies response and time budgets.

## Actions and approvals

Read-only investigation runs automatically. Non-destructive writes such as report export, PCAP analysis, scoring recomputation, disposition, enrichment rebuild, or calibration execution require confirmation. Capture control, survey, Sigma synchronization, and external provider use require exact scope review. Destructive operations require typed confirmation and recent step-up authentication.

Approvals bind exact arguments, scope, requester, expiry, and idempotency key. The analyst reports completion only from the underlying service result.

## Detector authoring

The AI can prepare detector scaffolds and calibration scenarios through typed WatchTower tools. Generated code remains uncalibrated until deterministic corpus evaluation and explicit reviewed promotion. The AI cannot directly grant scoring trust.
