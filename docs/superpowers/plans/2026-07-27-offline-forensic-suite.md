# Offline Forensic Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each offline PCAP a source-isolated, evidence-backed forensic case with identical CLI/UI projections, explainable suspicious-item triage, and an analyst-first topology.

**Architecture:** Add an immutable `ForensicCase` boundary around each PCAP analysis, preserve existing live/CLI tables for compatibility, and introduce case-scoped projection tables where the current global-IP schema cannot represent multiple cases safely. A shared `ForensicCaseProjection` service will feed the existing CLI modules and the UI API. Suspicion triage will consume existing detector, Sigma, IOC, protocol, and conversation evidence without replacing Behavioral Scoring V2.

**Tech Stack:** Python 3.9+, SQLAlchemy/SQLite additive migrations, Scapy/Rust replay, FastAPI, pytest, React 19, TanStack Router/Query, Cytoscape.js, TypeScript, existing Rich CLI styling.

## Global Constraints

- Preserve all existing CLI command names, Rich styling, and default live behavior.
- Every offline record must be scoped to an immutable case ID and PCAP content hash.
- Do not treat a public IP, uncommon port, or external reachability alone as malicious.
- Suspicion flags require one strong signal or two independent weaker signals and must retain evidence references.
- Never persist credentials, tokens, authorization values, or unrestricted packet payloads.
- Database migrations are additive and must work with existing user data.
- Python/Rust findings, case metrics, and evidence references must match where both backends support the same capability.
- New production behavior is introduced test-first: write a failing test, run it, implement the smallest change, then rerun focused and regression tests.
- Existing unrelated worktree changes must remain untouched.

---

### Task 1: Add Case-Scoped Storage Contracts

**Files:**
- Create: `tests/test_offline_case_storage.py`
- Modify: `core/storage/models.py:7-215`
- Modify: `core/storage/database.py:120-225, 3080-3350`
- Modify: `core/storage/database.py:120-225` to add the additive migration block beside existing `_ensure_column_exists` calls

**Interfaces:**
- Produce `ForensicCase`, `ForensicCaseEntity`, and `ForensicTriageFlag` SQLAlchemy models.
- Produce `WatchtowerDB.create_forensic_case(values) -> dict`.
- Produce `WatchtowerDB.get_forensic_case(case_id) -> dict | None`.
- Produce `WatchtowerDB.upsert_case_entity(case_id, values) -> dict`.
- Produce `WatchtowerDB.get_case_entities(case_id, limit, cursor) -> dict`.
- Produce `WatchtowerDB.upsert_triage_flag(case_id, values) -> dict` and `WatchtowerDB.get_triage_flags(case_id, status=None, limit=100, cursor=None) -> dict`.

- [ ] **Step 1: Write the failing scope-isolation tests**

```python
def test_same_ip_can_have_independent_entities_in_two_cases(db):
    db.create_forensic_case({"id": "case-a", "analysis_id": "analysis-a", "sha256": "a" * 64})
    db.create_forensic_case({"id": "case-b", "analysis_id": "analysis-b", "sha256": "b" * 64})
    db.upsert_case_entity("case-a", {"ip": "10.0.0.5", "hostname": "alpha", "confidence": 0.8})
    db.upsert_case_entity("case-b", {"ip": "10.0.0.5", "hostname": "bravo", "confidence": 0.9})
    assert db.get_case_entities("case-a", 100, None)["items"][0]["hostname"] == "alpha"
    assert db.get_case_entities("case-b", 100, None)["items"][0]["hostname"] == "bravo"


def test_triage_flag_is_case_scoped_and_idempotent(db):
    values = {"target_type": "ip", "target_id": "203.0.113.5", "fingerprint": "f" * 64,
              "reason": "IOC match", "confidence": 0.95, "status": "open"}
    first = db.upsert_triage_flag("case-a", values)
    second = db.upsert_triage_flag("case-a", values)
    assert first["id"] == second["id"]
    assert len(db.get_triage_flags("case-a")["items"]) == 1
```

- [ ] **Step 2: Run the focused tests and verify the expected missing-contract failure**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_case_storage.py -q`

Expected: FAIL because the case models and repository methods do not exist.

- [ ] **Step 3: Add additive models and migrations**

Add `ForensicCase` fields for case/analysis IDs, PCAP hash, filename, byte count, capture bounds, link type, parser/backend versions, state, progress, warnings, visibility limitations, report hash, created/completed timestamps, and retained-input policy. Add `ForensicCaseEntity` with a surrogate ID, `(case_id, ip)` uniqueness, identity fields, provenance JSON, confidence, traffic counters, and first/last seen. Add `ForensicTriageFlag` with `(case_id, fingerprint)` uniqueness, target fields, evidence references, reason, confidence, status, actor, and audit timestamps. Create missing tables additively and record migration names in the existing schema migration registry.

- [ ] **Step 4: Implement repository methods with bounded cursor pagination**

Use the existing `session_scope()` pattern. Sort entities by confidence, bytes, and IP; sort triage flags by status priority, confidence, last seen, and ID. Return `{items, next_cursor, cursor, limit}` and never expose ORM instances.

- [ ] **Step 5: Run focused and database regression tests**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_case_storage.py tests/test_database.py -q`

Expected: PASS with existing database behavior preserved.

- [ ] **Step 6: Commit the storage contract**

```powershell
git add tests/test_offline_case_storage.py core/storage/models.py core/storage/database.py core/storage/migrations.py
git commit -m "feat: add scoped offline case storage"
```

### Task 2: Create Immutable PCAP Cases and Chain of Custody

**Files:**
- Create: `tests/test_pcap_case_lifecycle.py`
- Modify: `core/api/pcap_jobs.py:19-173`
- Modify: `core/forensics/engine.py:520-711`
- Modify: `core/storage/models.py` for case/report foreign-key-compatible fields
- Modify: `core/storage/database.py` for case lifecycle methods

**Interfaces:**
- Produce `PcapJob.case_id` and `PcapJob.analysis_id` public fields.
- Produce `PcapJobManager.create_case_for_path(path, filename, mode, backend) -> dict`.
- Produce `WatchtowerDB.append_case_custody_event(case_id, event_type, digest, metadata) -> dict`.
- Produce `ForensicsEngine.analyze_pcap(..., case_id=None, source_name=None) -> ForensicReport`.

- [ ] **Step 1: Write failing lifecycle tests**

```python
def test_upload_creates_hash_bound_case_and_analysis(client, pcap_fixture):
    response = submit_fixture(client, pcap_fixture, backend="rust")
    job = wait_for_terminal(client, response.json()["id"])
    assert job["case_id"]
    assert job["analysis_id"] == job["id"]
    assert len(job["pcap_sha256"]) == 64
    assert job["processing_state"] == "complete"
    case = client.get(f"/api/v2/pcap/cases/{job['case_id']}").json()
    assert case["sha256"] == job["pcap_sha256"]
    assert case["custody"][0]["event_type"] == "ingested"
```

- [ ] **Step 2: Run the test and verify it fails for missing case fields/endpoints**

Run: `.\WT\Scripts\pytest.exe tests/test_pcap_case_lifecycle.py -q`

Expected: FAIL because jobs do not create immutable case records.

- [ ] **Step 3: Add content hashing and case creation**

Hash the uploaded file in bounded chunks before analysis. Create the case once with the hash, file metadata, requested mode/backend, and a custody event. Set the analysis ID to the durable job ID. Pass `case_id` into the engine and preserve the existing source string for CLI compatibility.

- [ ] **Step 4: Persist capture bounds and terminal state**

During replay, record the minimum and maximum packet timestamps, link type, parser/backend versions, bytes processed, packet count, warnings, truncation, and final state. Compute a canonical report hash from sorted case metrics and record a completed or partial custody event. A corrupt or cancelled input must not reach `complete`.

- [ ] **Step 5: Add case lifecycle endpoints**

Add `GET /api/v2/pcap/cases`, `GET /api/v2/pcap/cases/{case_id}`, and `GET /api/v2/pcap/cases/{case_id}/custody`. Keep the existing job endpoints unchanged and include `case_id`/`analysis_id` in their payloads.

- [ ] **Step 6: Run focused lifecycle tests and commit**

Run: `.\WT\Scripts\pytest.exe tests/test_pcap_case_lifecycle.py tests/test_pcap_api.py -q`

```powershell
git add tests/test_pcap_case_lifecycle.py core/api/pcap_jobs.py core/forensics/engine.py core/storage/models.py core/storage/database.py core/api/server.py
git commit -m "feat: bind offline analysis to immutable cases"
```

### Task 3: Build the Shared Forensic Case Projection

**Files:**
- Create: `tests/test_forensic_case_projection.py`
- Create: `core/forensics/case_projection.py`
- Modify: `core/api/service.py:1096-1388`
- Modify: `core/api/server.py:835-990`
- Modify: `core/cli/modules/forensics.py` at existing report, flows, alerts, dive, and graph readers
- Modify: `core/storage/database.py` for case-scoped flow/conversation/entity queries

**Interfaces:**
- Produce `ForensicCaseProjection.get_case(case_id) -> dict`.
- Produce `ForensicCaseProjection.page(case_id, kind, limit=100, cursor=None, filters=None) -> dict`.
- Produce `ForensicCaseProjection.summary(case_id) -> dict`.
- Produce `ForensicCaseProjection.conversations(case_id, limit=100, cursor=None, filters=None) -> dict`.
- Produce `ForensicCaseProjection.timeline(case_id, limit=200, cursor=None, filters=None) -> dict`.
- Produce `ForensicCaseProjection.export_manifest(case_id) -> dict`.

- [ ] **Step 1: Write the parity regression test before changing projections**

```python
def test_case_projection_exposes_entities_that_cli_report_counts(client, completed_case):
    case = client.get(f"/api/v2/pcap/cases/{completed_case}").json()
    entities = client.get(f"/api/v2/pcap/cases/{completed_case}/entities?limit=500").json()
    flows = client.get(f"/api/v2/pcap/cases/{completed_case}/flows?limit=500").json()
    assert len(entities["items"]) == case["summary"]["total_entities"]
    assert len(flows["items"]) == case["summary"]["total_flows"]
```

- [ ] **Step 2: Run the test and capture the current mismatch**

Run: `.\WT\Scripts\pytest.exe tests/test_forensic_case_projection.py -q`

Expected: FAIL with entity count zero despite the report summary containing entities.

- [ ] **Step 3: Implement one projection service**

Read case-scoped entities from `ForensicCaseEntity`, canonical conversations from case-tagged flow rows, findings from the existing V2 finding sink, alerts as compatibility projections, and artifacts/evidence/streams from case-scoped records. Every returned item includes `case_id`, `analysis_id`, source, timestamps, and native evidence references. Use opaque base64 keyset cursors for new endpoints while accepting numeric cursors in existing endpoints.

- [ ] **Step 4: Route API and CLI compatibility readers through the projection**

Add `/api/v2/pcap/cases/{case_id}/summary`, `/entities`, `/flows`, `/conversations`, `/findings`, `/alerts`, `/timeline`, `/topology`, `/artifacts`, `/streams`, `/evidence`, and `/manifest`. Keep `/api/v2/pcap/analyses/{id}/...` as a case-resolving compatibility path. Update CLI internals to use the projection without changing command syntax, table headings, or default live behavior.

- [ ] **Step 5: Add cross-surface parity assertions**

Compare CLI report counts and first-page canonical IDs with the projection response. Assert that findings, evidence hashes, entity identity fields, timeline bounds, and topology edge IDs are equal for the same case.

- [ ] **Step 6: Run focused API/CLI tests and commit**

Run: `.\WT\Scripts\pytest.exe tests/test_forensic_case_projection.py tests/test_pcap_api.py tests/test_shell_ui.py -q`

```powershell
git add tests/test_forensic_case_projection.py core/forensics/case_projection.py core/api/service.py core/api/server.py core/cli/modules/forensics.py core/storage/database.py
git commit -m "feat: unify offline CLI and UI projections"
```

### Task 4: Add Conversation-Centric Evidence and Redacted Streams

**Files:**
- Create: `tests/test_offline_conversations.py`
- Create: `core/forensics/conversations.py`
- Create: `core/forensics/evidence_projection.py`
- Modify: `core/forensics/engine.py:892-1244`
- Modify: `core/storage/models.py` and `core/storage/database.py`
- Modify: `core/api/server.py` and `core/api/service.py`

**Interfaces:**
- Produce `ConversationRecord.from_flow_rows(case_id, rows) -> list[dict]`.
- Produce `EvidenceExcerptBuilder.build(flow, direction, max_bytes=512) -> dict`.
- Produce `ForensicCaseProjection.stream_excerpt(case_id, conversation_id, direction) -> dict`.

- [ ] **Step 1: Write failing conversation tests**

```python
def test_conversation_projection_merges_reverse_rows_and_preserves_direction(case_projection):
    record = case_projection.conversations("case-a", limit=10)["items"][0]
    assert record["initiator"]
    assert record["responder"]
    assert record["to_responder_bytes"] >= 0
    assert record["to_initiator_bytes"] >= 0
    assert "retransmissions" in record
    assert record["first_seen"] <= record["last_seen"]


def test_stream_excerpt_masks_credentials_and_is_bounded(case_projection):
    excerpt = case_projection.stream_excerpt("case-a", "conversation-1", "to_responder")
    assert len(excerpt["excerpt"]) <= 512
    assert "password" not in excerpt["excerpt"].lower()
    assert excerpt["evidence_hash"]
```

- [ ] **Step 2: Run the tests and verify the missing conversation/evidence fields**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_conversations.py -q`

Expected: FAIL because current projections expose directional rows and hashes but not complete conversation evidence.

- [ ] **Step 3: Implement canonical conversation aggregation**

Use protocol and unordered endpoint pairs to merge reverse rows within a case, preserve initiator selection from SYN/first observed direction, sum directional counters, retain TCP outcomes, retransmission metadata, L7 metadata, and first/last timestamps. Persist bounded conversation records or derive them deterministically from case-scoped rows.

- [ ] **Step 4: Implement redacted evidence excerpts**

Decode only bounded stored stream data. Mask protocol-specific credentials, authorization headers, cookies, tokens, and password fields. Return direction, protocol, evidence hash, truncation state, and a native reference; return metadata-only when payload is unavailable.

- [ ] **Step 5: Run protocol, carving, and evidence regression tests**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_conversations.py tests/test_carving.py tests/test_protocol_plugins.py -q`

- [ ] **Step 6: Commit the evidence projection**

```powershell
git add tests/test_offline_conversations.py core/forensics/conversations.py core/forensics/evidence_projection.py core/forensics/engine.py core/storage/models.py core/storage/database.py core/api/server.py core/api/service.py
git commit -m "feat: add case-scoped conversations and redacted evidence"
```

### Task 5: Implement Explainable Suspicion Triage

**Files:**
- Create: `tests/test_offline_suspicion.py`
- Create: `core/forensics/suspicion.py`
- Modify: `core/forensics/engine.py` after offline finalization
- Modify: `core/storage/models.py` and `core/storage/database.py`
- Modify: `core/api/server.py` and `core/api/service.py`
- Modify: `tests/test_pcap_api.py`

**Interfaces:**
- Produce `SuspicionTriage.evaluate_case(case_id) -> dict`.
- Produce `SuspicionTriage.flag(case_id, target_type, target_id, reason, actor) -> dict`.
- Produce `SuspicionTriage.dismiss(flag_id, status, reason, actor) -> dict`.
- Add `GET /api/v2/pcap/cases/{case_id}/suspicious` and `POST /api/v2/pcap/cases/{case_id}/suspicious`.
- Add `POST /api/v2/pcap/suspicious/{flag_id}/status`.

- [ ] **Step 1: Write failing triage tests**

```python
def test_ioc_match_creates_suspicious_ip_with_evidence(case_projection, db):
    result = SuspicionTriage(db).evaluate_case("case-a")
    item = next(item for item in result["items"] if item["target_type"] == "ip")
    assert item["status"] == "open"
    assert item["reason"]
    assert item["evidence_refs"]
    assert item["confidence"] >= 0.9


def test_external_ip_alone_does_not_create_suspicious_flag(case_projection, db):
    result = SuspicionTriage(db).evaluate_case("benign-case")
    assert all(item["target_id"] != "198.51.100.10" for item in result["items"])


def test_manual_flag_is_audited_and_case_scoped(api_client):
    response = api_client.post("/api/v2/pcap/cases/case-a/suspicious", json={
        "target_type": "flow", "target_id": "conversation-1", "reason": "Investigate beacon candidate",
    })
    assert response.status_code == 201
    assert response.json()["status"] == "open"
```

- [ ] **Step 2: Run the tests and verify the triage contract is absent**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_suspicion.py -q`

Expected: FAIL because the triage service and endpoints do not exist.

- [ ] **Step 3: Implement evidence-backed candidate generation**

Aggregate existing canonical findings, Sigma matches, IOC/reputation matches, protocol mismatches, authentication failures, scan/beacon indicators, unusual TCP outcomes, rare destinations, and artifact metadata. Require one strong signal or two independent signal families. Generate deterministic fingerprints and store observed values, thresholds, contributing IDs, evidence references, confidence, first/last seen, and target details.

- [ ] **Step 4: Implement manual flagging and dispositions**

Persist manual flags with actor, reason, timestamp, and scope. `benign`/`dismissed` items leave evidence intact, disappear from the default open queue, and do not alter Behavioral Scoring V2 without the existing explicit disposition path.

- [ ] **Step 5: Run detector and scoring regressions**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_suspicion.py tests/test_behavioral_scoring_v2_acceptance.py tests/test_behavioral_detectors_v2_recovery.py tests/test_sigma_engine.py -q`

- [ ] **Step 6: Commit suspicion triage**

```powershell
git add tests/test_offline_suspicion.py tests/test_pcap_api.py core/forensics/suspicion.py core/forensics/engine.py core/storage/models.py core/storage/database.py core/api/server.py core/api/service.py
git commit -m "feat: add explainable offline suspicion triage"
```

### Task 6: Build the Analyst Case Overview and Evidence Pivots

**Files:**
- Modify: `ui/src/lib/pcap.ts`
- Modify: `ui/src/types/watchtower.ts`
- Modify: `ui/src/routes/forensics.tsx`
- Create: `ui/src/components/ForensicCaseOverview.tsx`
- Create: `ui/src/components/ForensicSuspicionQueue.tsx`
- Create: `ui/src/components/ForensicEvidencePanel.tsx`
- Create: `ui/src/components/ForensicCaseScope.tsx`

**Interfaces:**
- `getForensicCase(caseId)`, `getForensicCaseSummary(caseId)`, `getForensicSuspicious(caseId)`, and `setForensicFlagStatus(flagId, status, reason)` in `ui/src/lib/pcap.ts`.
- `ForensicCaseOverview` accepts `caseId` and a typed `ForensicCaseSummary`.
- `ForensicSuspicionQueue` accepts paginated triage items and emits target pivots.

- [ ] **Step 1: Add a failing type/API contract test**

Create `ui/src/lib/pcap.contract.test.ts` using the existing test setup. Assert that case summary types require `case_id`, `analysis_id`, `sha256`, `capture_start`, `capture_end`, `visibility_limitations`, `top_conversations`, and `suspicious_count`.

- [ ] **Step 2: Run the UI contract check and verify missing case types/functions**

Run: `npm --prefix ui run typecheck`

Expected: FAIL until the new types and functions are implemented.

- [ ] **Step 3: Add case-scoped data clients and URL scope**

Make the selected case ID explicit in the URL, load overview data first, and lazy-load large projections. Preserve current layout, typography, colors, button language, and report tabs.

- [ ] **Step 4: Implement the analyst overview**

Show case identity, hash, capture bounds, processing state, parser/link details, local asset count, external peer count, protocol mix, top conversations, open suspicion count, alerts/findings, and visibility limitations. Every card links to the relevant tab or filtered view.

- [ ] **Step 5: Implement suspicion queue and pivots**

Show target type, target value, reason, confidence, evidence count, first/last seen, and status. Add one-click `Flag for investigation`, `Mark benign`, and `Dismiss` actions with a reason dialog. Link IP/flow/domain/certificate/ASN/artifact targets to the appropriate scoped view.

- [ ] **Step 6: Run UI checks and commit**

Run: `npm --prefix ui run lint; npm --prefix ui run typecheck; npm --prefix ui run build`

```powershell
git add ui/src/lib/pcap.ts ui/src/types/watchtower.ts ui/src/routes/forensics.tsx ui/src/components/ForensicCaseOverview.tsx ui/src/components/ForensicSuspicionQueue.tsx ui/src/components/ForensicEvidencePanel.tsx ui/src/components/ForensicCaseScope.tsx
git commit -m "feat: add offline case overview and suspicion queue"
```

### Task 7: Replace the Crowded Topology With an Analyst Map

**Files:**
- Create: `tests/test_offline_topology.py`
- Create: `core/forensics/topology.py`
- Modify: `core/api/service.py:1183-1249`
- Modify: `core/api/server.py` topology routes
- Modify: `ui/src/components/PcapTemporalTopology.tsx`
- Create: `ui/src/components/PcapAnalystTopology.tsx`
- Modify: `ui/src/lib/pcap.ts`

**Interfaces:**
- Produce `AnalystTopology.build(case_id, filters) -> {nodes, edges, counts, suppressed, clusters}`.
- Support filters `mode=analyst|full`, `protocol`, `entity`, `finding_only`, `min_bytes`, `min_packets`, `time_start`, and `time_end`.
- Return stable node/edge IDs and a `suppressed` summary so hidden traffic remains auditable.

- [ ] **Step 1: Write failing topology reduction tests**

```python
def test_analyst_topology_suppresses_low_signal_edges(case_projection):
    result = AnalystTopology(case_projection.db).build("case-a", {"mode": "analyst"})
    assert len(result["edges"]) < result["counts"]["all_edges"]
    assert result["suppressed"]["broadcast_control"] >= 0
    assert all(edge["data"]["id"] for edge in result["edges"])


def test_full_topology_and_filters_recover_hidden_connections(case_projection):
    result = AnalystTopology(case_projection.db).build("case-a", {"mode": "full", "protocol": "TCP"})
    assert all(edge["data"].get("protocol") == "TCP" for edge in result["edges"])
```

- [ ] **Step 2: Run the tests and verify the current topology has no analyst reduction contract**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_topology.py -q`

Expected: FAIL because topology currently returns the full conversation set without ranked suppression metadata.

- [ ] **Step 3: Implement ranked topology construction**

Rank edges by findings, suspicion flags, bytes, recurrence, novelty, and protocol relevance. Suppress broadcast/multicast/link-local discovery and low-signal control edges in analyst mode. Cluster external endpoints by resolved domain, ASN, certificate, or service when evidence supports it; otherwise retain separate IP nodes. Keep every suppressed edge available through full mode.

- [ ] **Step 4: Implement UI controls and temporal playback**

Add analyst/full mode, protocol and entity filters, finding-only toggle, minimum byte threshold, cluster toggle, expand neighborhood, cumulative/active-only playback, play/pause, seek, and speed controls. Use stable Cytoscape layouts and never mount thousands of unfiltered edges in the initial analyst view.

- [ ] **Step 5: Run topology/UI checks and commit**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_topology.py tests/test_pcap_api.py -q; npm --prefix ui run lint; npm --prefix ui run typecheck; npm --prefix ui run build`

```powershell
git add tests/test_offline_topology.py core/forensics/topology.py core/api/service.py core/api/server.py ui/src/components/PcapTemporalTopology.tsx ui/src/components/PcapAnalystTopology.tsx ui/src/lib/pcap.ts
git commit -m "feat: add analyst-ranked offline topology"
```

### Task 8: Add Case Export and Forensic Evidence Manifest

**Files:**
- Create: `tests/test_offline_case_export.py`
- Create: `core/forensics/case_export.py`
- Modify: `core/api/server.py`
- Modify: `core/api/service.py`
- Modify: `ui/src/lib/pcap.ts`
- Modify: `ui/src/routes/forensics.tsx`

**Interfaces:**
- Produce `CaseExporter.build_manifest(case_id) -> dict`.
- Produce `CaseExporter.export(case_id, output_path) -> dict`.
- Add `GET /api/v2/pcap/cases/{case_id}/manifest` and `POST /api/v2/pcap/cases/{case_id}/export`.

- [ ] **Step 1: Write failing export tests**

```python
def test_case_manifest_contains_hashes_and_visibility_limits(case_exporter):
    manifest = case_exporter.build_manifest("case-a")
    assert manifest["case_id"] == "case-a"
    assert manifest["pcap_sha256"]
    assert manifest["report_sha256"]
    assert "visibility_limitations" in manifest
    assert "findings" in manifest["counts"]


def test_export_does_not_include_raw_payloads(case_exporter, tmp_path):
    result = case_exporter.export("case-a", tmp_path / "case.json")
    exported = (tmp_path / "case.json").read_text(encoding="utf-8")
    assert "password=" not in exported.lower()
    assert result["manifest_sha256"]
```

- [ ] **Step 2: Run the tests and verify export is missing**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_case_export.py -q`

Expected: FAIL because case manifests and export endpoints do not exist.

- [ ] **Step 3: Implement deterministic manifest and redacted bundle export**

Export case metadata, counts, custody events, entities, conversations, findings, triage flags, artifacts, streams metadata, topology summary, timeline bounds, and evidence references. Exclude raw packets and unrestricted payloads. Hash each manifest section and the final bundle.

- [ ] **Step 4: Add UI export action and visibility summary**

Add an explicit export button with progress/error handling and a visible list of data omitted because of retention, redaction, truncation, missing keylog, parser limitations, or unavailable enrichment.

- [ ] **Step 5: Run export/API regression tests and commit**

Run: `.\WT\Scripts\pytest.exe tests/test_offline_case_export.py tests/test_pcap_api.py -q; npm --prefix ui run typecheck; npm --prefix ui run build`

```powershell
git add tests/test_offline_case_export.py core/forensics/case_export.py core/api/server.py core/api/service.py ui/src/lib/pcap.ts ui/src/routes/forensics.tsx
git commit -m "feat: export redacted offline case bundles"
```

### Task 9: Add PCAP Corpus Acceptance and Parity Tests

**Files:**
- Create: `tests/test_offline_corpus_acceptance.py`
- Create: `tests/fixtures/offline_case_expectations.yaml`
- Modify: `tests/test_rust_fast_analysis.py`
- Modify: `tests/test_pcap_api.py`
- Modify: `README.md` with the offline acceptance command

**Interfaces:**
- Produce an opt-in command `WATCHTOWER_OFFLINE_ACCEPTANCE=1 .\WT\Scripts\pytest.exe tests/test_offline_corpus_acceptance.py -q`.
- The test reads PCAP paths from `offline_analysis_test_files` and does not commit captures, databases, or runtime reports.

- [ ] **Step 1: Write the acceptance test and expectation schema**

Require each available PCAP to produce a complete Rust case, nonzero flows, source-scoped entities, canonical conversations, timeline bounds, topology nodes, and a suspicious queue that is either explainably empty or contains evidence-backed candidates. The schema stores minimum expectations and detector observations, not brittle exact IDs.

- [ ] **Step 2: Run the acceptance test before implementation completion**

Run: `$env:WATCHTOWER_OFFLINE_ACCEPTANCE='1'; .\WT\Scripts\pytest.exe tests/test_offline_corpus_acceptance.py -q`

Expected: FAIL on the current entity projection, case metadata, and analyst topology requirements.

- [ ] **Step 3: Implement parity assertions for Python and Rust where supported**

Replay each case with Rust and Python, compare flows/conversations, finding fingerprints, evidence hashes, entity identities, and report counts. Mark unsupported parser/backend capabilities explicitly rather than silently comparing incomplete results.

- [ ] **Step 4: Run the full regression and UI build gates**

Run: `.\WT\Scripts\pytest.exe -q; npm --prefix ui run lint; npm --prefix ui run typecheck; npm --prefix ui run build`

- [ ] **Step 5: Run the supplied-PCAP UI acceptance**

Start the API/UI on the configured non-conflicting port, upload every supplied PCAP through the Forensics UI, open every case tab, flag at least one suspicious candidate when evidence supports it, dismiss one candidate, export a bundle, and compare the UI counters/IDs against the CLI projection. Record timing, RSS, errors, and unresolved visibility limitations in `docs/reports/` without committing runtime captures or databases.

- [ ] **Step 6: Commit acceptance coverage and documentation**

```powershell
git add tests/test_offline_corpus_acceptance.py tests/fixtures/offline_case_expectations.yaml tests/test_rust_fast_analysis.py tests/test_pcap_api.py README.md
git commit -m "test: add offline corpus parity acceptance"
```

## Verification Checklist

- [ ] Current UI-zero-entities regression fails before the storage/projection changes and passes afterward.
- [ ] Same IP in two cases retains independent identity fields and evidence.
- [ ] CLI and UI expose identical case counts, canonical IDs, findings, evidence hashes, and timeline bounds.
- [ ] Suspicious IP/flow/entity candidates are explainable, case-scoped, auditable, and conservative.
- [ ] Topology analyst mode is bounded and useful while full mode preserves complete visibility.
- [ ] Artifacts, streams, evidence, and limitations are visible from the case workspace.
- [ ] Rust/Python parity is exact where supported.
- [ ] Existing CLI styling and live behavior remain unchanged.
- [ ] Full Python tests and UI lint/typecheck/build pass.
