from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "WatchTower_Product_Evaluation_2026-09-19.pdf"


NAVY = colors.HexColor("#10243e")
BLUE = colors.HexColor("#1d5f93")
TEAL = colors.HexColor("#0d8076")
AMBER = colors.HexColor("#a76800")
RED = colors.HexColor("#a83832")
PALE_BLUE = colors.HexColor("#eaf3fb")
PALE_AMBER = colors.HexColor("#fff4dc")
PALE_RED = colors.HexColor("#fdebea")
GRID = colors.HexColor("#d3dce5")
TEXT = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#5b6773")


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(
    name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
    fontSize=27, leading=32, textColor=NAVY, alignment=TA_CENTER, spaceAfter=10,
))
styles.add(ParagraphStyle(
    name="CoverSub", parent=styles["Normal"], fontName="Helvetica",
    fontSize=12, leading=18, textColor=MUTED, alignment=TA_CENTER, spaceAfter=8,
))
styles.add(ParagraphStyle(
    name="H1x", parent=styles["Heading1"], fontName="Helvetica-Bold",
    fontSize=17, leading=21, textColor=NAVY, spaceBefore=4, spaceAfter=9,
))
styles.add(ParagraphStyle(
    name="H2x", parent=styles["Heading2"], fontName="Helvetica-Bold",
    fontSize=12, leading=15, textColor=BLUE, spaceBefore=8, spaceAfter=5,
))
styles.add(ParagraphStyle(
    name="Bodyx", parent=styles["BodyText"], fontName="Helvetica",
    fontSize=8.8, leading=12.2, textColor=TEXT, spaceAfter=6,
))
styles.add(ParagraphStyle(
    name="Smallx", parent=styles["BodyText"], fontName="Helvetica",
    fontSize=7.2, leading=9.4, textColor=MUTED, spaceAfter=3,
))
styles.add(ParagraphStyle(
    name="Tablex", parent=styles["BodyText"], fontName="Helvetica",
    fontSize=7.1, leading=9.1, textColor=TEXT,
))
styles.add(ParagraphStyle(
    name="TableHeadx", parent=styles["BodyText"], fontName="Helvetica-Bold",
    fontSize=7.2, leading=9.2, textColor=colors.white,
))
styles.add(ParagraphStyle(
    name="Score", parent=styles["BodyText"], fontName="Helvetica-Bold",
    fontSize=12, leading=14, textColor=NAVY, alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name="Callout", parent=styles["BodyText"], fontName="Helvetica",
    fontSize=9, leading=13, textColor=NAVY, leftIndent=8, rightIndent=8,
    spaceBefore=5, spaceAfter=5,
))


def P(text: str, style: str = "Bodyx") -> Paragraph:
    return Paragraph(escape(text).replace("\n", "<br/>"), styles[style])


def raw(text: str, style: str = "Bodyx") -> Paragraph:
    return Paragraph(text, styles[style])


def table(rows, widths, header=True, row_backgrounds=None):
    converted = []
    for r, row in enumerate(rows):
        converted.append([
            Paragraph(escape(str(cell)), styles["TableHeadx" if header and r == 0 else "Tablex"])
            for cell in row
        ])
    t = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if row_backgrounds:
        for idx, color in row_backgrounds.items():
            commands.append(("BACKGROUND", (0, idx), (-1, idx), color))
    t.setStyle(TableStyle(commands))
    return t


def callout(text: str, background=PALE_BLUE):
    t = Table([[raw(text, "Callout")]], colWidths=[174 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.6, BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(GRID)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9 * mm, "WatchTower product evaluation | 19 September 2026")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


scores = [
    ("Native installation and lifecycle", "5.8", "5%", "Setup automation, auth setup, diagnostics, start/stop/uninstall.", "Runtime dependencies are heavy; Rust availability is not part of backend selection; native and test seams drift."),
    ("Container/controller deployment", "6.4", "4%", "Controller, persistent volume, mesh ports, optional Neo4j separation.", "Native capture is a separate sensor path; container-to-host AI connectivity and deployment role are not a single guided workflow."),
    ("Offline PCAP and case workflow", "6.8", "6%", "Case identity, evidence envelopes, timeline, topology, artifacts, cancellation states.", "Default Rust replay fails hard when the sensor binary is absent; partial/cancelled finalization has real failure cases."),
    ("Live capture and source management", "5.7", "8%", "Network and Bluetooth source abstraction, backend policy, capture sessions.", "Policy chooses Rust by name rather than probing the binary; Windows capture path has dependency and daemon seams."),
    ("Behavioural sensing", "6.1", "8%", "Stateful, protocol, coverage, beaconing, recon, exfiltration, and application-abuse detectors.", "Three high-value detectors are disabled by default: beaconing, recon/lateral movement, and exfiltration."),
    ("Detection, risk, and alert triage", "7.0", "8%", "Canonical findings, policy suppression, dispositions, risk rollups, calibration metadata.", "Legacy, dual, and V2 scoring modes remain visible in the implementation; users can still encounter mixed semantics."),
    ("Flows and conversations", "6.8", "5%", "Scoped flow queries, protocol metadata, conversation tracking, bounded stream handling.", "Large-query behavior relies on limits and sampling boundaries that are not consistently surfaced as a user-facing completeness model."),
    ("Identity and enrichment", "7.2", "7%", "Evidence-backed identity, provenance, confidence, local asset profiles, enrichment reindexing.", "Identity views and hunts do not share one complete scope contract; entity queries are less scoped than flow queries."),
    ("Forensics, evidence, and cases", "6.8", "8%", "Immutable analysis identity, encrypted evidence envelopes, forensic cases, deep dissection.", "The richest path is also the most dependency-sensitive; Rust-first failure can block the core offline workflow."),
    ("Topology and evidence graph", "6.2", "4%", "Neo4j materialization, neighborhood, shortest path, timeline, Cytoscape visualization.", "Graph is an optional service with a separate operational lifecycle; degraded flow-based relationships are not the primary experience."),
    ("Sigma rules and hunts", "6.7", "7%", "Validated rule loading, rejection reasons, preview/install/sync/rollback, scoped historical hunts.", "Compatibility is intentionally a subset; identity-category hunts currently use entities filtered only by source, not full scope."),
    ("Mesh and sensor fleet", "6.3", "8%", "Encrypted enrollment, certificate rotation, revocation, spooling, controller commands, fleet UI.", "Hybrid capture and controller APIs have contract drift; command lifecycle is more complex than the operator task requires."),
    ("Plugins and calibration", "6.8", "4%", "Manifest validation, calibration levels, attestation lookup, plugin health, scaffolding.", "The trust model is disciplined but operationally difficult; disabled/uncalibrated capabilities are not yet translated into a simple coverage story."),
    ("AI analyst", "7.1", "10%", "Conversation memory, idempotency, approvals, scope filtering, provider test, SSE progress, CLI parity.", "Durable event replay, edit/branch/retry controls, complete research outcome taxonomy, and real local-model qualification remain."),
    ("Web UI and UX", "6.0", "5%", "Workspace navigation, simple/standard/analyst modes, status vocabulary, AI progress and scope controls.", "Mode-based information hiding conflicts with a single natural interface; large monolithic routes keep setup and analysis concerns dense."),
    ("CLI and UX", "6.1", "3%", "Rich task families, help text, JSON output in many commands, doctor, auth, AI and forensics controls.", "The 1,088-line shell contains legacy aliases and overlapping command families; cross-surface lifecycle and failure vocabulary is not fully unified."),
]


def build_report():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=17 * mm, bottomMargin=19 * mm, title="WatchTower Product Evaluation",
        author="Codex",
    )
    story = []

    # Cover
    story += [Spacer(1, 28 * mm), P("WATCHTOWER", "CoverTitle"), P("Product evaluation and gap analysis", "CoverSub"),
              Spacer(1, 7 * mm), P("Management review | Native, container, offline, UI, and CLI paths", "CoverSub"),
              Spacer(1, 16 * mm), callout("Overall product score: 6.5 / 10\n\nWatchTower has unusually broad security and forensics ambition, with strong evidence, identity, calibration, and AI foundations. Its current product risk is not lack of capability; it is inconsistent seams between runtime dependencies, scopes, state transitions, and operator surfaces.", PALE_BLUE),
              Spacer(1, 12 * mm), P("Assessment date: 19 September 2026", "CoverSub"), P("Repository: C:/Users/aksha/Desktop/Projects/WT1", "Smallx"), PageBreak()]

    story += [P("1. Executive assessment", "H1x"),
              P("WatchTower is a serious research-grade platform rather than a narrow network monitor. It combines live capture, historical forensics, detection and scoring, identity, graphing, mesh sensors, Sigma, plugins, and a local-first AI analyst. That breadth is its main strategic strength and its main product problem: the operator has to understand too many service boundaries and capability modes before reaching a dependable answer."),
              callout("Management decision: continue investment, but move the product from feature expansion to contract hardening. The next release should optimize for predictable startup, explicit capability coverage, consistent scope, and one recovery model across UI and CLI.", PALE_AMBER),
              P("The 6.5 score is a weighted product score, not a test pass percentage. A 7 means the capability is useful for an informed operator but still has material operational caveats. A 9 requires predictable setup, clear degraded behavior, complete scope semantics, and a smooth primary workflow."),
              P("The product is strongest in: evidence-backed storage, identity provenance, detection policy structure, extensible plugin contracts, and the foundations of the AI analyst. It is weakest in: Rust/runtime readiness, cross-layer state and API contracts, default behavioural coverage, and information architecture across the web and shell surfaces."),
              P("The README explicitly positions the release as experimental and a research project. That is accurate for the present architecture and should remain visible until the release and lifecycle gaps below are closed. (README.md:5-9)"),
              PageBreak()]

    story += [P("2. Scorecard", "H1x"),
              P("Weights reflect product importance for the intended WatchTower workflow: capture or import data, establish trustworthy evidence, detect and prioritize, investigate, and recover from operational failure. UI and CLI are scored separately and included in the aggregate."),
              table([("Path", "Score", "Weight", "What is working", "Primary gap")]+scores, [39*mm, 14*mm, 13*mm, 51*mm, 57*mm], row_backgrounds={}),
              Spacer(1, 6), callout("Aggregate: 6.5 / 10. Technical capability excluding UI/CLI: approximately 6.5 / 10. Web UI/UX: 6.0 / 10. CLI/UX: 6.1 / 10.", PALE_BLUE),
              PageBreak()]

    story += [P("3. Feature-path assessment", "H1x"),
              P("The following assessment treats each path as a product journey, not as an isolated module. A path scores lower when the underlying feature is sophisticated but the user must manually bridge dependencies, scopes, or recovery states."),
              P("Installation and lifecycle", "H2x"),
              P("The native setup path is thoughtful: it pins or checks Python, Rust, Node, Npcap, the Npcap SDK, optional Sysmon and Neo4j, builds the UI and sensor, configures operator access, and runs diagnostics. The container path separates the controller from native capture and persists state in a named volume. Uninstall supports keep-data and purge choices. This is better than a typical prototype."),
              P("The weakness is that setup is still a dependency orchestration script rather than a capability-led installer. Backend selection can choose Rust even when the runtime binary is absent, and the user then receives a hard analysis failure. A fresh installation needs a single preflight that proves the selected capture/replay path, AI endpoint, optional graph service, and sensor role before the UI says Ready."),
              P("Capture, behavioural sensing, and detection", "H2x"),
              P("The detection architecture is one of WatchTower's strongest technical areas: detector manifests declare input kinds, finding types, evidence, calibration state, and correlation groups; the database supports policy suppression and risk rollups; and the plugin loader reports health and calibration metadata."),
              P("The product promise is weakened by defaults. Beaconing, reconnaissance/lateral movement, and exfiltration detectors declare enabled = False in the shipped detector modules. That may be a deliberate safety or false-positive policy, but it means the default product does not deliver the full behavioural sensing story unless the operator discovers and enables the capabilities. This should be represented as coverage, not hidden as a plugin detail."),
              P("Identity, enrichment, flows, and graph", "H2x"),
              P("Identity has a good provenance model and a separate reindexing workflow. Flow data contains protocol and application metadata, and the graph service can materialize relationships, neighborhoods, shortest paths, and timelines. The main weakness is scope consistency: flow retrieval has grown richer filters, but entity retrieval and some graph paths still have narrower filtering contracts. That creates a risk that a well-scoped flow answer is paired with a broader identity or graph answer."),
              P("Forensics, cases, and Sigma", "H2x"),
              P("The offline forensic path is ambitious and technically mature in shape: analysis identities, case records, evidence envelopes, packet indexes, streams, artifacts, timelines, and partial states are all represented. Sigma loading is safer than a blind rule import because unsupported categories, fields, modifiers, and malformed rules are rejected and retained with reasons."),
              P("The practical risk is compatibility and completeness. Sigma intentionally supports a subset of upstream Sigma, but the user-facing experience needs to say what telemetry is covered and what was not evaluated. More importantly, network-identity Sigma records are loaded via get_all_entities(source=source), while the flow path receives interface, session, time, node, and target filters. That is a concrete wrong-scope risk for identity hunts. (core/forensics/sigma_engine.py:278-284; core/storage/database.py:1466)"),
              P("Mesh and fleet", "H2x"),
              P("Mesh includes enrollment, certificate rotation, revocation, encrypted spooling, gRPC transport, commands, case transfer validation, and a fleet view. The security posture is stronger than a simple remote-agent prototype. The gap is operational: hybrid capture adds a second command and state machine, and the current hybrid helper supplies idempotency_key arguments that older test doubles and likely older controller integrations do not accept. This is evidence of a cross-layer contract that needs versioning and capability negotiation. (core/mesh/hybrid.py:44-82)"),
              P("AI analyst", "H2x"),
              P("The AI work has materially improved the product foundation: persistent conversation history, origin message IDs, client request IDs, active-run conflict handling, approval-bound resumes, scope-aware tools, cancellation, provider tests, structured answers, and CLI/UI lifecycle parity are present. It is now a credible subsystem rather than a decorative chat page."),
              P("It is not yet a ChatGPT-level analyst experience. The event stream is not durable across process restart, the UI lacks complete edit/branch/retry/copy and jump-to-latest behavior, and research outcome states are not consistently modeled as first-class user results. Model qualification needs real Ollama probes, not only fake-provider tests."),
              PageBreak()]

    story += [P("4. UI and UX evaluation", "H1x"),
              callout("Web UI/UX score: 6.0 / 10", PALE_AMBER),
              P("The web UI has a sensible high-level workspace grouping: Overview, Monitor, Alerts, Investigate, and Settings. Status labels and next-action vocabulary are a good foundation, and the AI route now shows progress and preserves the narrative answer instead of allowing an investigation card to replace it."),
              P("The central UX problem is information architecture. The sidebar still exposes Simple, Standard, and Analyst experience modes, with the note that advanced controls appear only in Analyst mode. That creates a hidden-capability model and contradicts the intended single conversational interface. The user has to understand a product mode before they can know whether a feature exists."),
              P("The large route modules are evidence of density: ai.tsx is approximately 1,023 lines, settings.tsx approximately 1,011, and forensics.tsx approximately 954. These routes combine setup, scope selection, execution, status, evidence, and recovery. The result is likely to be functionally capable but cognitively expensive, especially when an operation is degraded or awaiting an approval."),
              P("The UI needs a consistent operation shell: a visible scope chip, one readiness panel, one operation status model, one evidence completeness model, and one recovery panel. Settings should configure providers and services; the main task surfaces should not make users manage infrastructure while investigating."),
              P("Concrete UX improvements needed:"),
              P("• Replace experience-mode hiding with progressive disclosure inside the same task surface.\n• Make the active scope persistent and visually unmissable.\n• Keep narrative answers primary; render evidence cards as expandable supplements.\n• Add copy, retry, edit-and-branch, conversation titles, jump-to-latest, and resilient reconnect states.\n• Surface disabled detectors and unavailable graph/research capabilities as coverage statements.\n• Use the same plain-language error and next-action vocabulary on every route."),
              P("Evidence: ui/src/components/AppSidebar.tsx:25-66, 87-92, 145-171, 259; ui/src/routes/ai.tsx; ui/src/routes/settings.tsx; ui/src/routes/forensics.tsx."),
              PageBreak()]

    story += [P("5. CLI and UX evaluation", "H1x"),
              callout("CLI/UX score: 6.1 / 10", PALE_AMBER),
              P("The CLI is broad and more helpful than a typical internal tool. It has doctor, auth, daemon, capture, analyze, hunt, scoring, identity, enrich, graph, AI provider and conversation commands, plus a shell with usage text. Several commands emit structured JSON, and the newer UX helpers correctly avoid claiming capture success after failures."),
              P("The core issue is command sprawl and legacy overlap. core/cli/shell.py is approximately 1,088 lines and explicitly says legacy commands remain while users migrate to task-oriented names. The same concept can appear as ui/open, mesh/sensors, dive/investigate, plugins/extensions, chat/ai, and multiple nested command syntaxes. That makes the CLI powerful for maintainers but harder to learn and automate consistently."),
              P("The CLI also exposes lower-level concepts earlier than necessary: backend selection, source type, graph, calibration, providers, research sources, and mesh commands. A task-oriented top layer should offer a small set of stable commands and make advanced operations discoverable through subcommands, not require the operator to know the architecture."),
              P("Concrete CLI improvements needed:"),
              P("• Establish one canonical command taxonomy and keep aliases as documented compatibility shims.\n• Make every long-running operation return the same operation_id, state, next_actions, and resume/cancel behavior.\n• Guarantee stable JSON schemas for automation, separate from human Rich output.\n• Add explicit --scope or --capture selectors to every evidence-bearing command.\n• Return capability and completeness metadata with hunt, graph, identity, and AI results.\n• Make doctor a capability report, not just a collection of dependency checks."),
              P("Evidence: core/cli/shell.py:31-57, 142-277, 338-426, 463-521, 810-874; core/cli/modules/ai.py; core/ux/contracts.py; tests/platform/test_cli_ux.py."),
              PageBreak()]

    story += [P("6. Grouped systemic gaps", "H1x"),
              P("These are the general-case problems behind multiple feature-specific symptoms. Solving the general case will improve several paths at once."),
              table([
                  ("ID / severity", "Affected paths", "Concrete evidence", "General solution"),
                  ("G1 — P0\nRuntime capability truth", "Native install, live capture, offline forensics, CLI", "backend_policy defaults to Rust by backend name; rust_sensor_available exists separately; ForensicsEngine raises when the binary is missing. Full suite shows Rust binary failures.", "Build a CapabilityRegistry that probes executable, driver, permissions, model, graph, and sensor role. Selection must use capability results and return a degraded fallback or actionable preflight before task start."),
                  ("G2 — P0\nCross-layer contract drift", "Mesh, hybrid capture, daemon, setup tests, UI/CLI", "hybrid.py passes idempotency_key into queue_command; full suite records TypeError in hybrid fakes. Capture tests expect a different DaemonManager seam. Windows setup test expects direct doctor invocation while implementation wraps it.", "Version and validate contracts at boundaries. Use typed operation envelopes, compatibility adapters, and contract tests generated from the same schema. Keep dependency injection seams explicit."),
                  ("G3 — P0\nScope and evidence completeness", "Sigma, identity, graph, AI, flows", "Sigma flows receive full scope but entities are loaded by source only. Database has separate query shapes for flows and entities. Large limits are not a universal completeness contract.", "Create one server-owned Scope object and require every evidence query to return effective_scope, completeness, truncation, unavailable_capabilities, and provenance. Reject or mark mismatched evidence."),
                  ("G4 — P1\nDefault coverage is hidden", "Behavioural sensing, plugins, Sigma, graph, research", "Beaconing, recon/lateral, and exfiltration detectors are enabled = False. Sigma supports a declared subset. Neo4j and external research are optional lanes.", "Expose a Coverage Matrix in UI/CLI: enabled, disabled by policy, unsupported telemetry, unavailable dependency, and last error. Tie findings and answers to that matrix."),
                  ("G5 — P1\nLong-running state is fragmented", "Capture, forensics, mesh, AI, CLI/UI", "AI has in-memory event replay and cancellation; forensic failures include partial/cancelled finalization cases; mesh has its own command states.", "Adopt one durable Operation lifecycle with monotonic events, checkpoints, cancellation semantics, restart recovery, idempotency, and a shared renderer for UI and CLI."),
                  ("G6 — P1\nInformation architecture hides capability", "Web UI, CLI, AI, settings", "AppSidebar has three experience modes and hides children in Simple mode; AI, settings, and forensics routes are each roughly 950–1,023 lines; shell is 1,088 lines with legacy aliases.", "Move from mode-based feature hiding to task-based progressive disclosure. Separate configure, observe, investigate, and export. Keep advanced detail available in context."),
                  ("G7 — P1\nTrust/calibration is not operator-simple", "Detection, plugins, AI answers", "Manifest/calibration metadata is strong, but the operator must understand calibration levels, attestations, legacy/V2 modes, and evidence references.", "Translate trust metadata into human language: observed, supported, calibrated, corroborated, unknown. Never display a score without scope, evidence count, and coverage limitations."),
                  ("G8 — P2\nRelease confidence is uneven", "All paths", "Full suite: 511 passed, 11 skipped, 15 failed. Failures include Rust artifact absence, hardware-flush terminal-state behavior, hybrid API drift, and a setup contract mismatch.", "Create a release prerequisite gate: build artifacts, smoke fixtures, contract tests, native/container setup, and a clean full-suite run. Keep research/experimental paths explicitly separated from release-critical paths."),
              ], [30*mm, 32*mm, 58*mm, 54*mm]),
              PageBreak()]

    story += [P("7. Strengths worth preserving", "H1x"),
              P("The product should not be simplified by deleting its differentiators. The right move is to put a calmer product layer over them."),
              P("• Evidence-first architecture: findings, citations, provenance, case identity, and encrypted evidence envelopes give WatchTower a trustworthy substrate."),
              P("• Local-first posture: capture data and AI context remain local by default, and hosted inference is an explicit provider path."),
              P("• Calibration discipline: detector manifests, corpus levels, attestation references, and policy constraints are more mature than the UI currently communicates."),
              P("• Broad protocol and forensic ambition: packet, flow, stream, identity, artifact, timeline, and graph views can support a real analyst workflow."),
              P("• Safety foundations: mesh enrollment, certificate handling, idempotent command storage, approval-gated AI actions, and research redaction are appropriate design choices."),
              P("• Recovery vocabulary: the new UX contracts and AI cancellation work show the right direction—plain-language states plus next actions rather than raw exception text."),
              P("The product manager's recommendation is therefore to harden and compose the existing capabilities rather than start another feature expansion cycle."),
              P("8. Recommended roadmap", "H1x"),
              table([
                  ("Order", "Release objective", "Exit condition"),
                  ("P0", "Runtime truth and operation contracts", "Clean capability preflight for native, container/controller, offline, Ollama, graph, and Sigma. Versioned operation envelope shared by API, UI, CLI, and mesh."),
                  ("P0", "Scope/evidence contract", "Every evidence query returns effective scope and completeness. Sigma identity hunts and graph relationships cannot silently exceed the selected scope."),
                  ("P0", "Default behavioural coverage", "Product clearly declares which detectors are enabled and why. High-value detectors are either safely enabled or surfaced as an explicit coverage decision."),
                  ("P1", "One operation lifecycle", "Durable events, reconnect replay, restart interruption, cancellation, checkpoints, idempotency, and shared status/next-action rendering."),
                  ("P1", "Task-first UI and CLI", "No mode is required to discover core capability. Configure services separately. A beginner can start capture or ask the analyst without learning mesh, backend, or calibration terminology."),
                  ("P1", "AI analyst completion", "Real qualified Ollama model passes the fixed persona suite; research failure and incomplete tasks are explicit; edit/branch/retry/copy and accessibility flows are complete."),
                  ("P2", "Release certification", "Native and container install/upgrade/uninstall fixtures pass; Rust artifact is present or fallback is intentional; full suite is clean; measured latency and coverage are published."),
              ], [16*mm, 65*mm, 93*mm]),
              PageBreak()]

    story += [P("9. Final product decision", "H1x"),
              callout("Recommendation: advance WatchTower as a high-potential security platform, but do not position it as a low-complexity production analyst product until the P0 seams are fixed.", PALE_RED),
              P("Current aggregate score: 6.5 / 10."),
              P("The score is high enough to justify continued investment and targeted pilot use by technically capable operators. It is not high enough for a broad user promise of advanced security without too much complexity, because the complexity currently appears in the exact places users need confidence: setup, capability readiness, scope, degraded behavior, and recovery."),
              P("The fastest path to 8+ is not another detector or another page. It is a common capability and operation layer that makes every feature answer four questions consistently: What is available? What scope was used? How complete is the result? What should the operator do next?"),
              P("The fastest path from 8 to 9 is the UX layer: one calm task model across the browser and shell, with progressive disclosure and high-quality recovery. The product already contains enough technical depth to reward that investment."),
              P("Appendix A — Evidence register", "H1x"),
              table([
                  ("Evidence", "Use in assessment"),
                  ("README.md:5-21", "Release positioning, scope of product capabilities, local-first AI, sensor mesh, forensics, identity, and scoring."),
                  ("scripts/setup.ps1; scripts/setup.sh; docs/containers.md", "Native prerequisites, Rust/Npcap/UI build, container/controller model, optional Neo4j, diagnostics, and uninstall paths."),
                  ("core/backend_policy.py; core/packet_engine/rust_capture.py; core/forensics/engine.py:645-989", "Backend selection and hard Rust-missing failure behavior."),
                  ("core/forensics/plugins/detectors/*.py; core/forensics/plugin_loader.py", "Detector defaults, plugin health, manifests, calibration metadata, and disabled behavioral capabilities."),
                  ("core/forensics/sigma_engine.py:21-114, 256-337; core/storage/database.py:1466", "Sigma compatibility subset, rejection model, and incomplete entity scope contract."),
                  ("core/mesh/hybrid.py:44-82; core/mesh/service.py", "Hybrid command lifecycle, idempotency boundary, enrollment, spool, and fleet operations."),
                  ("core/ai/orchestrator.py; core/ai/providers.py; core/ai/research.py; ui/src/routes/ai.tsx; core/cli/modules/ai.py", "AI conversation, provider, research, approval, cancellation, structured answer, and UI/CLI behavior."),
                  ("ui/src/components/AppSidebar.tsx; ui/src/routes/settings.tsx; ui/src/routes/forensics.tsx; core/cli/shell.py", "Information architecture, experience modes, dense route surfaces, and command taxonomy."),
                  ("Full repository test run on 19 September 2026", "511 passed, 11 skipped, 15 failed. Failures are concrete runtime/contract/release signals, not treated as mere lack of verification."),
              ], [55*mm, 119*mm]),
              P("Appendix B — Scoring rubric", "H2x"),
              P("0–2: nonfunctional or unsafe. 3–4: prototype with major blockers. 5–6: useful but fragile or complex. 7–8: dependable for informed operators with bounded caveats. 9: production-quality, clear, recoverable, and consistent. 10: exceptional maturity and ease across paths."),
              P("Report generated from repository evidence; no application source code was changed to produce this assessment.", "Smallx")]

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUT)


if __name__ == "__main__":
    build_report()
