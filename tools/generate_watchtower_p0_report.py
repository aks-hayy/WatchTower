from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "WatchTower_Product_Evaluation_2026-09-20-p0.pdf"

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
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=NAVY, alignment=TA_CENTER, spaceAfter=10))
styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontName="Helvetica", fontSize=11, leading=16, textColor=MUTED, alignment=TA_CENTER, spaceAfter=7))
styles.add(ParagraphStyle(name="H1x", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceBefore=3, spaceAfter=8))
styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=BLUE, spaceBefore=7, spaceAfter=4))
styles.add(ParagraphStyle(name="Bodyx", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.7, leading=12, textColor=TEXT, spaceAfter=5))
styles.add(ParagraphStyle(name="Smallx", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=MUTED, spaceAfter=3))
styles.add(ParagraphStyle(name="Tablex", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=TEXT))
styles.add(ParagraphStyle(name="TableHeadx", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=colors.white))
styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=NAVY, leftIndent=7, rightIndent=7, spaceBefore=4, spaceAfter=4))


def p(text, style="Bodyx"):
    return Paragraph(escape(text).replace("\n", "<br/>"), styles[style])


def callout(text, background=PALE_BLUE, border=BLUE):
    table = Table([[p(text, "Callout")]], colWidths=[174 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def table(rows, widths, row_backgrounds=None):
    converted = []
    for index, row in enumerate(rows):
        style = "TableHeadx" if index == 0 else "Tablex"
        converted.append([Paragraph(escape(str(cell)), styles[style]) for cell in row])
    result = Table(converted, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
    ]
    for row, color in (row_backgrounds or {}).items():
        commands.append(("BACKGROUND", (0, row), (-1, row), color))
    result.setStyle(TableStyle(commands))
    return result


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(GRID)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9 * mm, "WatchTower post-P0 product evaluation | 20 September 2026")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_report():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(OUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=17 * mm, bottomMargin=19 * mm, title="WatchTower Post-P0 Product Evaluation", author="Codex")
    story = []

    story += [
        Spacer(1, 27 * mm),
        p("WATCHTOWER", "CoverTitle"),
        p("Post-P0 product evaluation", "CoverSub"),
        p("Runtime truth, scope correctness, operation contracts, and replay reliability", "CoverSub"),
        Spacer(1, 13 * mm),
        callout("Aggregate product score: 6.8 / 10\n\nMeasured improvement from 6.5 / 10. This increase is limited to changes supported by fresh regression evidence; the remaining release-contract failures are retained below.", PALE_BLUE),
        Spacer(1, 10 * mm),
        p("Assessment date: 20 September 2026", "CoverSub"),
        p("Repository: C:/Users/aksha/Desktop/Projects/WT1", "Smallx"),
        PageBreak(),
    ]

    story += [
        p("1. Executive result", "H1x"),
        p("The P0 seam work improved WatchTower in the places that previously made the product feel unreliable: capability selection now knows when the Rust sensor is absent, offline replay falls back to Python when it is safe to do so, Sigma identity hunts apply the same scope dimensions as flow hunts, graph responses report scope and completeness, and mesh commands expose a shared operation envelope while remaining compatible with older controller adapters."),
        callout("The score improved because real user journeys now degrade usefully. A missing optional Rust accelerator no longer blocks ordinary offline analysis. This is not a claim that the release gate is clean: four tests still fail and are listed with their causes.", PALE_AMBER, AMBER),
        p("The implementation preserved existing captures, configuration, and API compatibility. No detector calibration policy, scoring profile, or manifest was changed to make the result look better."),
        p("Score interpretation: this is a weighted product score, not a test pass rate. A score increase requires both a concrete product improvement and fresh evidence that the affected path behaves better."),
        PageBreak(),
    ]

    story += [
        p("2. Before and after evidence", "H1x"),
        table([
            ("Measure", "Before P0", "After P0", "Interpretation"),
            ("Full Python suite", "511 passed / 15 failed / 11 skipped", "531 passed / 4 failed / 11 skipped", "Net improvement: +20 passing, -11 failing. Remaining failures are contract expectations, not the prior offline Rust crash group."),
            ("Focused P0 suite", "Not present", "69 passed", "Capability, scope, Sigma, graph, mesh, AI, UX contract, and detection regression paths pass."),
            ("UI typecheck", "Passed", "Passed", "No TypeScript regression from additive capability and operation types."),
            ("UI production build", "Passed", "Passed", "Client, SSR, and Nitro builds complete successfully."),
            ("Offline PCAP fallback", "Rust missing caused analysis failure", "Python fallback completes affected PCAP suites", "Fragmented FTP, carving, forensic rebuild, and streaming tests pass under the available runtime."),
        ], [37 * mm, 39 * mm, 39 * mm, 59 * mm], {1: PALE_BLUE, 2: PALE_BLUE, 3: PALE_BLUE, 4: PALE_BLUE, 5: PALE_BLUE}),
        Spacer(1, 7),
        p("The full suite was run three times during implementation. The final run took 345.24 seconds and ended with 531 passed, 11 skipped, and 4 failed. The focused P0 run took 17.13 seconds and ended with 69 passed and 3 warnings."),
        p("Warnings were dependency deprecations and pytest cache permission warnings; they did not change the pass/fail result."),
        PageBreak(),
    ]

    story += [
        p("3. Feature-path scorecard", "H1x"),
        p("Scores below compare the original management evaluation with the post-P0 evaluation. Paths without a measured implementation change remain unchanged rather than receiving speculative credit."),
        table([
            ("Feature path", "Before", "After", "Evidence-based reason"),
            ("Native installation and lifecycle", "5.8", "6.4", "Runtime capability registry and actionable Rust/Npcap/provider/graph/mesh states."),
            ("Container/controller deployment", "6.4", "6.7", "Shared capability and operation contracts make degraded controller paths more explicit."),
            ("Offline PCAP and case workflow", "6.8", "7.4", "Replay execution now uses runtime capability facts and Python fallback; real PCAP suites recovered."),
            ("Live capture and source management", "5.7", "6.3", "Configured engine path falls back from missing Rust; CLI lifecycle seam is injectable."),
            ("Behavioural sensing", "6.1", "6.1", "No detector-default or calibration work was performed in this P0."),
            ("Detection, risk, and alert triage", "7.0", "7.0", "No scoring-policy change; preserved to avoid fake improvement."),
            ("Flows and conversations", "6.8", "6.8", "No broad flow redesign; scope contract is additive."),
            ("Identity and enrichment", "7.2", "7.6", "Entity retrieval and Sigma identity hunts now share session/interface/node/time/target scope."),
            ("Forensics, evidence, and cases", "6.8", "7.3", "Missing Rust no longer blocks the tested offline paths when Python is supported."),
            ("Topology and evidence graph", "6.2", "6.7", "Graph responses include effective scope, truncation, freshness limitations, and bounded filters."),
            ("Sigma rules and hunts", "6.7", "7.1", "Wrong-scope identity regression is fixed and evidence record IDs are populated."),
            ("Mesh and sensor fleet", "6.3", "6.6", "Hybrid controller adapter accepts legacy signatures; queued commands carry operation envelopes."),
            ("Plugins and calibration", "6.8", "6.8", "No calibration-policy changes."),
            ("AI analyst", "7.1", "7.1", "No AI orchestration redesign in this P0; existing AI suite remains green."),
            ("Web UI and UX", "6.0", "6.0", "Only additive types; no visual redesign was claimed."),
            ("CLI and UX", "6.1", "6.3", "Lifecycle seam is explicit and replay/capture paths report capability-led fallback."),
        ], [41 * mm, 15 * mm, 15 * mm, 103 * mm], {8: PALE_BLUE, 9: PALE_BLUE, 10: PALE_BLUE, 11: PALE_BLUE, 12: PALE_BLUE}),
        Spacer(1, 6),
        callout("Weighted aggregate: 6.8 / 10. The gain is concentrated in runtime truth, offline analysis, scope correctness, Sigma, graph, mesh, and CLI reliability. UI/UX stays at 6.0 because no visual overhaul was implemented in this P0.", PALE_BLUE),
        PageBreak(),
    ]

    story += [
        p("4. What changed technically", "H1x"),
        p("Runtime capability truth", "H2x"),
        p("CapabilityRegistry now reports rust_sensor, npcap, ollama, graph, and mesh states with reasons and next actions. Health and API capability responses expose the registry. PacketEngineConfig injects those facts into backend selection, so the configured engine uses Python when Rust is unavailable and supported. Offline replay and scoring rebuild paths now inject the same runtime facts."),
        p("Effective scope and evidence", "H2x"),
        p("EffectiveScope normalizes source, interface, session, node, time, and target IP filters. Entity queries apply the filters before counts and endpoint selection. Sigma identity hunts now use the scoped entity query and populate an evidence record ID from the entity IP when no database ID exists. Graph neighborhood, path, and timeline queries pass scope filters and return effective_scope, completeness, and limitations."),
        p("Operation and compatibility contracts", "H2x"),
        p("OperationEnvelope provides stable operation_id, state, summary, error, next_actions, effective_scope, and completeness fields. Mesh queue responses include the envelope additively. Hybrid capture inspects the controller boundary before sending idempotency_key, preserving idempotency with current controllers while supporting legacy adapters. DaemonManager is an explicit import seam for the CLI entry point."),
        p("UI and CLI contract surface", "H2x"),
        p("The UI now has additive RuntimeCapability and OperationEnvelope types, and the shared Python UX operation contract carries effective scope and completeness. No claim is made that the visual AI or navigation overhaul is complete."),
        PageBreak(),
    ]

    story += [
        p("5. Remaining failures and actual gaps", "H1x"),
        p("The four final failures are not hidden. They are release work still required:") ,
        table([
            ("Failure", "Root cause", "Product implication", "Next action"),
            ("PacketEngineConfig default expects Rust", "Legacy test expects Rust even though the Rust binary is absent and the new runtime contract selects Python.", "The test contract is stale relative to the safety behavior; the machine is truthfully degraded.", "Update the fixture to inject Rust availability when testing Rust-first policy, and separately assert Python fallback when unavailable."),
            ("CLI omitted backend expects Rust", "Same stale Rust-first expectation; the actual CLI selected Python through PacketEngineConfig.", "CLI now avoids a guaranteed missing-binary failure, but the test still encodes the old default.", "Split policy-selection and runtime-execution tests; assert the user-visible fallback and next action."),
            ("Scoring rebuild expects Rust", "The test double records the historical default, while the real replay path correctly selects Python on this host.", "Offline rebuild is more reliable, but the contract test needs capability injection.", "Make the fixture declare a Rust-capable runtime or assert Python fallback for the unavailable fixture."),
            ("PowerShell setup doctor string mismatch", "The setup implementation invokes doctor through an argument-array wrapper; the release test searches for a literal older invocation.", "No runtime failure was demonstrated, but the setup contract is not aligned with its test.", "Replace the brittle string assertion with behavior-level script checks, or make the invocation form canonical."),
        ], [39 * mm, 48 * mm, 42 * mm, 45 * mm], {1: PALE_AMBER, 2: PALE_AMBER, 3: PALE_AMBER, 4: PALE_AMBER}),
        Spacer(1, 7),
        p("Remaining product gaps not addressed by P0: visual AI conversation controls, durable event replay across restart, complete research result taxonomy, default behavioral detector coverage, and a single task-based UI information architecture. Those remain the highest-value P1 work.", "Bodyx"),
        callout("Release status: improved but not release-clean. The P0 runtime and scope seams are passing their focused suite, while the full suite still has four contract failures that must be reconciled before declaring a clean release.", PALE_RED, RED),
        PageBreak(),
    ]

    story += [
        p("6. Management recommendation", "H1x"),
        p("Accept the P0 implementation as a genuine product improvement, but do not close the release gate yet. The core user journey is more resilient: a missing Rust accelerator becomes an explicit degraded capability instead of an unexplained analysis failure, identity and flow investigations no longer diverge silently by scope, and mesh operations have a shared lifecycle shape."),
        p("Next work should be sequenced as follows:") ,
        p("1. Reconcile the four remaining release-contract tests with the capability-led behavior and verify the setup script by execution rather than text matching."),
        p("2. Finish the durable AI operation lifecycle: restart recovery, SSE replay, cancellation acknowledgment, edit-and-branch, retry, and CLI/UI parity."),
        p("3. Replace hidden UI modes with progressive disclosure and a persistent scope/completeness shell."),
        p("4. Publish detector and telemetry coverage as a first-class product surface, especially for disabled behavioral detectors and Sigma support boundaries."),
        p("5. Re-evaluate again only after those changes with the same full-suite and persona-based UX evidence."),
        Spacer(1, 7),
        p("Verification commands used:", "H2x"),
        p(".venv\\Scripts\\python.exe -m pytest -q\n.venv\\Scripts\\python.exe -m pytest -q tests/ai tests/graph tests/platform/test_capability_registry.py tests/platform/test_scope_contract.py tests/platform/test_operation_envelope.py tests/platform/test_hybrid_capture.py tests/platform/test_ux_contracts.py tests/detection/test_sigma_engine.py\nnpm run typecheck\nnpm run build"),
        p("Final measured result: 531 passed, 11 skipped, 4 failed. No real captures, credentials, or calibration evidence were committed by this report generation.", "Smallx"),
    ]

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUT)


if __name__ == "__main__":
    build_report()
