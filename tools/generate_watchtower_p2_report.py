from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "WatchTower_Product_Evaluation_2026-09-20-p2.pdf"

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
styles.add(ParagraphStyle(name="CoverTitleP2", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25, leading=30, textColor=NAVY, alignment=TA_CENTER, spaceAfter=10))
styles.add(ParagraphStyle(name="CoverSubP2", parent=styles["Normal"], fontName="Helvetica", fontSize=11, leading=16, textColor=MUTED, alignment=TA_CENTER, spaceAfter=7))
styles.add(ParagraphStyle(name="H1P2", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceBefore=3, spaceAfter=8))
styles.add(ParagraphStyle(name="H2P2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=BLUE, spaceBefore=7, spaceAfter=4))
styles.add(ParagraphStyle(name="BodyP2", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.7, leading=12, textColor=TEXT, spaceAfter=5))
styles.add(ParagraphStyle(name="SmallP2", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=MUTED, spaceAfter=3))
styles.add(ParagraphStyle(name="TableP2", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=TEXT))
styles.add(ParagraphStyle(name="TableHeadP2", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=colors.white))
styles.add(ParagraphStyle(name="CalloutP2", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=NAVY, leftIndent=7, rightIndent=7, spaceBefore=4, spaceAfter=4))


def p(text, style="BodyP2"):
    return Paragraph(escape(text).replace("\n", "<br/>"), styles[style])


def callout(text, background=PALE_BLUE, border=BLUE):
    table = Table([[p(text, "CalloutP2")]], colWidths=[174 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background), ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def table(rows, widths, row_backgrounds=None):
    converted = []
    for index, row in enumerate(rows):
        style = "TableHeadP2" if index == 0 else "TableP2"
        converted.append([Paragraph(escape(str(cell)), styles[style]) for cell in row])
    result = Table(converted, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
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
    canvas.drawString(18 * mm, 9 * mm, "WatchTower P1/P2 product evaluation | 20 September 2026")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_report():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(OUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=17 * mm, bottomMargin=19 * mm, title="WatchTower P1 P2 Product Evaluation", author="Codex")
    story = [
        Spacer(1, 27 * mm), p("WATCHTOWER", "CoverTitleP2"), p("P1/P2 reliability re-evaluation", "CoverSubP2"),
        p("Capability truth, durable analyst lifecycle, and product UX seams", "CoverSubP2"), Spacer(1, 13 * mm),
        callout("Aggregate product score: 7.0 / 10\n\nMeasured improvement from 6.8 / 10 after P0. The improvement is limited to implemented seams with fresh regression evidence; the report does not claim the overall product is a 9/10 release.", PALE_BLUE),
        Spacer(1, 10 * mm), p("Assessment date: 20 September 2026", "CoverSubP2"), p("Repository: C:/Users/aksha/Desktop/Projects/WT1", "SmallP2"), PageBreak(),
        p("1. Executive result", "H1P2"),
        p("The remaining P1/P2 seams are implemented and measured. WatchTower now exposes one coverage vocabulary for plugins and runtime dependencies, persists AI lifecycle events for reconnects, marks abandoned analyst runs interrupted on startup instead of replaying them, keeps read-only plugin diagnostics usable on a read-only database, and leaves core navigation discoverable in every experience mode."),
        callout("P1/P2 plan status: complete. Release evidence: full Python suite passed, selected release gates passed, UI typecheck/build passed, and CLI coverage smoke test returned structured capability data.", PALE_BLUE),
        p("The score remains below 9 because several genuine product limitations remain: the current machine has no Rust sensor binary, Ollama still requires an explicit provider test, three behavioral detectors are disabled by policy, most detector trust is uncalibrated, graph and mesh are unavailable in the tested runtime, and the AI surface still lacks the complete ChatGPT-style edit/branch/retry interaction set."),
        PageBreak(),
        p("2. Measured release evidence", "H1P2"),
        table([
            ("Gate or check", "Result", "Evidence"),
            ("Full Python suite", "PASS", "539 passed, 11 skipped, 3 warnings in 351.83 seconds."),
            ("Selected release gates", "PASS", "release, ai, capture, and platform gates all passed in the persisted gate runner."),
            ("UI typecheck", "PASS", "tsc --noEmit completed successfully."),
            ("UI production build", "PASS", "Client, SSR, and Nitro builds completed successfully; only existing bundler warnings were emitted."),
            ("CLI coverage smoke", "PASS", "tower plugins coverage returned coverage.v1 JSON with ready, disabled_by_policy, and dependency states."),
            ("Durable AI events", "PASS", "Events were read by a new orchestrator instance; after=1 replay returned only the subsequent event."),
            ("Restart recovery", "PASS", "Queued/running/approval runs are marked INTERRUPTED and require explicit retry."),
        ], [42 * mm, 24 * mm, 108 * mm], {1: PALE_BLUE, 2: PALE_BLUE, 3: PALE_BLUE, 4: PALE_BLUE, 5: PALE_BLUE, 6: PALE_BLUE, 7: PALE_BLUE}),
        Spacer(1, 7), p("Warnings were dependency deprecations and pytest cache permission warnings. They did not change the pass/fail result.", "SmallP2"), PageBreak(),
        p("3. Feature-path scorecard", "H1P2"),
        p("Scores are managerial product scores on a 0-10 scale. They are not test percentages. Each P1/P2 increase is tied to a changed contract and a fresh passing check; unchanged or still-limited capabilities remain below release quality."),
        table([
            ("Feature path", "Score", "Assessment"),
            ("Native installation and lifecycle", "6.7", "Diagnostics are actionable and read-only plugin checks no longer require writable auth storage."),
            ("Container/controller deployment", "6.8", "Capability and operation contracts are shared; container-specific live service qualification remains limited."),
            ("Offline PCAP and case workflow", "7.4", "Runtime-aware replay and Python fallback are covered by passing capture/forensics suites."),
            ("Live capture and source management", "6.4", "Backend fallback is safe; native Rust acceleration is absent on the tested machine."),
            ("Behavioural sensing", "6.3", "Coverage is now visible, but beaconing, exfiltration, and recon/lateral detectors remain disabled by policy."),
            ("Detection, risk, and alert triage", "7.1", "Calibration limits are surfaced; broad detector trust is still bounded."),
            ("Flows and conversations", "6.9", "Scope contracts are stronger, but the overall analyst workflow is still dense."),
            ("Identity and enrichment", "7.6", "Identity and Sigma evidence use the same scoped dimensions and avoid wrong-subject claims."),
            ("Forensics, evidence, and cases", "7.3", "Offline resilience and operation completeness improved without changing evidence policy."),
            ("Topology and evidence graph", "6.8", "Effective scope and limitations are explicit; graph dependency is unavailable in this runtime."),
            ("Sigma rules and hunts", "7.2", "Rule/coverage states and scoped identity hunts are clearer; telemetry support is still bounded."),
            ("Mesh and sensor fleet", "6.6", "Operation envelopes and adapter compatibility are improved; mesh readiness remains dependency-bound."),
            ("Plugins and calibration", "7.0", "Coverage matrix is actionable; most detectors remain uncalibrated, so trust is intentionally limited."),
            ("AI analyst", "7.6", "Events and restart recovery are durable; full conversational branch/edit/retry UX is still unfinished."),
            ("Web UI and UX", "6.5", "Core destinations are discoverable and coverage status is legible; the wider UI remains information-dense."),
            ("CLI and UX", "6.8", "Coverage diagnostics are structured and auth-independent; full UI/CLI answer parity remains a follow-up."),
        ], [48 * mm, 18 * mm, 108 * mm], {1: PALE_BLUE, 2: PALE_BLUE, 3: PALE_BLUE, 4: PALE_BLUE, 5: PALE_BLUE, 6: PALE_BLUE, 7: PALE_BLUE, 8: PALE_BLUE, 9: PALE_BLUE, 10: PALE_BLUE, 11: PALE_BLUE, 12: PALE_BLUE, 13: PALE_BLUE, 14: PALE_BLUE, 15: PALE_BLUE, 16: PALE_BLUE}),
        Spacer(1, 6), callout("Weighted aggregate: 7.0 / 10. The largest gains are in AI run reliability, capability transparency, plugin UX, and read-only CLI diagnostics. The score is held down by actual runtime/dependency gaps and unfinished conversational UX, not by missing test execution.", PALE_BLUE), PageBreak(),
        p("4. P1/P2 implementation summary", "H1P2"),
        p("Coverage matrix", "H2P2"), p("core/operations/coverage.py defines ready, disabled_by_policy, unsupported_telemetry, unavailable_dependency, and invalid_plugin states with reasons, next actions, supported telemetry, and trust limitations. API endpoints /api/v1/plugins/coverage and /api/v2/plugins/coverage, the web plugin surface, the interactive shell, and tower plugins coverage consume the same contract."),
        p("Durable AI lifecycle", "H2P2"), p("ai_run_events is an additive database table with per-run monotonic sequences. The orchestrator persists redacted lifecycle events, replays from a cursor, bounds the returned window, and marks abandoned QUEUED, RUNNING, and AWAITING_APPROVAL runs INTERRUPTED at startup. Existing test doubles remain compatible through fallback memory behavior."),
        p("Progressive disclosure", "H2P2"), p("Experience mode no longer controls whether core destinations are visible. The setting now changes detail density while primary workspaces, extensions, and Analyst remain discoverable."),
        p("Release contract", "H2P2"), p("Rust-first tests now inject a Rust-capable fixture when they are testing the Rust branch, while runtime-unavailable paths assert Python fallback. The setup test accepts the actual safe argument-array wrapper. Read-only plugin commands bypass database-backed auth setup so diagnostics work on read-only storage."),
        PageBreak(),
        p("5. Remaining actual product gaps", "H1P2"),
        table([
            ("Gap family", "Observed state", "Why it matters"),
            ("Runtime accelerators", "Rust sensor is unavailable on the tested host; Python fallback is used.", "Live capture performance and native feature depth are lower until the binary is built/configured."),
            ("AI provider readiness", "Ollama is configured but the capability probe intentionally requires an explicit provider test.", "The UI can say configured/unqualified, but it cannot honestly promise analyst readiness until chat/tool/synthesis probes pass."),
            ("Detector coverage", "Beaconing, exfiltration, and recon/lateral detectors are disabled by policy.", "Those threat paths do not produce findings; the matrix now makes the blind spot visible."),
            ("Detector trust", "Most detector profiles report UNCALIBRATED.", "A finding can be useful evidence but must not be shown as a validated probability or high-trust score."),
            ("External services", "Graph and mesh report unavailable in the current runtime.", "Topology and fleet features must degrade to flow/local evidence and show the limitation."),
            ("Conversation UX", "Durable lifecycle is improved, but edit-and-branch, retry-as-linked-attempt, full answer parity, and rich citation presentation are not all complete.", "The AI analyst is more reliable but not yet a 9/10 ChatGPT-like experience."),
        ], [38 * mm, 66 * mm, 70 * mm], {1: PALE_AMBER, 2: PALE_AMBER, 3: PALE_AMBER, 4: PALE_AMBER, 5: PALE_AMBER, 6: PALE_AMBER}),
        Spacer(1, 8), callout("These are product limitations, not placeholders for unexecuted UAT. They are derived from runtime capability output, plugin definitions/calibration state, and the implemented surface area.", PALE_AMBER, AMBER), PageBreak(),
        p("6. Recommendation", "H1P2"),
        p("Close the P1/P2 reliability milestone. The implementation has a clean measured regression baseline and the main “silent degradation” seams are now visible and durable. Do not market the aggregate as 9/10 yet."),
        p("The next milestone should focus on P3 analyst experience: qualify Ollama on the actual target model, complete ChatGPT-style conversation controls and answer rendering, add deterministic 20-scenario persona evaluation, and either enable/calibrate the disabled behavioral detectors or explicitly position them as optional coverage packages."),
        p("Verification commands:", "H2P2"),
        p(".venv\\Scripts\\python.exe -m pytest -q\n.venv\\Scripts\\python.exe tools/release.py gate run --no-resume --gate release --gate ai --gate capture --gate platform\nnpm run typecheck\nnpm run build\n.venv\\Scripts\\tower.exe plugins coverage"),
        p("No real captures, credentials, or calibration evidence were committed by this work. The report reflects the repository state and measured outputs on 20 September 2026.", "SmallP2"),
    ]
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUT)


if __name__ == "__main__":
    build_report()
