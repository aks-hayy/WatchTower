import { createFileRoute } from "@tanstack/react-router";
import {
  Award,
  CheckCircle2,
  Cpu,
  Loader2,
  Play,
  Plug,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import {
  fetchPluginCalibrationStatus,
  fetchPluginInventory,
  promotePluginCalibration,
  runPluginCalibration,
  verifyPluginCalibration,
} from "@/lib/api.functions";
import type {
  CalibrationReportSummary,
  PluginCalibrationStatus,
  PluginCalibrationTarget,
  PluginInventory,
  PluginRecord,
} from "@/types/watchtower";

export const Route = createFileRoute("/plugins")({
  head: () => ({ meta: [{ title: "Plugin Inventory - Watchtower" }] }),
  loader: async () => {
    const [inventory, calibration] = await Promise.all([
      fetchPluginInventory(),
      fetchPluginCalibrationStatus(),
    ]);
    return { inventory, calibration };
  },
  component: PluginsPage,
});

function PluginsPage() {
  const initial = Route.useLoaderData();
  const [inventory, setInventory] = useState<PluginInventory>(initial.inventory);
  const [calibration, setCalibration] = useState<PluginCalibrationStatus>(initial.calibration);
  const [backend, setBackend] = useState<"all" | "python" | "rust">("all");
  const [reviewer, setReviewer] = useState("local-analyst");
  const [reason, setReason] = useState("Reviewed latest WatchTower calibration report");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ kind: "ok" | "warn"; text: string } | null>(null);

  const targetsByDetector = useMemo(() => {
    const map = new Map<string, PluginCalibrationTarget[]>();
    calibration.targets.forEach((target) => {
      const items = map.get(target.detector_id) || [];
      items.push(target);
      map.set(target.detector_id, items);
    });
    return map;
  }, [calibration.targets]);

  const refresh = async (clearMessage = false) => {
    const [nextInventory, nextCalibration] = await Promise.all([
      fetchPluginInventory(),
      fetchPluginCalibrationStatus(),
    ]);
    setInventory(nextInventory);
    setCalibration(nextCalibration);
    if (clearMessage) setMessage(null);
  };

  const run = async (target: PluginCalibrationTarget) => {
    if (!target.corpus_available) {
      setMessage({
        kind: "warn",
        text: `${target.finding_type}: no calibration corpus is available yet. Add corpus cases for ${target.detector_id} before this finding type can be measured.`,
      });
      return;
    }
    const key = actionKey("run", target);
    setBusy(key);
    setMessage(null);
    try {
      const result = await runPluginCalibration({
        data: {
          detector_id: target.detector_id,
          finding_type: target.finding_type,
          backend,
        },
      });
      const report = result.reports[0];
      setMessage({
        kind: result.passed ? "ok" : "warn",
        text: result.passed
          ? `${target.finding_type}: calibration passed`
          : `${target.finding_type}: calibration needs work${report?.failures?.length ? ` / ${report.failures[0]}` : ""}`,
      });
      await refresh();
    } catch (error) {
      setMessage({
        kind: "warn",
        text: error instanceof Error ? error.message : "Calibration failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const promote = async (target: PluginCalibrationTarget) => {
    const report = target.latest_report;
    if (!report?.report_path) {
      setMessage({
        kind: "warn",
        text: `${target.finding_type}: run calibration first. Promotion needs a passing report.`,
      });
      return;
    }
    if (!report.passed) {
      setMessage({
        kind: "warn",
        text: `${target.finding_type}: latest report did not pass. Fix the detector or corpus and run calibration again.`,
      });
      return;
    }
    if (!reviewer.trim() || !reason.trim()) {
      setMessage({
        kind: "warn",
        text: "Reviewer and promotion reason are required before promotion.",
      });
      return;
    }
    if (levelRank(report.awarded_level) <= levelRank(target.calibration_level)) {
      setMessage({
        kind: "warn",
        text: `${target.finding_type}: latest report does not raise the current trust level.`,
      });
      return;
    }
    const key = actionKey("promote", target);
    setBusy(key);
    setMessage(null);
    try {
      await promotePluginCalibration({
        data: {
          report_path: report.report_path,
          reviewer: reviewer.trim(),
          reason: reason.trim(),
        },
      });
      setMessage({
        kind: "ok",
        text: `${target.finding_type}: promoted to ${report.awarded_level.replaceAll("_", " ")}`,
      });
      await refresh();
    } catch (error) {
      setMessage({
        kind: "warn",
        text: error instanceof Error ? error.message : "Promotion failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const verify = async () => {
    setBusy("verify");
    setMessage(null);
    try {
      const result = await verifyPluginCalibration();
      setMessage({
        kind: result.valid ? "ok" : "warn",
        text: result.valid
          ? "Calibration profiles verified"
          : "Calibration profile verification failed",
      });
      await refresh();
    } catch (error) {
      setMessage({
        kind: "warn",
        text: error instanceof Error ? error.message : "Verification failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const installed =
    inventory.parsers.length + inventory.detectors.length + inventory.hardware.length;
  const calibrated = calibration.targets.filter(
    (item) => item.calibration_level !== "UNCALIBRATED",
  ).length;
  const withReports = calibration.targets.filter((item) => item.report_count > 0).length;

  return (
    <div className="min-h-screen">
      <header className="flex items-center gap-4 border-b border-border bg-surface/60 px-6 py-3">
        <span className="section-label section-label-accent">PLG</span>
        <span className="mono text-[11px] uppercase text-foreground">/ Plugin Inventory</span>
        <span className="ml-auto mono text-[10px] text-muted-foreground">
          {installed} installed / {calibrated} trusted / {withReports} reported
        </span>
        <button
          onClick={() => refresh(true)}
          title="Refresh plugin inventory"
          className="grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:text-signal"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </header>
      <div className="space-y-5 p-4 md:p-6">
        {message && (
          <div
            className={`border px-4 py-3 mono text-[11px] ${
              message.kind === "ok"
                ? "border-signal/30 bg-signal/5 text-signal"
                : "border-severity-high/40 bg-severity-high/10 text-severity-high"
            }`}
          >
            {message.text}
          </div>
        )}

        <section className="panel">
          <div className="grid gap-4 p-4 lg:grid-cols-[160px_1fr_1fr_auto]">
            <label>
              <span className="section-label">BACKEND</span>
              <select
                value={backend}
                onChange={(event) => setBackend(event.target.value as "all" | "python" | "rust")}
                className="mt-2 h-9 w-full border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
              >
                <option value="all">all</option>
                <option value="python">python</option>
                <option value="rust">rust</option>
              </select>
            </label>
            <label>
              <span className="section-label">REVIEWER</span>
              <input
                value={reviewer}
                onChange={(event) => setReviewer(event.target.value)}
                className="mt-2 h-9 w-full border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
              />
            </label>
            <label>
              <span className="section-label">PROMOTION REASON</span>
              <input
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                className="mt-2 h-9 w-full border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
              />
            </label>
            <button
              onClick={verify}
              disabled={busy !== null}
              className="mt-auto flex h-9 items-center justify-center gap-2 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:text-signal disabled:opacity-30"
            >
              {busy === "verify" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5" />
              )}
              Verify
            </button>
          </div>
        </section>

        <PluginSection title="Protocol Parsers" icon={Plug} records={inventory.parsers} />
        <PluginSection
          title="Detectors"
          icon={ShieldCheck}
          records={inventory.detectors}
          calibrationTargets={targetsByDetector}
          busy={busy}
          onRun={run}
          onPromote={promote}
          reviewerReady={Boolean(reviewer.trim() && reason.trim())}
        />
        <PluginSection title="Hardware Sources" icon={Radio} records={inventory.hardware} />
      </div>
    </div>
  );
}

function PluginSection({
  title,
  icon: Icon,
  records,
  calibrationTargets,
  busy,
  reviewerReady = false,
  onRun,
  onPromote,
}: {
  title: string;
  icon: LucideIcon;
  records: PluginRecord[];
  calibrationTargets?: Map<string, PluginCalibrationTarget[]>;
  busy?: string | null;
  reviewerReady?: boolean;
  onRun?: (target: PluginCalibrationTarget) => void;
  onPromote?: (target: PluginCalibrationTarget) => void;
}) {
  return (
    <section className="panel">
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <Icon className="h-3.5 w-3.5 text-signal" />
        <span className="text-sm text-foreground">{title}</span>
        <span className="ml-auto mono text-[10px] text-muted-foreground">{records.length}</span>
      </div>
      <div className="grid gap-px bg-border lg:grid-cols-2 2xl:grid-cols-3">
        {records.map((item) => {
          const targets = item.detector_id ? calibrationTargets?.get(item.detector_id) || [] : [];
          return (
            <div
              key={`${item.type || item.source_type}:${item.name}`}
              className="min-w-0 bg-background p-4"
            >
              <div className="flex items-center justify-between gap-3">
                <span className="truncate text-[13px] text-foreground">{item.name}</span>
                <span
                  className={`mono text-[9px] uppercase ${item.valid ? "text-ok" : "text-severity-critical"}`}
                >
                  {item.valid ? "ready" : "error"}
                </span>
              </div>
              <div className="mt-2 mono text-[10px] uppercase text-muted-foreground">
                API v{item.api_version}{" "}
                {item.device_count !== undefined ? ` / ${item.device_count} devices` : ""}
              </div>
              <div className="mt-1 truncate text-[11px] text-muted-foreground">
                {item.supported_link_types?.join(", ") ||
                  item.backends?.join(", ") ||
                  "no capability metadata"}
              </div>

              {item.type === "detector" && (
                <div className="mt-3 border-t border-border pt-3">
                  <div className="mb-2 flex items-center justify-between gap-2 mono text-[9px] uppercase">
                    <span className="text-muted-foreground">Scoring trust</span>
                    <span className={trustColor(item.calibration_level)}>
                      {(item.calibration_level || "UNCALIBRATED").replaceAll("_", " ")}
                    </span>
                  </div>
                  <div className="space-y-2">
                    {targets.map((target) => (
                      <CalibrationTargetRow
                        key={`${target.detector_id}:${target.finding_type}`}
                        target={target}
                        busy={busy}
                        reviewerReady={reviewerReady}
                        onRun={onRun}
                        onPromote={onPromote}
                      />
                    ))}
                    {targets.length === 0 && (
                      <div className="mono text-[10px] text-muted-foreground">
                        No calibration targets declared
                      </div>
                    )}
                  </div>
                </div>
              )}
              {item.last_error && (
                <div className="mt-2 text-[11px] text-severity-critical">{item.last_error}</div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function CalibrationTargetRow({
  target,
  busy,
  reviewerReady,
  onRun,
  onPromote,
}: {
  target: PluginCalibrationTarget;
  busy?: string | null;
  reviewerReady: boolean;
  onRun?: (target: PluginCalibrationTarget) => void;
  onPromote?: (target: PluginCalibrationTarget) => void;
}) {
  const report = target.latest_report;
  const runKey = actionKey("run", target);
  const promoteKey = actionKey("promote", target);
  const canRun = Boolean(target.corpus_available);
  const canPromote =
    Boolean(report?.report_path && report.passed && reviewerReady) &&
    levelRank(report?.awarded_level) > levelRank(target.calibration_level);

  return (
    <div className="border border-border bg-surface/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate mono text-[10px] text-foreground">
          {target.finding_type}
        </span>
        <span className={`mono text-[9px] uppercase ${trustColor(target.calibration_level)}`}>
          {shortLevel(target.calibration_level)} / {target.effective_cap.toFixed(0)}
        </span>
      </div>
      <ReportStrip target={target} report={report} reportCount={target.report_count} />
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          onClick={() => onRun?.(target)}
          disabled={busy !== null}
          title={
            canRun
              ? "Run calibration corpus"
              : target.corpus_error || "No calibration corpus available"
          }
          className={`flex h-7 items-center gap-1.5 border px-2.5 mono text-[9px] uppercase disabled:opacity-30 ${
            canRun
              ? "border-signal/40 text-signal"
              : "border-border text-muted-foreground hover:text-severity-high"
          }`}
        >
          {busy === runKey ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Play className="h-3 w-3" />
          )}
          Calibrate
        </button>
        <button
          onClick={() => onPromote?.(target)}
          disabled={busy !== null}
          title={
            !report?.passed
              ? "Run a passing calibration first"
              : !reviewerReady
                ? "Reviewer and reason are required"
                : "Promote latest report"
          }
          className={`flex h-7 items-center gap-1.5 border px-2.5 mono text-[9px] uppercase disabled:opacity-30 ${
            canPromote
              ? "border-ok/40 text-ok"
              : "border-border text-muted-foreground hover:text-severity-high"
          }`}
        >
          {busy === promoteKey ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Award className="h-3 w-3" />
          )}
          Promote
        </button>
      </div>
    </div>
  );
}

function ReportStrip({
  target,
  report,
  reportCount,
}: {
  target: PluginCalibrationTarget;
  report?: CalibrationReportSummary | null;
  reportCount: number;
}) {
  if (!report) {
    const corpusText = target.corpus_available
      ? `${target.corpus_case_count || 0} cases ready`
      : target.corpus_error || "No corpus";
    return (
      <div className="mt-2 flex items-center gap-1.5 mono text-[9px] text-muted-foreground">
        <ShieldAlert className="h-3 w-3" />
        {corpusText}
      </div>
    );
  }
  const metrics = report.metrics || {};
  return (
    <div className="mt-2 space-y-1.5 mono text-[9px] text-muted-foreground">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className={report.passed ? "text-ok" : "text-severity-high"}>
          {report.passed ? "PASS" : "FAIL"}
        </span>
        <span>{report.awarded_level.replaceAll("_", " ")}</span>
        <span>
          {reportCount} report{reportCount === 1 ? "" : "s"}
        </span>
        <span>{report.digest.slice(0, 12)}</span>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span>P {percent(metrics.precision)}</span>
        <span>R {percent(metrics.recall)}</span>
        <span>FP {Number(metrics.false_positive || 0)}</span>
        <span>FN {Number(metrics.false_negative || 0)}</span>
        <span>{Number(metrics.execution_seconds || 0).toFixed(1)}s</span>
      </div>
      {(report.failures.length > 0 || report.field_failures.length > 0) && (
        <div
          className="truncate text-severity-high"
          title={[...report.failures, ...report.field_failures].join("; ")}
        >
          {[...report.failures, ...report.field_failures][0]}
        </div>
      )}
    </div>
  );
}

function actionKey(action: string, target: PluginCalibrationTarget) {
  return `${action}:${target.detector_id}:${target.finding_type}`;
}

function levelRank(level?: string) {
  if (level === "FIELD_CALIBRATED") return 3;
  if (level === "CORPUS_VALIDATED") return 2;
  return 1;
}

function percent(value?: number) {
  return value === undefined ? "--" : `${(value * 100).toFixed(1)}%`;
}

function shortLevel(level?: string) {
  if (level === "FIELD_CALIBRATED") return "FIELD";
  if (level === "CORPUS_VALIDATED") return "CORPUS";
  if (level === "MIXED") return "MIXED";
  return "UNCAL";
}

function trustColor(level?: string) {
  if (level === "FIELD_CALIBRATED") return "text-ok";
  if (level === "CORPUS_VALIDATED" || level === "MIXED") return "text-severity-medium";
  return "text-muted-foreground";
}
