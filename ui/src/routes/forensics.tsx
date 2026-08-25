import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Ban,
  Boxes,
  ChevronLeft,
  ChevronRight,
  FileKey,
  FileSearch,
  FlaskConical,
  Loader2,
  Network,
  Plus,
  RefreshCw,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PcapTemporalTopology } from "@/components/PcapTemporalTopology";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  cancelPcapAnalysis,
  createPcapCaseFlag,
  getPcapAnalysis,
  listPcapCaseFlags,
  getPcapProjection,
  getPcapTimeline,
  getPcapTopology,
  listPcapAnalyses,
  pcapEventsUrl,
  submitPcapAnalysis,
  type PcapPage,
  type PcapProjection,
  type PcapTimelineData,
  type PcapTopologyData,
} from "@/lib/pcap";
import type { PcapResult } from "@/types/watchtower";

export const Route = createFileRoute("/forensics")({
  head: () => ({ meta: [{ title: "Forensics - Watchtower" }] }),
  component: ForensicsPage,
});

type Tab =
  | "overview"
  | "findings"
  | "entities"
  | "flows"
  | "topology"
  | "timeline"
  | "artifacts"
  | "streams"
  | "evidence";

const tabs: Array<{ id: Tab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "entities", label: "Entities" },
  { id: "flows", label: "Flows" },
  { id: "topology", label: "Topology" },
  { id: "timeline", label: "Timeline" },
  { id: "artifacts", label: "Artifacts" },
  { id: "streams", label: "Streams" },
  { id: "evidence", label: "Evidence" },
];

const terminalStates = new Set(["complete", "partial", "cancelled", "failed"]);

function formatBytes(value: number) {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value || 0} B`;
}

function formatTime(value: unknown) {
  const number = Number(value || 0);
  return number ? new Date(number * 1000).toLocaleString() : "not recorded";
}

function ForensicsPage() {
  const pcapInput = useRef<HTMLInputElement>(null);
  const keylogInput = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [keylog, setKeylog] = useState<File | null>(null);
  const [mode, setMode] = useState("auto");
  const [backend, setBackend] = useState("rust");
  const [jobs, setJobs] = useState<PcapResult[]>([]);
  const [analysis, setAnalysis] = useState<PcapResult | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  const refreshJobs = useCallback(async () => {
    const payload = await listPcapAnalyses();
    setJobs(payload.items);
    return payload.items;
  }, []);

  const refreshAnalysis = useCallback(async (id: string) => {
    const value = await getPcapAnalysis(id);
    setAnalysis(value);
    setJobs((current) => [value, ...current.filter((job) => job.id !== value.id)]);
    return value;
  }, []);

  useEffect(() => {
    refreshJobs().catch((cause) =>
      setError(cause instanceof Error ? cause.message : "Unable to load PCAP history"),
    );
  }, [refreshJobs]);

  useEffect(() => {
    if (!selectedId) return;
    refreshAnalysis(selectedId).catch((cause) =>
      setError(cause instanceof Error ? cause.message : "Unable to load analysis"),
    );
  }, [refreshAnalysis, selectedId]);

  const analysisStatus = analysis?.status;

  useEffect(() => {
    if (!selectedId || !analysisStatus || terminalStates.has(analysisStatus)) return;
    let closed = false;
    const events = new EventSource(pcapEventsUrl(selectedId), { withCredentials: true });
    const update = (event: MessageEvent) => {
      if (closed) return;
      const payload = JSON.parse(event.data) as PcapResult;
      if (payload.id) {
        setAnalysis(payload);
        setJobs((current) => [payload, ...current.filter((job) => job.id !== payload.id)]);
      }
    };
    events.addEventListener("progress", update as EventListener);
    events.addEventListener("terminal", () => {
      events.close();
      void refreshAnalysis(selectedId);
    });
    events.onerror = () => {
      events.close();
      if (!closed) window.setTimeout(() => void refreshAnalysis(selectedId), 700);
    };
    const fallback = window.setInterval(() => {
      if (!closed) void refreshAnalysis(selectedId);
    }, 2500);
    return () => {
      closed = true;
      events.close();
      window.clearInterval(fallback);
    };
  }, [analysisStatus, refreshAnalysis, selectedId]);

  const start = async () => {
    if (!file) return;
    setSubmitting(true);
    setError(null);
    try {
      const job = await submitPcapAnalysis(file, mode, backend, keylog);
      setSelectedId(job.id);
      setAnalysis(job);
      setTab("overview");
      setFile(null);
      setKeylog(null);
      if (pcapInput.current) pcapInput.current.value = "";
      if (keylogInput.current) keylogInput.current.value = "";
      await refreshJobs();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "PCAP upload failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-6 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">FOR</span>
          <span className="text-foreground">/ Forensic Workspace</span>
          <span className="text-muted-foreground">Durable PCAP evidence</span>
        </div>
      </header>

      <div className="grid min-h-[calc(100vh-45px)] lg:grid-cols-[270px_minmax(0,1fr)]">
        <aside className="border-r border-border bg-surface/30 p-3">
          <button
            onClick={() => {
              setSelectedId(null);
              setAnalysis(null);
              setError(null);
            }}
            className="flex h-9 w-full items-center justify-center gap-2 border border-signal bg-signal/10 mono text-[10px] uppercase tracking-wider text-signal hover:bg-signal hover:text-primary-foreground"
          >
            <Plus className="h-3.5 w-3.5" /> New analysis
          </button>
          <div className="mt-5 flex items-center justify-between border-b border-border pb-2">
            <span className="section-label">/ ANALYSIS HISTORY</span>
            <button
              title="Refresh analysis history"
              onClick={() => void refreshJobs()}
              className="text-muted-foreground hover:text-signal"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="mt-2 space-y-1">
            {jobs.map((job) => (
              <button
                key={job.id}
                onClick={() => {
                  setSelectedId(job.id);
                  setTab("overview");
                }}
                className={`w-full border px-3 py-2 text-left transition-colors ${
                  selectedId === job.id
                    ? "border-signal/60 bg-signal/10"
                    : "border-transparent hover:border-border hover:bg-surface"
                }`}
              >
                <div className="truncate text-[12px] text-foreground">{job.filename}</div>
                <div className="mt-1 flex items-center justify-between mono text-[9px] uppercase text-muted-foreground">
                  <span>{job.status}</span>
                  <span>{formatBytes(job.file_size)}</span>
                </div>
              </button>
            ))}
            {jobs.length === 0 && (
              <div className="py-12 text-center mono text-[10px] uppercase text-muted-foreground">
                No persisted analyses
              </div>
            )}
          </div>
        </aside>

        <main className="min-w-0 p-5">
          {!selectedId && (
            <UploadWorkspace
              file={file}
              keylog={keylog}
              mode={mode}
              backend={backend}
              submitting={submitting}
              pcapInput={pcapInput}
              keylogInput={keylogInput}
              setFile={setFile}
              setKeylog={setKeylog}
              setMode={setMode}
              setBackend={setBackend}
              onStart={start}
            />
          )}

          {selectedId && analysis && (
            <AnalysisWorkspace
              analysis={analysis}
              tab={tab}
              setTab={setTab}
              onCancel={() =>
                cancelPcapAnalysis(selectedId).then(() => refreshAnalysis(selectedId))
              }
            />
          )}

          {selectedId && !analysis && (
            <div className="grid min-h-[60vh] place-items-center">
              <Loader2 className="h-8 w-8 animate-spin text-signal" />
            </div>
          )}

          {error && (
            <div className="mt-4 border border-severity-critical/40 bg-severity-critical/10 px-4 py-3 mono text-[11px] text-severity-critical">
              {error}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function UploadWorkspace({
  file,
  keylog,
  mode,
  backend,
  submitting,
  pcapInput,
  keylogInput,
  setFile,
  setKeylog,
  setMode,
  setBackend,
  onStart,
}: {
  file: File | null;
  keylog: File | null;
  mode: string;
  backend: string;
  submitting: boolean;
  pcapInput: React.RefObject<HTMLInputElement | null>;
  keylogInput: React.RefObject<HTMLInputElement | null>;
  setFile: (value: File | null) => void;
  setKeylog: (value: File | null) => void;
  setMode: (value: string) => void;
  setBackend: (value: string) => void;
  onStart: () => void;
}) {
  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <div>
        <div className="section-label section-label-accent">/ NEW FORENSIC ANALYSIS</div>
        <h1 className="mt-1 text-xl tracking-tight text-foreground">Inspect a packet capture</h1>
      </div>
      <input
        ref={pcapInput}
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={(event) => setFile(event.target.files?.[0] || null)}
      />
      <input
        ref={keylogInput}
        type="file"
        accept=".log,.txt,.keylog"
        className="hidden"
        onChange={(event) => setKeylog(event.target.files?.[0] || null)}
      />
      <div
        onClick={() => pcapInput.current?.click()}
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault();
          setFile(event.dataTransfer.files?.[0] || null);
        }}
        className="panel bracket grid-bg-fine flex min-h-64 cursor-pointer flex-col items-center justify-center p-10 hover:border-signal/50"
      >
        <Upload className="mb-4 h-10 w-10 text-signal" strokeWidth={1.5} />
        <div className="text-foreground">{file ? file.name : "Drop PCAP or click to select"}</div>
        <div className="mt-1 mono text-[10px] uppercase text-muted-foreground">
          {file ? formatBytes(file.size) : ".pcap / .pcapng / .cap"}
        </div>
      </div>
      <div className="grid gap-px bg-border md:grid-cols-[1fr_1fr_1.2fr]">
        <Control
          label="ANALYSIS MODE"
          value={mode}
          onChange={setMode}
          options={["auto", "memory", "streaming"]}
        />
        <Control
          label="PACKET CORE"
          value={backend}
          onChange={setBackend}
          options={["python", "rust"]}
        />
        <div className="bg-background p-4">
          <span className="section-label">TLS KEYLOG (OPTIONAL)</span>
          <button
            onClick={() => keylogInput.current?.click()}
            className="mt-2 flex h-9 w-full items-center gap-2 border border-border px-3 mono text-[10px] text-muted-foreground hover:border-signal hover:text-signal"
          >
            <FileKey className="h-3.5 w-3.5" />
            <span className="truncate">{keylog?.name || "Select keylog"}</span>
          </button>
        </div>
      </div>
      <div className="flex items-center justify-between gap-4 border-t border-border pt-4">
        <p className="max-w-xl text-[11px] leading-relaxed text-muted-foreground">
          Uploads are removed after processing. TLS keylogs are encrypted while queued and deleted
          at completion.
        </p>
        <button
          disabled={!file || submitting}
          onClick={onStart}
          className="flex h-9 items-center gap-2 border border-signal bg-signal/10 px-4 mono text-[10px] uppercase tracking-wider text-signal hover:bg-signal hover:text-primary-foreground disabled:cursor-not-allowed disabled:opacity-30"
        >
          {submitting ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <FlaskConical className="h-3.5 w-3.5" />
          )}
          Queue analysis
        </button>
      </div>
    </div>
  );
}

function AnalysisWorkspace({
  analysis,
  tab,
  setTab,
  onCancel,
}: {
  analysis: PcapResult;
  tab: Tab;
  setTab: (tab: Tab) => void;
  onCancel: () => Promise<unknown>;
}) {
  const isTerminal = terminalStates.has(analysis.status);
  const progress = Number(analysis.progress || 0);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="section-label section-label-accent">
            / {analysis.status.toUpperCase()}
          </div>
          <h1 className="mt-1 truncate text-xl tracking-tight text-foreground">
            {analysis.filename}
          </h1>
          <div className="mt-1 mono text-[10px] text-muted-foreground">
            {analysis.source} / {analysis.mode} / {analysis.backend}
          </div>
        </div>
        {!isTerminal && (
          <button
            onClick={() => void onCancel()}
            className="flex h-8 items-center gap-2 border border-severity-high/40 px-3 mono text-[10px] uppercase text-severity-high hover:bg-severity-high/10"
          >
            <Ban className="h-3.5 w-3.5" /> Cancel
          </button>
        )}
      </div>
      {!isTerminal && (
        <div className="border border-border bg-background p-4">
          <div className="flex items-center justify-between mono text-[10px] uppercase text-muted-foreground">
            <span>
              {formatBytes(analysis.bytes_processed)} of {formatBytes(analysis.file_size)}
            </span>
            <span className="text-signal">{progress.toFixed(1)}%</span>
          </div>
          <div className="mt-3 h-1 bg-border">
            <div
              className="h-full bg-signal transition-[width]"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}
      {isTerminal && analysis.status !== "complete" && (
        <div className="flex items-start gap-3 border border-severity-high/40 bg-severity-high/10 p-3 text-[11px] text-severity-high">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Processing ended as {analysis.status}. Conclusions are explicitly partial.{" "}
            {analysis.error || ""}
          </span>
        </div>
      )}
      <div className="flex overflow-x-auto border-b border-border">
        {tabs.map((item) => (
          <button
            key={item.id}
            onClick={() => setTab(item.id)}
            className={`h-9 shrink-0 border-b-2 px-3 mono text-[10px] uppercase transition-colors ${tab === item.id ? "border-signal text-signal" : "border-transparent text-muted-foreground hover:text-foreground"}`}
          >
            {item.label}
          </button>
        ))}
      </div>
      <AnalysisTab analysis={analysis} tab={tab} />
    </div>
  );
}

function AnalysisTab({ analysis, tab }: { analysis: PcapResult; tab: Tab }) {
  const [page, setPage] = useState<PcapPage | null>(null);
  const [cursor, setCursor] = useState(0);
  const [history, setHistory] = useState<number[]>([]);
  const [topology, setTopology] = useState<PcapTopologyData | null>(null);
  const [timeline, setTimeline] = useState<PcapTimelineData | null>(null);
  const [findings, setFindings] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setCursor(0);
    setHistory([]);
    setPage(null);
  }, [analysis.id, tab]);

  useEffect(() => {
    if (!terminalStates.has(analysis.status) || tab === "overview") return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    const task =
      tab === "topology"
        ? Promise.all([
            getPcapTopology(analysis.id),
            getPcapTimeline(analysis.id),
            getPcapProjection(analysis.id, "findings", 0, 500),
          ]).then(([graph, time, findingPage]) => {
            if (!cancelled) {
              setTopology(graph);
              setTimeline(time);
              setFindings(findingPage.items);
            }
          })
        : tab === "timeline"
          ? getPcapTimeline(analysis.id).then((value) => {
              if (!cancelled) setTimeline(value);
            })
          : getPcapProjection(analysis.id, tab as PcapProjection, cursor, 100).then((value) => {
              if (!cancelled) setPage(value);
            });
    task
      .catch(
        (cause) =>
          !cancelled &&
          setError(cause instanceof Error ? cause.message : "Unable to load projection"),
      )
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [analysis.id, analysis.status, cursor, tab]);

  if (tab === "overview") return <Overview analysis={analysis} />;
  if (!terminalStates.has(analysis.status)) {
    return (
      <EmptyState
        icon={<Loader2 className="h-6 w-6 animate-spin" />}
        text="Evidence projections unlock when processing finishes"
      />
    );
  }
  if (loading && !page && !topology && !timeline)
    return (
      <EmptyState
        icon={<Loader2 className="h-6 w-6 animate-spin" />}
        text="Loading forensic projection"
      />
    );
  if (error) return <EmptyState icon={<AlertTriangle className="h-6 w-6" />} text={error} />;
  if (tab === "topology" && topology && timeline) {
    const findingTargets = findings.flatMap((finding) =>
      ["subject_ip", "entity_ip", "src_ip", "dst_ip"]
        .map((key) => String(finding[key] || ""))
        .filter(Boolean),
    );
    return (
      <PcapTemporalTopology
        topology={topology}
        timeline={timeline}
        findingTargets={findingTargets}
      />
    );
  }
  if (tab === "timeline" && timeline) return <TimelineView timeline={timeline} />;
  return (
    <div>
      <ProjectionTable kind={tab} items={page?.items || []} />
      <div className="mt-3 flex items-center justify-between">
        <span className="mono text-[10px] text-muted-foreground">
          Rows {cursor + 1}-{cursor + (page?.items.length || 0)}
        </span>
        <div className="flex gap-1">
          <button
            disabled={history.length === 0}
            title="Previous page"
            onClick={() => {
              const previous = history.at(-1) || 0;
              setHistory((items) => items.slice(0, -1));
              setCursor(previous);
            }}
            className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-30"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>
          <button
            disabled={page?.next_cursor == null}
            title="Next page"
            onClick={() => {
              if (page?.next_cursor != null) {
                setHistory((items) => [...items, cursor]);
                setCursor(page.next_cursor as number);
              }
            }}
            className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-30"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

function Overview({ analysis }: { analysis: PcapResult }) {
  const limitations =
    (analysis as PcapResult & { visibility_limitations?: string[] }).visibility_limitations || [];
  const caseRecord = (analysis as PcapResult & { case?: Record<string, unknown> }).case;
  const triage = (analysis.summary as Record<string, unknown> | undefined)?.triage as
    | { flagged?: number; signals?: number }
    | undefined;
  const [flags, setFlags] = useState<Record<string, unknown>[]>([]);
  const [flagType, setFlagType] = useState("ip");
  const [flagTarget, setFlagTarget] = useState("");
  const [flagReason, setFlagReason] = useState("");
  const [flagging, setFlagging] = useState(false);
  useEffect(() => {
    const caseId = String(caseRecord?.id || "");
    if (!caseId) return;
    void listPcapCaseFlags(caseId)
      .then((payload) => setFlags(payload.items))
      .catch(() => setFlags([]));
  }, [caseRecord?.id]);
  const addFlag = async () => {
    const caseId = String(caseRecord?.id || "");
    if (!caseId || !flagTarget.trim() || !flagReason.trim()) return;
    setFlagging(true);
    try {
      const flag = await createPcapCaseFlag(caseId, {
        target_type: flagType,
        target_id: flagTarget.trim(),
        reason: flagReason.trim(),
        confidence: 0.5,
      });
      setFlags((current) => [flag, ...current]);
      setFlagTarget("");
      setFlagReason("");
    } finally {
      setFlagging(false);
    }
  };
  return (
    <div className="space-y-4">
      <div className="border border-border bg-background p-4">
        <div className="section-label section-label-accent">/ CASE IDENTITY & CUSTODY</div>
        <dl className="mt-3 grid gap-y-2 mono text-[10px] md:grid-cols-2 md:gap-x-8">
          <dt className="text-muted-foreground">Case</dt>
          <dd className="break-all text-foreground">{String(caseRecord?.id || "not recorded")}</dd>
          <dt className="text-muted-foreground">PCAP SHA-256</dt>
          <dd className="break-all text-foreground">
            {String(caseRecord?.sha256 || "not recorded")}
          </dd>
          <dt className="text-muted-foreground">Parser/link layer</dt>
          <dd className="text-foreground">
            {String(caseRecord?.parser_version || "default")} /{" "}
            {String(caseRecord?.link_type || "detected")}
          </dd>
          <dt className="text-muted-foreground">Automatic triage</dt>
          <dd className="text-foreground">
            {Number(triage?.flagged || flags.length || 0).toLocaleString()} flagged from{" "}
            {Number(triage?.signals || 0).toLocaleString()} detector signals
          </dd>
        </dl>
        {flags.length > 0 && (
          <div className="mt-4 grid gap-2 md:grid-cols-2">
            {flags.slice(0, 6).map((flag) => (
              <div
                key={String(flag.id || flag.fingerprint)}
                className="border border-severity-high/40 bg-severity-high/5 p-3"
              >
                <div className="flex items-center justify-between mono text-[10px] uppercase">
                  <span className="text-severity-high">{String(flag.target_type || "entity")}</span>
                  <span className="text-muted-foreground">{String(flag.status || "open")}</span>
                </div>
                <div className="mt-1 mono text-[11px] text-foreground">
                  {String(flag.target_id || "unknown")}
                </div>
                <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                  {String(flag.reason || "Analyst review required")}
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="mt-4 border-t border-border pt-4">
          <div className="section-label">/ FLAG FOR REVIEW</div>
          <div className="mt-2 grid gap-2 md:grid-cols-[auto_1fr_1fr_auto]">
            <select
              value={flagType}
              onChange={(event) => setFlagType(event.target.value)}
              className="h-8 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground"
            >
              {["ip", "flow", "domain", "certificate", "asn", "service", "artifact"].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <input
              value={flagTarget}
              onChange={(event) => setFlagTarget(event.target.value)}
              placeholder="Target or evidence identifier"
              className="h-8 border border-border bg-background px-2 mono text-[10px] text-foreground outline-none focus:border-signal"
            />
            <input
              value={flagReason}
              onChange={(event) => setFlagReason(event.target.value)}
              placeholder="Why this needs review"
              className="h-8 border border-border bg-background px-2 mono text-[10px] text-foreground outline-none focus:border-signal"
            />
            <button
              disabled={flagging || !flagTarget.trim() || !flagReason.trim()}
              onClick={() => void addFlag()}
              className="flex h-8 items-center justify-center gap-2 border border-severity-high/50 px-3 mono text-[10px] uppercase text-severity-high hover:bg-severity-high/10 disabled:opacity-30"
            >
              <ShieldAlert className="h-3.5 w-3.5" /> Flag
            </button>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-px bg-border lg:grid-cols-6">
        <Metric label="PACKETS" value={(analysis.packet_count || 0).toLocaleString()} />
        <Metric label="FLOWS" value={(analysis.flow_count || 0).toLocaleString()} />
        <Metric label="ENTITIES" value={(analysis.entity_count || 0).toLocaleString()} />
        <Metric
          label="FINDINGS"
          value={String((analysis as PcapResult & { finding_count?: number }).finding_count || 0)}
        />
        <Metric label="ALERTS" value={(analysis.alert_count || 0).toLocaleString()} />
        <Metric label="DURATION" value={`${Number(analysis.duration_seconds || 0).toFixed(1)}s`} />
      </div>
      <div className="grid gap-px bg-border xl:grid-cols-2">
        <div className="bg-background p-4">
          <div className="section-label">/ PROTOCOL DISTRIBUTION</div>
          <div className="mt-3 space-y-2">
            {(analysis.protocols || []).slice(0, 12).map((item) => (
              <div
                key={item.protocol}
                className="grid grid-cols-[70px_1fr_55px] items-center gap-3 mono text-[10px]"
              >
                <span className="text-foreground">{item.protocol}</span>
                <span className="h-1 bg-border">
                  <span
                    className="block h-full bg-signal"
                    style={{ width: `${Math.min(100, item.percentage)}%` }}
                  />
                </span>
                <span className="text-right text-muted-foreground">{item.percentage}%</span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-background p-4">
          <div className="section-label">/ PROCESSING & VISIBILITY</div>
          <dl className="mt-3 grid grid-cols-2 gap-y-2 mono text-[10px]">
            <dt className="text-muted-foreground">State</dt>
            <dd className="text-right text-foreground">{analysis.status}</dd>
            <dt className="text-muted-foreground">Started</dt>
            <dd className="text-right text-foreground">
              {formatTime((analysis as PcapResult & { started_at?: number }).started_at)}
            </dd>
            <dt className="text-muted-foreground">Bytes processed</dt>
            <dd className="text-right text-foreground">{formatBytes(analysis.bytes_processed)}</dd>
            <dt className="text-muted-foreground">Completeness</dt>
            <dd className="text-right text-foreground">
              {String(
                (analysis as PcapResult & { processing_completeness?: string })
                  .processing_completeness || analysis.status,
              )}
            </dd>
          </dl>
          {limitations.length > 0 && (
            <div className="mt-4 border-l-2 border-severity-high pl-3 text-[11px] text-muted-foreground">
              {limitations.join(" ")}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ProjectionTable({ kind, items }: { kind: Tab; items: Record<string, unknown>[] }) {
  if (items.length === 0)
    return (
      <EmptyState
        icon={<FileSearch className="h-6 w-6" />}
        text={`No ${kind} were persisted for this analysis`}
      />
    );
  const columnsByKind: Record<string, Array<[string, string]>> = {
    findings: [
      ["finding_type", "Finding"],
      ["impact", "Impact"],
      ["subject_ip", "Subject"],
      ["confidence", "Confidence"],
      ["last_seen", "Last seen"],
    ],
    entities: [
      ["ip", "Entity"],
      ["hostname", "Hostname"],
      ["vendor", "Vendor"],
      ["device_type", "Device"],
      ["risk_score", "Priority"],
    ],
    flows: [
      ["flow_id", "Conversation"],
      ["protocol", "Protocol"],
      ["packet_count", "Packets"],
      ["byte_count", "Bytes"],
      ["last_seen", "Last seen"],
    ],
    artifacts: [
      ["filename", "Artifact"],
      ["filetype", "Type"],
      ["size", "Bytes"],
      ["sha256", "SHA-256"],
      ["timestamp", "Observed"],
    ],
    streams: [
      ["flow_id", "Stream"],
      ["protocol", "Protocol"],
      ["packet_count", "Packets"],
      ["byte_count", "Bytes"],
      ["evidence_hash", "Evidence hash"],
    ],
    evidence: [
      ["evidence_type", "Evidence"],
      ["entity_ip", "Entity"],
      ["reference", "Reference"],
      ["confidence", "Confidence"],
      ["timestamp", "Observed"],
    ],
  };
  const columns =
    columnsByKind[kind] ||
    Object.keys(items[0])
      .slice(0, 5)
      .map((key) => [key, key.replaceAll("_", " ")] as [string, string]);
  return (
    <div className="overflow-x-auto border border-border">
      <table className="w-full min-w-[760px] border-collapse">
        <thead>
          <tr className="bg-surface">
            {columns.map(([key, label]) => (
              <th key={key} className="border-b border-border px-3 py-2 text-left section-label">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr
              key={String(item.id || item.fingerprint || index)}
              className="data-row border-b border-border/60 last:border-0"
            >
              {columns.map(([key]) => {
                const value = item[key];
                const time = key.includes("seen") || key === "timestamp";
                return (
                  <td
                    key={key}
                    className="max-w-96 truncate px-3 py-2 mono text-[10px] text-foreground"
                    title={String(value ?? "")}
                  >
                    {time ? formatTime(value) : renderCell(key, value)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function renderCell(key: string, value: unknown) {
  if (key === "impact" && value)
    return (
      <SeverityBadge
        severity={String(value).toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"}
      />
    );
  if (typeof value === "number" && key.includes("confidence")) return value.toFixed(2);
  if (typeof value === "object" && value) return JSON.stringify(value);
  return String(value ?? "-");
}

function TimelineView({ timeline }: { timeline: PcapTimelineData }) {
  return (
    <div className="border border-border">
      <div className="flex items-center justify-between border-b border-border bg-surface px-3 py-2">
        <span className="section-label">/ CONVERSATION EVOLUTION</span>
        <span className="mono text-[10px] text-muted-foreground">
          {timeline.items.length.toLocaleString()} events in this window
        </span>
      </div>
      <div className="max-h-[62vh] divide-y divide-border overflow-y-auto">
        {timeline.items.map((item, index) => (
          <div
            key={String(item.id || index)}
            className="grid grid-cols-[120px_1fr_auto] items-center gap-4 px-3 py-2 data-row"
          >
            <span className="mono text-[10px] text-signal">{formatTime(item.first_seen)}</span>
            <span className="truncate mono text-[10px] text-foreground">
              {String(item.src_ip)}:{String(item.src_port)} → {String(item.dst_ip)}:
              {String(item.dst_port)}
            </span>
            <span className="mono text-[10px] text-muted-foreground">
              {String(item.protocol)} / {formatBytes(Number(item.bytes || 0))}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyState({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div className="grid min-h-72 place-items-center border border-border bg-background">
      <div className="flex flex-col items-center gap-3 text-muted-foreground">
        {icon}
        <span className="mono text-[10px] uppercase">{text}</span>
      </div>
    </div>
  );
}

function Control({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="bg-background p-4">
      <span className="section-label">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-2 h-9 w-full border border-border bg-background px-2 mono text-[10px] uppercase text-foreground focus:border-signal focus:outline-none"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-background p-4">
      <div className="section-label">{label}</div>
      <div className="mt-2 numeral text-xl text-foreground">{value}</div>
    </div>
  );
}
