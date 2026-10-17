import { createFileRoute } from "@tanstack/react-router";
import { fetchAlerts, setFindingDisposition } from "@/lib/api.functions";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Bot, CheckCircle2, Filter, XCircle } from "lucide-react";
import { useState } from "react";
import { useEffect } from "react";
import { useSensorScope } from "@/components/useSensorScope";
import type { Alert, CursorPage } from "@/types/watchtower";

export const Route = createFileRoute("/alerts")({
  head: () => ({ meta: [{ title: "Alerts — Watchtower" }] }),
  loader: async () => fetchAlerts({ data: { source: "live", limit: 100 } }),
  component: AlertsPage,
});

function AlertsPage() {
  const initialPage = Route.useLoaderData() as CursorPage<Alert>;
  const [page, setPage] = useState(initialPage);
  const [alerts, setAlerts] = useState(initialPage.items);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [cursorHistory, setCursorHistory] = useState<(string | undefined)[]>([undefined]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const { selectedNodeId } = useSensorScope();
  const [filter, setFilter] = useState<string>("ALL");
  const filtered = filter === "ALL" ? alerts : alerts.filter((a: Alert) => a.severity === filter);
  const counts = alerts.reduce((acc: Record<string, number>, a: Alert) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  useEffect(() => {
    void load(undefined, true);
    // load uses the selected node as its authoritative scope.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNodeId]);

  async function load(cursor?: string, reset = false) {
    const result = await fetchAlerts({
      data: {
        source: selectedNodeId ? undefined : "live",
        node: selectedNodeId,
        cursor,
        limit: 100,
      },
    });
    setPage(result);
    setAlerts(result.items);
    setSelected(null);
    if (reset) {
      setCursorHistory([undefined]);
      setCursorIndex(0);
    }
  }

  async function disposition(
    verdict: "true_positive" | "false_positive" | "benign_expected" | "unknown",
  ) {
    if (!selected || !reason.trim()) return;
    setBusy(true);
    try {
      await setFindingDisposition({ data: { id: selected.id, verdict, reason: reason.trim() } });
      setReason("");
      await load(cursorHistory[cursorIndex], false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="px-6 py-3 flex items-center gap-6 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">ALT</span>
          <span className="text-foreground">/ Incident Log</span>
          <span className="text-muted-foreground">{alerts.length} events</span>
        </div>
      </header>

      <div className="px-6 py-5 space-y-5">
        <div className="grid grid-cols-4 gap-px bg-border">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
            <div key={sev} className="bg-background p-4">
              <div className="section-label">{sev}</div>
              <div
                className={`numeral text-3xl mt-1 ${sev === "CRITICAL" ? "text-severity-critical" : sev === "HIGH" ? "text-severity-high" : sev === "MEDIUM" ? "text-severity-medium" : "text-signal"}`}
              >
                {counts[sev] || 0}
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center gap-1 border-b border-border">
          <Filter className="h-3 w-3 text-muted-foreground mr-2" />
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-3 py-2 mono text-[10px] uppercase tracking-wider transition-colors border-b-2 ${
                filter === sev
                  ? "text-signal border-signal"
                  : "text-muted-foreground border-transparent hover:text-foreground"
              }`}
            >
              {sev}{" "}
              <span className="opacity-60">
                ({sev === "ALL" ? alerts.length : counts[sev] || 0})
              </span>
            </button>
          ))}
        </div>

        <div className="grid grid-cols-12 gap-px bg-border">
          <div
            className={`${selected ? "col-span-8" : "col-span-12"} panel divide-y divide-border`}
          >
            {filtered.map((alert: Alert) => (
              <button
                key={alert.id}
                onClick={() => setSelected(alert)}
                className="w-full p-4 text-left data-row"
              >
                <div className="flex items-start gap-4">
                  <div className="mono text-[10px] text-muted-foreground w-14 shrink-0 pt-0.5">
                    #{String(alert.id).padStart(4, "0")}
                  </div>
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                      alert.severity === "CRITICAL"
                        ? "bg-severity-critical"
                        : alert.severity === "HIGH"
                          ? "bg-severity-high"
                          : alert.severity === "MEDIUM"
                            ? "bg-severity-medium"
                            : "bg-severity-low"
                    }`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm text-foreground tracking-tight">{alert.type}</h3>
                      <SeverityBadge severity={alert.severity} />
                      {alert.ai_verdict && (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 mono text-[10px] uppercase text-signal border border-signal/40">
                          <Bot className="h-2.5 w-2.5" /> {alert.ai_verdict}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-[13px] text-foreground/70">{alert.explanation}</p>
                    <div className="mt-2 flex flex-wrap items-center mono text-[10px] uppercase tracking-wider text-muted-foreground">
                      <span>SRC {alert.src_ip}</span>
                      <span className="divider-dot">DST {alert.dst_ip}</span>
                      <span className="divider-dot">
                        {new Date(alert.timestamp * 1000).toLocaleString("en-GB")}
                      </span>
                      <span className="divider-dot">{alert.source}</span>
                      <span className="divider-dot">
                        {alert.capture_interface || "unknown interface"}
                      </span>
                    </div>
                  </div>
                </div>
              </button>
            ))}
          </div>
          {selected && (
            <aside className="col-span-4 bg-background p-4">
              <div className="section-label">/ FINDING DETAIL</div>
              <h2 className="mt-2 text-sm text-foreground">{selected.type}</h2>
              <div className="mt-4 grid grid-cols-2 gap-3 mono text-[10px] uppercase">
                <Metric label="Impact" value={selected.impact || selected.severity} />
                <Metric
                  label="Contribution"
                  value={`${(selected.effective_contribution || 0).toFixed(1)} / 100`}
                />
                <Metric
                  label="Entity priority"
                  value={`${(selected.current_entity_priority || 0).toFixed(1)} / 100`}
                />
                <Metric
                  label="Confidence"
                  value={`${Math.round((selected.assessment_confidence || 0) * 100)}%`}
                />
              </div>
              <pre className="mt-4 max-h-52 overflow-auto border border-border bg-surface p-3 mono text-[10px] text-muted-foreground">
                {JSON.stringify(selected.evidence, null, 2)}
              </pre>
              <textarea
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Disposition reason"
                className="mt-4 min-h-20 w-full border border-border bg-background p-2 text-xs text-foreground outline-none focus:border-signal"
              />
              <div className="mt-2 grid grid-cols-2 gap-2">
                <button
                  disabled={busy || !reason.trim()}
                  onClick={() => void disposition("true_positive")}
                  className="inline-flex items-center justify-center gap-2 border border-ok/50 px-2 py-2 mono text-[10px] uppercase text-ok disabled:opacity-30"
                >
                  <CheckCircle2 className="h-3 w-3" /> True positive
                </button>
                <button
                  disabled={busy || !reason.trim()}
                  onClick={() => void disposition("false_positive")}
                  className="inline-flex items-center justify-center gap-2 border border-severity-high/50 px-2 py-2 mono text-[10px] uppercase text-severity-high disabled:opacity-30"
                >
                  <XCircle className="h-3 w-3" /> False positive
                </button>
              </div>
            </aside>
          )}
        </div>
        <div className="flex items-center justify-between">
          <button
            disabled={cursorIndex === 0}
            onClick={() => {
              const index = cursorIndex - 1;
              setCursorIndex(index);
              void load(cursorHistory[index], false);
            }}
            className="border border-border px-3 py-2 mono text-[10px] uppercase disabled:opacity-30"
          >
            Previous 100
          </button>
          <span className="mono text-[10px] uppercase text-muted-foreground">
            Page {cursorIndex + 1}
          </span>
          <button
            disabled={!page.next_cursor}
            onClick={() => {
              if (!page.next_cursor) return;
              const history = cursorHistory.slice(0, cursorIndex + 1);
              history.push(page.next_cursor);
              setCursorHistory(history);
              setCursorIndex(cursorIndex + 1);
              void load(page.next_cursor, false);
            }}
            className="border border-border px-3 py-2 mono text-[10px] uppercase disabled:opacity-30"
          >
            Next 100
          </button>
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-border p-2">
      <div className="text-muted-foreground">{label}</div>
      <div className="mt-1 text-foreground">{value}</div>
    </div>
  );
}
