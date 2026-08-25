import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Clock, FileSearch, Link2, ShieldAlert } from "lucide-react";
import { LookupIntelPanel } from "@/components/LookupIntelPanel";
import { fetchEntityDetail } from "@/lib/api.functions";
import type { Investigation } from "@/types/watchtower";
import { useEffect, useState } from "react";
import { useSensorScope } from "@/components/useSensorScope";

export const Route = createFileRoute("/entities/$ip")({
  head: ({ params }) => ({ meta: [{ title: `${params.ip} - Watchtower Investigation` }] }),
  loader: async ({ params }) => fetchEntityDetail({ data: { ip: params.ip } }),
  component: EntityInvestigationPage,
});

function EntityInvestigationPage() {
  const initial = Route.useLoaderData() as Investigation;
  const [result, setResult] = useState(initial);
  const { selectedNodeId } = useSensorScope();
  useEffect(() => {
    fetchEntityDetail({ data: { ip: initial.target, node: selectedNodeId } }).then(setResult);
  }, [initial.target, selectedNodeId]);
  const riskColor =
    result.risk_score >= 80
      ? "text-severity-critical"
      : result.risk_score >= 50
        ? "text-severity-high"
        : result.risk_score >= 20
          ? "text-severity-medium"
          : "text-signal";

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-5 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <Link
            to="/entities"
            title="Back to entities"
            className="grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
          </Link>
          <span className="section-label section-label-accent">DIV</span>
          <span className="text-foreground">/ Asset Investigation</span>
          <span className="text-signal">{result.target}</span>
          <span className="ml-auto text-muted-foreground">source {result.source}</span>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-px bg-border">
        <section className="col-span-12 bg-background p-5 lg:col-span-4">
          <div className="panel p-4">
            <div className="section-label">/ ASSESSMENT</div>
            <div className={`mt-2 numeral text-3xl ${riskColor}`}>{result.verdict}</div>
            <div className="mt-4 grid grid-cols-2 gap-px bg-border">
              <Metric label="PRIORITY" value={`${result.priority_score.toFixed(1)}/100`} />
              <Metric
                label="ASSESSMENT CONFIDENCE"
                value={`${Math.round(result.assessment_confidence * 100)}%`}
              />
            </div>
            <p className="mt-4 text-[13px] leading-relaxed text-muted-foreground">
              {result.summary}
            </p>
          </div>

          <div className="mt-5 panel">
            <div className="border-b border-border px-4 py-2.5 section-label">
              / SCORE CONTRIBUTORS
            </div>
            <div className="divide-y divide-border">
              {result.contributors.map((contributor, index) => (
                <div
                  key={`${contributor.finding_type || contributor.detector_id}-${index}`}
                  className="px-4 py-3"
                >
                  <div className="flex items-center justify-between gap-3 mono text-[11px]">
                    <span className="text-foreground">
                      {contributor.finding_type || contributor.detector_id || "finding"}
                    </span>
                    <span className="text-signal">
                      {Number(contributor.effective_contribution || 0).toFixed(1)}
                    </span>
                  </div>
                  {contributor.explanation && (
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      {contributor.explanation}
                    </div>
                  )}
                </div>
              ))}
              {result.contributors.length === 0 && (
                <div className="px-4 py-3 mono text-[10px] uppercase text-muted-foreground">
                  No active V2 contributors
                </div>
              )}
            </div>
          </div>

          <div className="mt-5 panel">
            <div className="border-b border-border px-4 py-2.5 section-label">/ FINDINGS</div>
            <div className="divide-y divide-border">
              {result.findings.map((finding) => (
                <div
                  key={finding}
                  className="px-4 py-3 text-[12px] leading-relaxed text-foreground"
                >
                  {finding}
                </div>
              ))}
            </div>
          </div>

          <div className="mt-5 panel">
            <div className="border-b border-border px-4 py-2.5 section-label">/ NEXT ACTIONS</div>
            <ol className="divide-y divide-border">
              {result.next_actions.map((action, index) => (
                <li
                  key={action}
                  className="flex gap-3 px-4 py-3 text-[12px] leading-relaxed text-foreground"
                >
                  <span className="mono text-signal">{String(index + 1).padStart(2, "0")}</span>
                  {action}
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="col-span-12 bg-background p-5 lg:col-span-8">
          <div className="grid grid-cols-3 gap-px bg-border">
            <Metric
              label="EVIDENCE"
              value={result.evidence.length.toLocaleString("en-US")}
              icon={<FileSearch className="h-3.5 w-3.5" />}
            />
            <Metric
              label="CORRELATIONS"
              value={result.correlations.length.toLocaleString("en-US")}
              icon={<Link2 className="h-3.5 w-3.5" />}
            />
            <Metric
              label="ALERT GROUPS"
              value={result.alert_groups.length.toLocaleString("en-US")}
              icon={<ShieldAlert className="h-3.5 w-3.5" />}
            />
          </div>

          {result.lookup && (
            <div className="mt-5">
              <LookupIntelPanel lookup={result.lookup} />
            </div>
          )}

          <div className="mt-5 panel">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <Clock className="h-3.5 w-3.5 text-signal" />
              <div className="section-label">/ EVIDENCE TIMELINE</div>
            </div>
            <div className="divide-y divide-border">
              {result.timeline.map((item) => (
                <div
                  key={`${item.ref}-${item.timestamp}`}
                  className="grid grid-cols-[150px_90px_1fr] gap-3 px-4 py-3 data-row"
                >
                  <span className="mono text-[10px] text-muted-foreground">
                    {item.timestamp
                      ? new Date(item.timestamp * 1000).toLocaleString("en-GB")
                      : "unknown time"}
                  </span>
                  <span className="mono text-[10px] uppercase text-signal">{item.type}</span>
                  <div>
                    <div className="text-[12px] text-foreground">{item.summary}</div>
                    <div className="mt-0.5 mono text-[9px] text-muted-foreground">{item.ref}</div>
                  </div>
                </div>
              ))}
              {result.timeline.length === 0 && (
                <div className="grid min-h-48 place-items-center mono text-[11px] uppercase text-muted-foreground">
                  No evidence is currently stored for this asset
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="bg-background p-4">
      <div className="flex items-center justify-between section-label">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-1 numeral text-2xl text-foreground">{value}</div>
    </div>
  );
}
