import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2, Crosshair, Loader2, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { fetchInterfaces, runSigmaHunt } from "@/lib/api.functions";
import type { NetworkInterface } from "@/types/watchtower";

export const Route = createFileRoute("/hunt")({
  head: () => ({ meta: [{ title: "Historical Hunt - Watchtower" }] }),
  loader: async () => (await fetchInterfaces()) as NetworkInterface[],
  component: HuntPage,
});

type HuntResult = {
  matched: number;
  persisted: boolean;
  active_rules: number;
  rejected_rules: number;
};

function HuntPage() {
  const interfaces = Route.useLoaderData();
  const [source, setSource] = useState("live");
  const [captureInterface, setCaptureInterface] = useState("");
  const [rule, setRule] = useState("");
  const [persist, setPersist] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await runSigmaHunt({
          data: {
            source: source.trim() || undefined,
            interface: captureInterface || undefined,
            rule: rule.trim() || undefined,
            persist,
          },
        }),
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Historical hunt failed");
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-6 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">HNT</span>
          <span className="text-foreground">/ Historical Sigma Hunt</span>
          <span className="ml-auto text-muted-foreground">stored traffic only</span>
        </div>
      </header>

      <div className="grid gap-px bg-border lg:grid-cols-[420px_1fr]">
        <section className="min-h-[calc(100vh-49px)] bg-background p-5">
          <div className="panel">
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <Crosshair className="h-3.5 w-3.5 text-signal" />
              <span className="section-label">/ HUNT SCOPE</span>
            </div>
            <div className="space-y-4 p-4">
              <Field
                label="SOURCE"
                value={source}
                onChange={setSource}
                placeholder="live or pcap:..."
              />
              <label className="block">
                <span className="section-label">CAPTURE INTERFACE</span>
                <select
                  value={captureInterface}
                  onChange={(event) => setCaptureInterface(event.target.value)}
                  className="mt-2 h-9 w-full border border-border bg-background px-2 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
                >
                  <option value="">All interfaces</option>
                  {interfaces
                    .filter((item) => item.source_type === "network")
                    .map((item) => (
                      <option key={item.id} value={item.name}>
                        {item.name}
                      </option>
                    ))}
                </select>
              </label>
              <Field
                label="RULE ID OR TITLE"
                value={rule}
                onChange={setRule}
                placeholder="blank runs all compatible rules"
              />
              <label className="flex items-center justify-between border border-border px-3 py-2.5">
                <span>
                  <span className="block text-[12px] text-foreground">Persist matches</span>
                  <span className="mono text-[9px] uppercase text-muted-foreground">
                    write resulting alerts
                  </span>
                </span>
                <input
                  type="checkbox"
                  checked={persist}
                  onChange={(event) => setPersist(event.target.checked)}
                  className="h-4 w-4 accent-[hsl(var(--signal))]"
                />
              </label>
              <button
                onClick={run}
                disabled={running}
                className="flex h-9 w-full items-center justify-center gap-2 border border-signal bg-signal/10 mono text-[10px] uppercase tracking-wider text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-40"
              >
                {running ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Crosshair className="h-3.5 w-3.5" />
                )}
                Execute Hunt
              </button>
            </div>
          </div>
          <p className="mt-4 text-[12px] leading-relaxed text-muted-foreground">
            Sigma rules are evaluated only against stored WatchTower flows, entities, and metadata.
            This action does not install live packet detectors or alter capture behavior.
          </p>
        </section>

        <section className="min-h-[calc(100vh-49px)] bg-background p-5">
          {result ? (
            <div className="panel">
              <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-ok" />
                <span className="section-label">/ HUNT COMPLETE</span>
              </div>
              <div className="grid grid-cols-2 gap-px bg-border lg:grid-cols-4">
                <Metric label="MATCHES" value={result.matched} alert={result.matched > 0} />
                <Metric label="ACTIVE RULES" value={result.active_rules} />
                <Metric label="REJECTED" value={result.rejected_rules} />
                <Metric label="PERSISTED" value={result.persisted ? "YES" : "NO"} />
              </div>
            </div>
          ) : error ? (
            <div className="border border-severity-critical/40 bg-severity-critical/10 p-4 mono text-[11px] text-severity-critical">
              <ShieldAlert className="mr-2 inline h-4 w-4" />
              {error}
            </div>
          ) : (
            <div className="panel grid min-h-80 place-items-center">
              <div className="text-center">
                <Crosshair className="mx-auto h-8 w-8 text-muted-foreground" />
                <div className="mt-3 mono text-[11px] uppercase tracking-wider text-muted-foreground">
                  Configure a historical scope and execute
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="block">
      <span className="section-label">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-9 w-full border border-border bg-background px-3 mono text-[11px] text-foreground placeholder:text-muted-foreground focus:border-signal focus:outline-none"
      />
    </label>
  );
}

function Metric({
  label,
  value,
  alert = false,
}: {
  label: string;
  value: string | number;
  alert?: boolean;
}) {
  return (
    <div className="bg-background p-4">
      <div className="section-label">{label}</div>
      <div className={`mt-2 numeral text-2xl ${alert ? "text-severity-high" : "text-foreground"}`}>
        {value}
      </div>
    </div>
  );
}
