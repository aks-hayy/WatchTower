import { createFileRoute } from "@tanstack/react-router";
import {
  CheckCircle2,
  CloudDownload,
  Loader2,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";
import {
  fetchSigmaRules,
  fetchSigmaStatus,
  installSigmaUrl,
  previewSigmaUrl,
  rollbackSigmaCorpus,
  syncSigmaCorpus,
} from "@/lib/api.functions";
import type { SigmaPreview, SigmaRule } from "@/types/watchtower";

export const Route = createFileRoute("/sigma")({
  head: () => ({ meta: [{ title: "Sigma Rules - Watchtower" }] }),
  loader: async () => ({ rules: await fetchSigmaRules(), status: await fetchSigmaStatus() }),
  component: SigmaPage,
});

function SigmaPage() {
  const initial = Route.useLoaderData();
  const [rules, setRules] = useState<SigmaRule[]>(initial.rules);
  const [status, setStatus] = useState<Record<string, unknown>>(initial.status);
  const [url, setUrl] = useState("");
  const [preview, setPreview] = useState<SigmaPreview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const refresh = async () => {
    const [nextRules, nextStatus] = await Promise.all([fetchSigmaRules(), fetchSigmaStatus()]);
    setRules(nextRules);
    setStatus(nextStatus);
  };
  const act = async (name: string, action: () => Promise<unknown>) => {
    setBusy(name);
    setMessage(null);
    try {
      await action();
      await refresh();
      setMessage(`${name} complete`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : `${name} failed`);
    } finally {
      setBusy(null);
    }
  };
  const inspect = async () => {
    setBusy("preview");
    setMessage(null);
    setPreview(null);
    try {
      setPreview(await previewSigmaUrl({ data: { url: url.trim() } }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Preview failed");
    } finally {
      setBusy(null);
    }
  };

  const manifest = (status.manifest || null) as Record<string, unknown> | null;
  const repository = String(status.repository || "https://github.com/SigmaHQ/sigma.git");
  return (
    <div className="min-h-screen">
      <header className="flex items-center gap-4 border-b border-border bg-surface/60 px-6 py-3">
        <span className="section-label section-label-accent">SIG</span>
        <span className="mono text-[11px] uppercase text-foreground">/ Sigma Corpus</span>
        <span className="ml-auto mono text-[10px] text-muted-foreground">
          {rules.filter((rule) => rule.compatible).length} compatible / {rules.length} loaded
        </span>
        <button
          onClick={refresh}
          title="Refresh Sigma inventory"
          className="grid h-7 w-7 place-items-center border border-border text-muted-foreground hover:text-signal"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </header>
      <div className="space-y-5 p-4 md:p-6">
        {message && (
          <div className="border border-signal/30 bg-signal/5 px-4 py-3 mono text-[11px] text-signal">
            {message}
          </div>
        )}
        <section className="panel">
          <div className="border-b border-border px-4 py-2.5 text-sm text-foreground">
            Remote Rule Intake
          </div>
          <div className="grid gap-4 p-4 lg:grid-cols-[1fr_auto]">
            <label>
              <span className="section-label">HTTPS GITHUB YAML URL</span>
              <input
                value={url}
                onChange={(event) => {
                  setUrl(event.target.value);
                  setPreview(null);
                }}
                placeholder="https://raw.githubusercontent.com/.../rule.yml"
                className="mt-2 h-9 w-full border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
              />
            </label>
            <button
              onClick={inspect}
              disabled={!url.trim() || busy !== null}
              className="mt-auto flex h-9 items-center gap-2 border border-signal/50 px-4 mono text-[10px] uppercase text-signal disabled:opacity-30"
            >
              {busy === "preview" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <CloudDownload className="h-3.5 w-3.5" />
              )}
              Preview
            </button>
          </div>
          {preview && (
            <div className="border-t border-border p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-[13px] text-foreground">{preview.title}</span>
                <span
                  className={`mono text-[9px] uppercase ${preview.compatible ? "text-ok" : "text-severity-critical"}`}
                >
                  {preview.compatible ? "compatible" : "rejected"}
                </span>
                <span className="mono text-[9px] text-muted-foreground">
                  {preview.level} / {preview.category}
                </span>
              </div>
              <div className="mt-2 break-all mono text-[9px] text-muted-foreground">
                SHA-256 {preview.sha256}
              </div>
              {preview.errors.length > 0 && (
                <div className="mt-3 text-[11px] text-severity-critical">
                  {preview.errors.join("; ")}
                </div>
              )}
              <pre className="mt-3 max-h-72 overflow-auto border border-border bg-surface p-3 text-[10px] leading-relaxed text-muted-foreground">
                {preview.content}
              </pre>
              <button
                onClick={() =>
                  act("load", () =>
                    installSigmaUrl({
                      data: { url: preview.url, expected_sha256: preview.sha256 },
                    }),
                  )
                }
                disabled={!preview.compatible || busy !== null}
                className="mt-3 flex h-8 items-center gap-2 border border-ok/50 px-3 mono text-[10px] uppercase text-ok disabled:opacity-30"
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                Load into WatchTower
              </button>
            </div>
          )}
        </section>

        <section className="panel">
          <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2.5">
            <span className="text-sm text-foreground">Official SigmaHQ Corpus</span>
            <span className="mono text-[9px] text-muted-foreground">
              {manifest ? String(manifest.commit || "unknown").slice(0, 12) : "not synchronized"}
            </span>
            <div className="ml-auto flex gap-2">
              <button
                onClick={() => act("sync", () => syncSigmaCorpus())}
                disabled={busy !== null}
                className="flex h-7 items-center gap-1.5 border border-signal/40 px-2.5 mono text-[9px] uppercase text-signal"
              >
                <CloudDownload className="h-3 w-3" />
                Sync
              </button>
              <button
                onClick={() => act("rollback", () => rollbackSigmaCorpus())}
                disabled={busy !== null}
                className="flex h-7 items-center gap-1.5 border border-border px-2.5 mono text-[9px] uppercase text-muted-foreground"
              >
                <RotateCcw className="h-3 w-3" />
                Rollback
              </button>
            </div>
          </div>
          <div className="border-b border-border px-4 py-2 mono text-[9px] text-muted-foreground">
            SOURCE {repository.replace(/\.git$/, "")}
          </div>
          {busy && ["sync", "rollback", "load"].includes(busy) && (
            <div className="flex items-center gap-2 border-b border-border px-4 py-2 mono text-[10px] text-signal">
              <Loader2 className="h-3 w-3 animate-spin" />
              {busy} in progress
            </div>
          )}
        </section>

        <section className="panel">
          <div className="border-b border-border px-4 py-2.5 text-sm text-foreground">
            Loaded Rules
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left mono text-[10px]">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="p-3">RULE</th>
                  <th>ID</th>
                  <th>SOURCE</th>
                  <th>LEVEL</th>
                  <th>LOGSOURCE</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, index) => (
                  <tr
                    key={`${rule.source}:${rule.id}:${index}`}
                    className="border-b border-border/60"
                  >
                    <td className="max-w-72 p-3 text-foreground">{rule.title}</td>
                    <td>{rule.id || "-"}</td>
                    <td>{rule.source}</td>
                    <td>{rule.level || "-"}</td>
                    <td>{rule.category || "-"}</td>
                    <td>
                      {rule.compatible ? (
                        <span className="text-ok">READY</span>
                      ) : (
                        <span
                          className="inline-flex items-center gap-1 text-severity-critical"
                          title={rule.errors.join("; ")}
                        >
                          <ShieldAlert className="h-3 w-3" />
                          REJECTED
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
