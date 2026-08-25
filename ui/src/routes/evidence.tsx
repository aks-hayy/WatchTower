import { createFileRoute } from "@tanstack/react-router";
import { fetchCarvedFiles } from "@/lib/api.functions";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { CarvedFile } from "@/types/watchtower";

export const Route = createFileRoute("/evidence")({
  head: () => ({ meta: [{ title: "Evidence — Watchtower" }] }),
  loader: async () => (await fetchCarvedFiles({ data: {} })) as CarvedFile[],
  component: EvidencePage,
});

function fmtSize(b: number) {
  return b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${(b / 1e3).toFixed(1)} KB`;
}

function EvidencePage() {
  const files = Route.useLoaderData() as CarvedFile[];
  const malicious = files.filter((f: CarvedFile) => f.vt_status === "malicious").length;

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="px-6 py-3 flex items-center gap-6 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">EVD</span>
          <span className="text-foreground">/ Evidence Vault</span>
          <span className="text-muted-foreground">
            {files.length} artifacts · {malicious} flagged
          </span>
        </div>
      </header>

      <div className="p-6">
        <div className="panel overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface-2">
                {[
                  "#",
                  "FILENAME",
                  "TYPE",
                  "SIZE",
                  "MD5",
                  "SOURCE",
                  "VT SCORE",
                  "STATUS",
                  "SEEN",
                ].map((h) => (
                  <th key={h} className="text-left px-4 py-2 section-label">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {files.map((f: CarvedFile) => (
                <tr key={f.id} className="border-b border-border/60 data-row">
                  <td className="px-4 py-2.5 mono text-[11px] text-muted-foreground">
                    {String(f.id).padStart(4, "0")}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      {f.vt_status === "malicious" ? (
                        <ShieldAlert className="h-3.5 w-3.5 text-severity-critical" />
                      ) : (
                        <ShieldCheck className="h-3.5 w-3.5 text-ok" />
                      )}
                      <span className="text-[13px] text-foreground tracking-tight">
                        {f.filename}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 mono text-[11px] text-muted-foreground uppercase">
                    {f.filetype}
                  </td>
                  <td className="px-4 py-2.5 mono text-[11px] text-foreground">
                    {fmtSize(f.size)}
                  </td>
                  <td className="px-4 py-2.5 mono text-[11px] text-muted-foreground truncate max-w-[220px]">
                    {f.md5}
                  </td>
                  <td className="px-4 py-2.5 mono text-[11px] text-signal">{f.source_ip}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`numeral text-sm ${f.vt_status === "malicious" ? "text-severity-critical" : "text-ok"}`}
                    >
                      {f.vt_score}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-flex items-center px-1.5 py-0.5 mono text-[10px] uppercase tracking-wider ${f.vt_status === "malicious" ? "chip-critical" : "chip-low"}`}
                    >
                      {f.vt_status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 mono text-[11px] text-muted-foreground">
                    {new Date(f.timestamp * 1000).toLocaleString("en-GB")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
