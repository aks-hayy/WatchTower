import { createFileRoute, Link } from "@tanstack/react-router";
import { fetchEntities } from "@/lib/api.functions";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { useSensorScope } from "@/components/useSensorScope";
import type { CursorPage, Entity } from "@/types/watchtower";

export const Route = createFileRoute("/entities/")({
  head: () => ({ meta: [{ title: "Entities — Watchtower" }] }),
  loader: async () => fetchEntities({ data: { source: "live", limit: 100 } }),
  component: EntitiesPage,
});

function getRiskColor(s: number) {
  if (s >= 80) return "text-severity-critical";
  if (s >= 50) return "text-severity-high";
  if (s >= 20) return "text-severity-medium";
  return "text-signal";
}
function getRiskLevel(s: number) {
  if (s >= 80) return "CRITICAL";
  if (s >= 50) return "HIGH";
  if (s >= 20) return "MEDIUM";
  return "LOW";
}

function EntitiesPage() {
  const initialPage = Route.useLoaderData() as CursorPage<Entity>;
  const [page, setPage] = useState(initialPage);
  const [entities, setEntities] = useState(initialPage.items);
  const [cursorHistory, setCursorHistory] = useState<(string | undefined)[]>([undefined]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const { selectedNodeId } = useSensorScope();
  const [search, setSearch] = useState("");
  const filtered = entities.filter((e: Entity) =>
    [e.ip, e.hostname, e.user, e.os, e.mac].some((f) =>
      f?.toLowerCase().includes(search.toLowerCase()),
    ),
  );

  useEffect(() => {
    void load(undefined, true);
    // load owns scope transitions and cursor reset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNodeId]);

  async function load(cursor?: string, reset = false) {
    const result = await fetchEntities({
      data: {
        source: selectedNodeId ? undefined : "live",
        node: selectedNodeId,
        limit: 100,
        cursor,
      },
    });
    setPage(result);
    setEntities(result.items);
    if (reset) {
      setCursorHistory([undefined]);
      setCursorIndex(0);
    }
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="px-6 py-3 flex items-center gap-6 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">ENT</span>
          <span className="text-foreground">/ Identity Registry</span>
          <span className="text-muted-foreground">{entities.length} assessed on this page</span>
          <div className="ml-auto relative w-80">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="text"
              placeholder="filter ip / host / user / os"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-background border border-border pl-8 pr-3 py-1.5 mono text-[11px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-signal"
            />
          </div>
        </div>
      </header>

      <div className="px-6 py-5">
        <div className="panel overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface-2">
                {["IP", "HOSTNAME", "USER", "OS", "SCOPE", "PRIORITY", "CONFIDENCE", "STATE"].map(
                  (h) => (
                    <th key={h} className="text-left px-4 py-2 section-label">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {filtered.map((e: Entity) => (
                <tr key={e.ip} className="border-b border-border/60 data-row">
                  <td className="px-4 py-2.5 mono text-[12px] text-signal">
                    <Link
                      to="/entities/$ip"
                      params={{ ip: e.ip }}
                      className="hover:text-foreground"
                    >
                      {e.ip}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-[13px] text-foreground tracking-tight">
                    {e.hostname || "—"}
                  </td>
                  <td className="px-4 py-2.5 mono text-[12px] text-muted-foreground">
                    {e.user || "—"}
                  </td>
                  <td className="px-4 py-2.5 mono text-[12px] text-muted-foreground">{e.os}</td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-[10px] uppercase tracking-wider text-muted-foreground border border-border px-1.5 py-0.5">
                      {e.source}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className={`numeral text-base ${getRiskColor(e.risk_score)}`}>
                        {e.risk_score.toFixed(0)}
                      </span>
                      <div className="w-16 h-[3px] bg-border">
                        <div
                          className={`h-full ${getRiskColor(e.risk_score).replace("text-", "bg-")}`}
                          style={{ width: `${e.risk_score}%` }}
                        />
                      </div>
                      <SeverityBadge severity={getRiskLevel(e.risk_score)} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5 mono text-[12px] text-muted-foreground">
                    {Math.round(e.assessment_confidence * 100)}%
                  </td>
                  <td className="px-4 py-2.5 mono text-[10px] uppercase text-muted-foreground">
                    {e.processing_completeness}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex items-center justify-between">
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
