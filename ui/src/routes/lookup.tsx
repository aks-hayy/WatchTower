import { createFileRoute } from "@tanstack/react-router";
import { Loader2, Search } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { LookupIntelPanel } from "@/components/LookupIntelPanel";
import { fetchLookup } from "@/lib/api.functions";
import type { IpLookup } from "@/types/watchtower";
import { useSensorScope } from "@/components/useSensorScope";

export const Route = createFileRoute("/lookup")({
  head: () => ({ meta: [{ title: "IP Lookup - Watchtower" }] }),
  validateSearch: (search: Record<string, unknown>) => ({
    ip: typeof search.ip === "string" ? search.ip : "",
  }),
  component: LookupPage,
});

function LookupPage() {
  const { selectedNodeId } = useSensorScope();
  const search = Route.useSearch();
  const [ip, setIp] = useState(search.ip || "");
  const [lookup, setLookup] = useState<IpLookup | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const runLookup = useCallback(
    async (target: string) => {
      const trimmed = target.trim();
      if (!trimmed) return;
      setBusy(true);
      setMessage(null);
      try {
        const result = await fetchLookup({ data: { ip: trimmed, node: selectedNodeId } });
        setLookup(result);
      } catch (error) {
        setLookup(null);
        setMessage(error instanceof Error ? error.message : "Lookup failed");
      } finally {
        setBusy(false);
      }
    },
    [selectedNodeId],
  );

  useEffect(() => {
    if (search.ip) {
      setIp(search.ip);
      void runLookup(search.ip);
    }
  }, [runLookup, search.ip]);

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-5 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">LKP</span>
          <span className="text-foreground">/ IP Lookup</span>
          <span className="text-muted-foreground">passive identity and enrichment</span>
        </div>
      </header>

      <div className="space-y-5 p-4 md:p-6">
        <section className="panel p-4">
          <form
            className="grid gap-3 md:grid-cols-[1fr_auto]"
            onSubmit={(event) => {
              event.preventDefault();
              void runLookup(ip);
            }}
          >
            <label className="relative block">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={ip}
                onChange={(event) => setIp(event.target.value)}
                placeholder="enter IPv4 or IPv6 address"
                className="h-10 w-full border border-border bg-background pl-10 pr-3 mono text-[12px] text-foreground placeholder:text-muted-foreground focus:border-signal focus:outline-none"
              />
            </label>
            <button
              type="submit"
              disabled={busy || !ip.trim()}
              className="flex h-10 min-w-32 items-center justify-center gap-2 border border-signal/60 px-4 mono text-[10px] uppercase text-signal disabled:opacity-40"
            >
              {busy ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Search className="h-3.5 w-3.5" />
              )}
              Lookup
            </button>
          </form>
          {message && (
            <div className="mt-3 border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-[12px] text-severity-high">
              {message}
            </div>
          )}
        </section>

        {lookup ? (
          <LookupIntelPanel lookup={lookup} />
        ) : (
          <section className="panel p-8 text-center">
            <div className="section-label section-label-accent">/ READY</div>
            <div className="mt-2 text-2xl text-foreground">Enter an IP to build context</div>
            <p className="mx-auto mt-3 max-w-2xl text-[13px] leading-relaxed text-muted-foreground">
              WatchTower will combine passive identity, stored traffic, observed names, local asset
              role, reverse DNS, GeoIP, ASN, service usage, peers, and known context gaps.
            </p>
          </section>
        )}
      </div>
    </div>
  );
}
