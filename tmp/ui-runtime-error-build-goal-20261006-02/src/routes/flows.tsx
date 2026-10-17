import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, Database, Filter, RefreshCw, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSensorScope } from "@/components/useSensorScope";
import {
  fetchFlowDetail,
  fetchFlows,
  fetchInterfaces,
  fetchMeshNodes,
  fetchSessions,
} from "@/lib/api.functions";
import type {
  CaptureSession,
  CursorPage,
  Flow,
  JsonObject,
  NetworkInterface,
  SensorNode,
} from "@/types/watchtower";

export const Route = createFileRoute("/flows")({
  head: () => ({ meta: [{ title: "Flows - Watchtower" }] }),
  validateSearch: (search: Record<string, unknown>) => ({
    flow: Number.isFinite(Number(search.flow)) ? Number(search.flow) : undefined,
  }),
  loader: async () => {
    const [page, interfaces, sessions, nodes] = await Promise.all([
      fetchFlows({ data: { source: "live", limit: 100 } }),
      fetchInterfaces(),
      fetchSessions({ data: { limit: 500 } }),
      fetchMeshNodes({ data: { limit: 100 } }),
    ]);
    return { page, interfaces, sessions, nodes };
  },
  component: FlowsPage,
});

function formatEndpoint(ip: string, port: number) {
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return port ? `${host}:${port}` : host;
}

function formatBytes(bytes: number) {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function processAttribution(metadata: JsonObject) {
  const value = metadata.process_attribution;
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function FlowsPage() {
  const initial = Route.useLoaderData() as {
    page: CursorPage<Flow>;
    interfaces: NetworkInterface[];
    sessions: CaptureSession[];
    nodes: SensorNode[];
  };
  const [page, setPage] = useState(initial.page);
  const [flows, setFlows] = useState(initial.page.items);
  const [cursorHistory, setCursorHistory] = useState<(string | undefined)[]>([undefined]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const searchState = Route.useSearch();
  const navigate = Route.useNavigate();
  const { selectedNodeId } = useSensorScope();
  const [interfaceName, setInterfaceName] = useState("");
  const [session, setSession] = useState("");
  const [node, setNode] = useState(selectedNodeId || "");
  const [protocol, setProtocol] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Flow | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!searchState.flow) {
      setSelected(null);
      return;
    }
    void fetchFlowDetail({ data: { id: searchState.flow } })
      .then(setSelected)
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Flow detail failed"));
  }, [searchState.flow]);

  useEffect(() => {
    const next = selectedNodeId || "";
    setNode(next);
    setSession("");
    void refresh({ node: next, session: "" });
    // refresh is intentionally scoped to the global sensor transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNodeId]);

  const visibleSessions = useMemo(
    () =>
      initial.sessions.filter(
        (item) =>
          (!interfaceName || item.interface === interfaceName) &&
          (!node || item.sensor_node_id === node),
      ),
    [initial.sessions, interfaceName, node],
  );
  const visibleFlows = useMemo(() => {
    const needle = search.toLowerCase();
    return flows.filter(
      (flow) =>
        !needle ||
        [
          flow.src_ip,
          flow.dst_ip,
          flow.flow_id,
          flow.source,
          flow.src_identity?.identity_label || "",
          flow.dst_identity?.identity_label || "",
        ].some((value) => value.toLowerCase().includes(needle)),
    );
  }, [flows, search]);

  async function refresh(next?: {
    interfaceName?: string;
    session?: string;
    protocol?: string;
    node?: string;
    cursor?: string;
    retainHistory?: boolean;
  }) {
    const nextInterface = next?.interfaceName ?? interfaceName;
    const nextSession = next?.session ?? session;
    const nextProtocol = next?.protocol ?? protocol;
    const nextNode = next?.node ?? node;
    setLoading(true);
    setError("");
    try {
      const result = await fetchFlows({
        data: {
          source: nextNode ? undefined : "live",
          interface: nextInterface || undefined,
          session: nextSession || undefined,
          protocol: nextProtocol || undefined,
          node: nextNode || undefined,
          limit: 100,
          cursor: next?.cursor,
        },
      });
      setPage(result);
      setFlows(result.items);
      if (!next?.retainHistory) {
        setCursorHistory([undefined]);
        setCursorIndex(0);
      }
      void navigate({ search: (previous) => ({ ...previous, flow: undefined }), replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Flow query failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-6 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">FLW</span>
          <span className="text-foreground">/ Flow Explorer</span>
          <span className="text-muted-foreground">
            {visibleFlows.length.toLocaleString("en-US")} records
          </span>
          <span className="ml-auto text-muted-foreground">
            {node ? `node ${node.slice(0, 8)}` : "source live"}
          </span>
        </div>
      </header>

      <div className="border-b border-border bg-surface/30 px-6 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <select
            aria-label="Sensor node"
            value={node}
            onChange={(event) => {
              const value = event.target.value;
              setNode(value);
              setSession("");
              void refresh({ node: value, session: "" });
            }}
            className="h-8 max-w-56 border border-border bg-background px-2 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
          >
            <option value="">Local sensor</option>
            {initial.nodes.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} / {item.status}
              </option>
            ))}
          </select>
          <select
            aria-label="Capture interface"
            value={interfaceName}
            onChange={(event) => {
              const value = event.target.value;
              setInterfaceName(value);
              setSession("");
              void refresh({ interfaceName: value, session: "" });
            }}
            className="h-8 border border-border bg-background px-2 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
          >
            <option value="">All interfaces</option>
            {initial.interfaces
              .filter((item) => item.source_type === "network")
              .map((item) => (
                <option key={item.id} value={item.name}>
                  {item.name}
                </option>
              ))}
          </select>
          <select
            aria-label="Capture session"
            value={session}
            onChange={(event) => {
              setSession(event.target.value);
              void refresh({ session: event.target.value });
            }}
            className="h-8 max-w-64 border border-border bg-background px-2 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
          >
            <option value="">All sessions</option>
            {visibleSessions.map((item) => (
              <option key={item.id} value={item.id}>
                {item.id} · {item.status}
              </option>
            ))}
          </select>
          <select
            aria-label="Protocol"
            value={protocol}
            onChange={(event) => {
              setProtocol(event.target.value);
              void refresh({ protocol: event.target.value });
            }}
            className="h-8 border border-border bg-background px-2 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
          >
            <option value="">All protocols</option>
            {["TCP", "UDP", "ICMP", "ICMPV6"].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
          <div className="relative min-w-56 flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="filter endpoint or source"
              className="h-8 w-full border border-border bg-background pl-8 pr-3 mono text-[11px] text-foreground placeholder:text-muted-foreground focus:border-signal focus:outline-none"
            />
          </div>
          <button
            onClick={() => void refresh()}
            disabled={loading}
            title="Refresh flows"
            className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
        {error && (
          <div className="mt-2 mono text-[11px] text-severity-high">QUERY ERROR · {error}</div>
        )}
      </div>

      <div className="grid grid-cols-12 gap-px bg-border">
        <div
          className={`${selected ? "col-span-12 xl:col-span-9" : "col-span-12"} min-w-0 bg-background p-5`}
        >
          <div className="panel overflow-x-auto">
            <table className="w-full min-w-[1080px] text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-2">
                  {[
                    "LAST SEEN",
                    "SOURCE ENDPOINT",
                    "DESTINATION ENDPOINT",
                    "PROTO",
                    "PACKETS",
                    "BYTES",
                    "INTERFACE",
                    "SESSION",
                    "CORE",
                  ].map((heading) => (
                    <th key={heading} className="px-3 py-2 text-left section-label">
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleFlows.map((flow) => (
                  <tr
                    key={`${flow.id}-${flow.capture_session_id || flow.source}`}
                    onClick={() => {
                      void navigate({ search: (previous) => ({ ...previous, flow: flow.id }) });
                    }}
                    className={`cursor-pointer border-b border-border/60 data-row ${selected?.id === flow.id ? "bg-signal/[0.06]" : ""}`}
                  >
                    <td className="whitespace-nowrap px-3 py-2.5 mono text-[10px] text-muted-foreground">
                      {flow.last_seen
                        ? new Date(flow.last_seen * 1000).toLocaleString("en-GB")
                        : "—"}
                    </td>
                    <td className="px-3 py-2.5 mono text-[11px] text-signal">
                      {formatEndpoint(flow.src_ip, flow.src_port)}
                    </td>
                    <td className="px-3 py-2.5 mono text-[11px] text-foreground">
                      {formatEndpoint(flow.dst_ip, flow.dst_port)}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="border border-border px-1.5 py-0.5 mono text-[10px] text-foreground">
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-right numeral text-foreground">
                      {flow.packet_count.toLocaleString("en-US")}
                    </td>
                    <td className="px-3 py-2.5 text-right mono text-[11px] text-muted-foreground">
                      {formatBytes(flow.byte_count)}
                    </td>
                    <td className="px-3 py-2.5 mono text-[10px] text-foreground">
                      {flow.capture_interface || "unknown"}
                    </td>
                    <td
                      className="max-w-44 truncate px-3 py-2.5 mono text-[10px] text-muted-foreground"
                      title={flow.capture_session_id || ""}
                    >
                      {flow.capture_session_id || "legacy"}
                    </td>
                    <td className="px-3 py-2.5 mono text-[10px] uppercase text-muted-foreground">
                      {flow.capture_backend || "legacy"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!loading && visibleFlows.length === 0 && (
              <div className="grid min-h-48 place-items-center mono text-[11px] uppercase tracking-wider text-muted-foreground">
                No flows match the active provenance filters
              </div>
            )}
          </div>
          <div className="mt-3 flex items-center justify-between">
            <button
              disabled={cursorIndex === 0 || loading}
              onClick={() => {
                const nextIndex = cursorIndex - 1;
                setCursorIndex(nextIndex);
                void refresh({
                  cursor: cursorHistory[nextIndex],
                  retainHistory: true,
                });
              }}
              className="border border-border px-3 py-2 mono text-[10px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-30"
            >
              Previous 100
            </button>
            <span className="mono text-[10px] uppercase text-muted-foreground">
              Page {cursorIndex + 1} / {flows.length} records
            </span>
            <button
              disabled={!page.next_cursor || loading}
              onClick={() => {
                if (!page.next_cursor) return;
                const nextHistory = cursorHistory.slice(0, cursorIndex + 1);
                nextHistory.push(page.next_cursor);
                setCursorHistory(nextHistory);
                setCursorIndex(cursorIndex + 1);
                void refresh({ cursor: page.next_cursor, retainHistory: true });
              }}
              className="border border-border px-3 py-2 mono text-[10px] uppercase text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-30"
            >
              Next 100
            </button>
          </div>
        </div>

        {selected && (
          <aside className="col-span-12 bg-background xl:col-span-3">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div>
                <div className="section-label">/ FLOW DETAIL</div>
                <div className="text-sm text-foreground">Evidence #{selected.id}</div>
              </div>
              <button
                onClick={() => {
                  void navigate({ search: (previous) => ({ ...previous, flow: undefined }) });
                }}
                title="Close flow detail"
                className="grid h-7 w-7 place-items-center text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-5 p-4">
              <div className="space-y-2">
                <Detail
                  label="SOURCE"
                  value={formatEndpoint(selected.src_ip, selected.src_port)}
                  accent
                />
                <Detail
                  label="DESTINATION"
                  value={formatEndpoint(selected.dst_ip, selected.dst_port)}
                />
                <IdentityDetail label="SOURCE IDENTITY" identity={selected.src_identity} accent />
                <IdentityDetail label="DESTINATION IDENTITY" identity={selected.dst_identity} />
                <Detail label="PROTOCOL" value={selected.protocol} />
                <Detail label="DURATION" value={`${selected.duration.toFixed(3)}s`} />
                <ProcessAttributionDetail
                  attribution={processAttribution(selected.l7_metadata || {})}
                />
                <Detail
                  label="PROVENANCE"
                  value={`${selected.capture_interface || "unknown"} · ${selected.capture_backend || "legacy"}`}
                />
              </div>
              <div className="border-t border-border pt-4">
                <div className="section-label mb-2">/ INVESTIGATE</div>
                <div className="space-y-2">
                  <Link
                    to="/entities/$ip"
                    params={{ ip: selected.src_ip }}
                    className="flex items-center justify-between border border-border px-3 py-2 mono text-[10px] uppercase text-foreground hover:border-signal hover:text-signal"
                  >
                    Source asset <ArrowRight className="h-3 w-3" />
                  </Link>
                  <Link
                    to="/entities/$ip"
                    params={{ ip: selected.dst_ip }}
                    className="flex items-center justify-between border border-border px-3 py-2 mono text-[10px] uppercase text-foreground hover:border-signal hover:text-signal"
                  >
                    Destination asset <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>
              </div>
              <div className="border-t border-border pt-4">
                <div className="mb-2 flex items-center gap-2 section-label">
                  <Database className="h-3 w-3" /> L7 METADATA
                </div>
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all border border-border bg-surface p-3 mono text-[10px] leading-relaxed text-muted-foreground">
                  {Object.keys(selected.l7_metadata || {}).length
                    ? JSON.stringify(selected.l7_metadata, null, 2)
                    : "No parser metadata stored for this flow."}
                </pre>
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

function IdentityDetail({
  label,
  identity,
  accent = false,
}: {
  label: string;
  identity?: Flow["src_identity"];
  accent?: boolean;
}) {
  if (!identity) {
    return (
      <Detail
        label={label}
        value="Identity card unavailable for this capture scope"
        accent={accent}
      />
    );
  }
  const confidence = `${Math.round(Math.max(0, identity.confidence) * 100)}%`;
  return (
    <div>
      <div className="section-label">{label}</div>
      <div
        className={`mt-0.5 break-words text-[11px] ${accent ? "text-signal" : "text-foreground"}`}
      >
        {identity.identity_label}
      </div>
      <div className="mt-1 mono text-[10px] uppercase text-muted-foreground">
        {identity.identity_state || identity.identity_type.replaceAll("_", " ")} / {confidence} /{" "}
        {identity.verification}
      </div>
      {identity.next_action && (
        <div className="mt-1 text-[10px] text-muted-foreground">Next: {identity.next_action}</div>
      )}
    </div>
  );
}

function ProcessAttributionDetail({ attribution }: { attribution: JsonObject | null }) {
  if (!attribution) {
    return (
      <Detail label="ENDPOINT PROCESS" value="No endpoint attribution recorded for this flow" />
    );
  }
  const services = Array.isArray(attribution.service_names)
    ? attribution.service_names.filter((value): value is string => typeof value === "string")
    : [];
  const label = attribution.image
    ? `${String(attribution.image)}${attribution.pid ? ` (PID ${String(attribution.pid)})` : ""}`
    : String(attribution.reason || "Endpoint process unavailable");
  const provenance = `${String(attribution.provenance || "unattributed").replaceAll("_", " ")} / ${Math.round(Number(attribution.confidence || 0) * 100)}%`;
  return (
    <div>
      <Detail label="ENDPOINT PROCESS" value={label} />
      <Detail label="ATTRIBUTION" value={provenance} />
      {services.length > 0 && <Detail label="WINDOWS SERVICE" value={services.join(", ")} />}
    </div>
  );
}

function Detail({
  label,
  value,
  accent = false,
}: {
  label: string;
  value: string;
  accent?: boolean;
}) {
  return (
    <div>
      <div className="section-label">{label}</div>
      <div
        className={`mt-0.5 break-all mono text-[11px] ${accent ? "text-signal" : "text-foreground"}`}
      >
        {value}
      </div>
    </div>
  );
}
