import { createFileRoute } from "@tanstack/react-router";
import {
  fetchDashboard,
  fetchInterfaces,
  fetchTopology,
  startEngine,
  stopEngine,
} from "@/lib/api.functions";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  Activity,
  AlertTriangle,
  Wifi,
  Play,
  Square,
  ChevronDown,
  Radar,
  Circle,
  ArrowUpRight,
  ArrowDownRight,
  Target,
  Crosshair,
  Loader2,
} from "lucide-react";
import { useEffect, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import type {
  Alert,
  DashboardData,
  Entity,
  NetworkInterface,
  ProtocolEntry,
  TimelinePoint,
  TopologyEdge,
  TopologyNode,
} from "@/types/watchtower";
import { useSensorScope } from "@/components/useSensorScope";

export const Route = createFileRoute("/")({
  loader: async () => fetchDashboard(),
  component: CommandCenter,
});

function formatBytes(bytes: number) {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${(bytes / 1e3).toFixed(1)} KB`;
}

function useClock() {
  const [now, setNow] = useState<string>("");
  useEffect(() => {
    const tick = () => setNow(new Date().toISOString().replace("T", " ").slice(0, 19) + "Z");
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

function CommandCenter() {
  const initialData = Route.useLoaderData() as DashboardData;
  const [data, setData] = useState(initialData);
  const { selectedNodeId } = useSensorScope();
  const { health, stats, timeline, protocols, ports, alerts, entities, topology, pipeline } = data;
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>(data.interfaces);
  const [adaptersOpen, setAdaptersOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [captureBusy, setCaptureBusy] = useState<string | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const clock = useClock();

  useEffect(() => {
    void Promise.all([
      fetchDashboard({ data: { node: selectedNodeId } }),
      selectedNodeId ? Promise.resolve([]) : fetchInterfaces(),
      fetchTopology({ data: { node: selectedNodeId } }),
    ]).then(([next, nextInterfaces, nextTopology]) => {
      setData({ ...next, interfaces: nextInterfaces, topology: nextTopology });
      setInterfaces(nextInterfaces);
      setSelectedNode(null);
    });
  }, [selectedNodeId]);

  const timelineData = timeline.map((t: TimelinePoint) => ({
    ...t,
    time: new Date(t.timestamp * 1000).toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
    }),
  }));
  const activeCount = interfaces.filter((i) => i.capturing).length;
  const totalAlerts =
    stats.alerts.critical + stats.alerts.high + stats.alerts.medium + stats.alerts.low;
  const maxPriority = Math.max(0, ...entities.map((entity) => entity.priority_score));
  const risk =
    maxPriority >= 80
      ? {
          level: "ELEVATED",
          color: "text-severity-critical",
          bg: "bg-severity-critical/10",
          border: "border-severity-critical/40",
        }
      : maxPriority >= 50
        ? {
            level: "GUARDED",
            color: "text-severity-high",
            bg: "bg-severity-high/10",
            border: "border-severity-high/40",
          }
        : maxPriority >= 20
          ? {
              level: "WATCH",
              color: "text-severity-medium",
              bg: "bg-severity-medium/10",
              border: "border-severity-medium/40",
            }
          : { level: "NOMINAL", color: "text-ok", bg: "bg-ok/10", border: "border-ok/40" };
  const topEntities = [...entities].sort((a, b) => b.risk_score - a.risk_score).slice(0, 6);

  const toggleCapture = async (id: string, capturing: boolean) => {
    setCaptureBusy(id);
    setCaptureError(null);
    try {
      if (capturing) await stopEngine({ data: { interface_id: id } });
      else await startEngine({ data: { interface_id: id } });
      setInterfaces(await fetchInterfaces());
    } catch (cause) {
      setCaptureError(cause instanceof Error ? cause.message : "Capture control failed");
      setInterfaces(await fetchInterfaces().catch(() => interfaces));
    } finally {
      setCaptureBusy(null);
    }
  };

  const degree = new Map<string, number>();
  topology.edges.forEach((edge) => {
    degree.set(edge.data.source, (degree.get(edge.data.source) || 0) + 1);
    degree.set(edge.data.target, (degree.get(edge.data.target) || 0) + 1);
  });
  const visibleNodes = [...topology.nodes]
    .sort(
      (left, right) =>
        right.data.risk - left.data.risk ||
        (degree.get(right.data.id) || 0) - (degree.get(left.data.id) || 0) ||
        left.data.id.localeCompare(right.data.id),
    )
    .slice(0, 36);
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.data.id));
  const visibleEdges = topology.edges
    .filter((edge) => visibleNodeIds.has(edge.data.source) && visibleNodeIds.has(edge.data.target))
    .slice(0, 120);
  const positions = visibleNodes.map((_: TopologyNode, i: number) => {
    const angle = i * 2.399963 - Math.PI / 2;
    const r = 45 + Math.sqrt((i + 1) / Math.max(1, visibleNodes.length)) * 155;
    return {
      x: Number((300 + Math.cos(angle) * r).toFixed(3)),
      y: Number((220 + Math.sin(angle) * r).toFixed(3)),
    };
  });
  const nodeMap = new Map<string, number>(
    visibleNodes.map((n: TopologyNode, i: number) => [n.data.id, i]),
  );
  const selected = selectedNode ? visibleNodes.find((n) => n.data.id === selectedNode) : null;

  return (
    <div className="flex flex-col min-h-screen">
      {health.status !== "ok" && (
        <div className="border-b border-severity-high/40 bg-severity-high/10 px-6 py-2 mono text-[11px] text-severity-high">
          CONTROL PLANE {health.status.toUpperCase()} ·{" "}
          {health.message || `database ${health.database}, daemon ${health.daemon}`}
        </div>
      )}
      {(pipeline.stale_analytics ||
        pipeline.pending_packets > 0 ||
        pipeline.detector_failures > 0) && (
        <div className="border-b border-severity-high/40 bg-severity-high/10 px-6 py-2 mono text-[11px] text-severity-high">
          PIPELINE {pipeline.stale_analytics ? "STALE" : pipeline.status.toUpperCase()} /{" "}
          {pipeline.pending_packets.toLocaleString("en-US")} pending /{" "}
          {pipeline.queue_lag_ms.toFixed(1)} ms lag / {pipeline.detector_failures} detector failures
        </div>
      )}
      {/* Top status bar */}
      <header className="border-b border-border bg-surface/60 backdrop-blur-sm">
        <div className="flex items-center gap-6 px-6 py-2 mono text-[11px] uppercase tracking-wider">
          <div className="flex items-center gap-2">
            <span className="section-label section-label-accent">CMD</span>
            <span className="text-foreground">/ Command Center</span>
          </div>
          <div className="text-muted-foreground" suppressHydrationWarning>
            {clock || "\u00a0"}
          </div>
          <div className="ml-auto flex items-center gap-5">
            <StatusPill label="POSTURE" value={risk.level} color={risk.color} />
            <StatusPill
              label="ADAPTERS"
              value={`${activeCount}/${interfaces.length}`}
              color="text-signal"
            />
            <StatusPill label="EVENTS/24H" value={totalAlerts.toString()} color="text-foreground" />
            <StatusPill
              label="QUEUE"
              value={`${pipeline.pending_packets.toLocaleString("en-US")} pkt`}
              color="text-foreground"
            />
          </div>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-px bg-border">
        {/* LEFT RAIL — Watchlist */}
        <div className="col-span-12 lg:col-span-3 bg-background">
          <div className="border-b border-border px-4 py-3 flex items-center justify-between">
            <div>
              <div className="section-label">/ WATCHLIST</div>
              <div className="text-sm text-foreground tracking-tight">
                Stored High-Risk Entities
              </div>
            </div>
            <Target className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <div className="divide-y divide-border">
            {topEntities.map((e: Entity, idx: number) => (
              <div key={e.ip} className="px-4 py-3 data-row cursor-pointer group">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="mono text-[10px] text-muted-foreground w-4">
                        {String(idx + 1).padStart(2, "0")}
                      </span>
                      <span className="mono text-[12px] text-signal truncate">{e.ip}</span>
                    </div>
                    <div className="ml-6 mt-0.5 text-[11px] text-foreground/80 truncate">
                      {e.hostname || "—"}
                    </div>
                    <div className="ml-6 mt-0.5 mono text-[10px] uppercase tracking-wider text-muted-foreground truncate">
                      {e.os} · {e.identity_source}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div
                      className={`numeral text-lg ${e.risk_score >= 80 ? "text-severity-critical" : e.risk_score >= 50 ? "text-severity-high" : e.risk_score >= 20 ? "text-severity-medium" : "text-signal"}`}
                    >
                      {e.risk_score.toFixed(0)}
                    </div>
                    <div className="mono text-[9px] uppercase text-muted-foreground">priority</div>
                  </div>
                </div>
                <RiskBar score={e.risk_score} />
              </div>
            ))}
          </div>

          <div className="border-t border-border px-4 py-3">
            <div className="section-label mb-2">/ PROTOCOL MIX</div>
            <div className="space-y-1.5">
              {protocols.slice(0, 5).map((p: ProtocolEntry) => (
                <div key={p.protocol}>
                  <div className="flex justify-between mono text-[11px]">
                    <span className="text-foreground">{p.protocol}</span>
                    <span className="text-muted-foreground">{p.percentage}%</span>
                  </div>
                  <div className="mt-1 h-[3px] bg-border">
                    <div className="h-full bg-signal" style={{ width: `${p.percentage}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CENTER — Graph viewport + Timeline */}
        <div className="col-span-12 lg:col-span-6 bg-background flex flex-col">
          <div className="border-b border-border px-5 py-3 flex items-center justify-between">
            <div>
              <div className="section-label">/ TOPOLOGY VIEWPORT</div>
              <div className="text-sm text-foreground tracking-tight">
                Stored Traffic Graph — {topology.nodes.length} nodes
              </div>
            </div>
            <div className="flex items-center gap-4 mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-ok pulse-dot" /> tracking
              </span>
              <Crosshair className="h-3.5 w-3.5" />
            </div>
          </div>

          <div
            className="relative grid-bg-fine bracket m-4 border border-border bg-surface/40 sweep"
            style={{ minHeight: 480 }}
          >
            {/* Concentric range rings */}
            <svg
              viewBox="0 0 600 440"
              className="w-full h-full"
              preserveAspectRatio="xMidYMid meet"
            >
              <defs>
                <radialGradient id="scan" cx="50%" cy="50%">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.06" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
                </radialGradient>
              </defs>
              <circle cx="300" cy="220" r="200" fill="url(#scan)" />
              {[90, 145, 200].map((r) => (
                <circle
                  key={r}
                  cx="300"
                  cy="220"
                  r={r}
                  fill="none"
                  stroke="#1e2a38"
                  strokeDasharray="2 4"
                />
              ))}
              <line x1="300" y1="0" x2="300" y2="440" stroke="#1e2a38" strokeDasharray="2 4" />
              <line x1="0" y1="220" x2="600" y2="440" stroke="transparent" />
              <line x1="0" y1="220" x2="600" y2="220" stroke="#1e2a38" strokeDasharray="2 4" />

              {visibleEdges.map((edge: TopologyEdge, i: number) => {
                const si = nodeMap.get(edge.data.source);
                const ti = nodeMap.get(edge.data.target);
                if (si === undefined || ti === undefined) return null;
                return (
                  <line
                    key={i}
                    x1={positions[si].x}
                    y1={positions[si].y}
                    x2={positions[ti].x}
                    y2={positions[ti].y}
                    stroke="#38bdf8"
                    strokeOpacity={0.2}
                    strokeWidth={0.8}
                  />
                );
              })}
              {visibleNodes.map((node: TopologyNode, i: number) => {
                const isSel = node.data.id === selectedNode;
                const color =
                  node.data.risk >= 80
                    ? "#ef4444"
                    : node.data.risk >= 50
                      ? "#f97316"
                      : node.data.risk >= 20
                        ? "#f0b429"
                        : "#38bdf8";
                return (
                  <g
                    key={node.data.id}
                    transform={`translate(${positions[i].x}, ${positions[i].y})`}
                    onClick={() => setSelectedNode(node.data.id)}
                    className="cursor-pointer"
                  >
                    {isSel && <circle r={16} fill="none" stroke={color} strokeOpacity={0.6} />}
                    <circle
                      r={5 + node.data.risk * 0.04}
                      fill={color}
                      fillOpacity={0.2}
                      stroke={color}
                      strokeWidth={1}
                    />
                    <circle r={2} fill={color} />
                    {(isSel || node.data.risk >= 20 || i < 8) && (
                      <text
                        y={-11}
                        textAnchor="middle"
                        fill="#cfd6e0"
                        fontSize={9}
                        fontFamily="IBM Plex Mono"
                      >
                        {node.data.label.length > 24
                          ? `${node.data.label.slice(0, 21)}...`
                          : node.data.label}
                      </text>
                    )}
                  </g>
                );
              })}
              <text x="10" y="18" fontSize={9} fontFamily="IBM Plex Mono" fill="#6b7787">
                GRID_A · 200m
              </text>
              <text x="10" y="430" fontSize={9} fontFamily="IBM Plex Mono" fill="#6b7787">
                ◉ N01
              </text>
            </svg>

            {/* HUD overlay */}
            <div className="pointer-events-none absolute top-2 right-3 mono text-[9px] uppercase tracking-wider text-signal/70">
              SOURCE {stats.source}
            </div>
            <div className="pointer-events-none absolute bottom-2 left-3 mono text-[9px] uppercase tracking-wider text-muted-foreground">
              {selected
                ? `TGT: ${selected.data.label} / PRIORITY ${selected.data.risk}`
                : "SELECT NODE ▸"}
            </div>
          </div>

          {/* Timeline */}
          <div className="border-t border-border px-5 py-3">
            <div className="flex items-baseline justify-between mb-2">
              <div>
                <div className="section-label">/ PACKET VELOCITY</div>
                <div className="text-sm text-foreground tracking-tight">24h Signal</div>
              </div>
              <div className="numeral text-2xl text-foreground">
                {stats.total_packets.toLocaleString("en-US")}
                <span className="ml-1 mono text-[10px] uppercase text-muted-foreground">pkt</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={130}>
              <AreaChart data={timelineData} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="sig" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#6b7787", fontSize: 9, fontFamily: "IBM Plex Mono" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis hide />
                <Tooltip
                  contentStyle={{
                    background: "#10151c",
                    border: "1px solid #1e2a38",
                    borderRadius: 3,
                    color: "#cfd6e0",
                    fontFamily: "IBM Plex Mono",
                    fontSize: 11,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="packets_per_sec"
                  stroke="#38bdf8"
                  fill="url(#sig)"
                  strokeWidth={1.5}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* RIGHT RAIL — Feeds */}
        <div className="col-span-12 lg:col-span-3 bg-background flex flex-col">
          <div className={`border-b border-border px-4 py-3 ${risk.bg}`}>
            <div className="flex items-center justify-between">
              <div className="section-label">/ INVESTIGATION POSTURE</div>
              <Radar className={`h-3.5 w-3.5 ${risk.color}`} />
            </div>
            <div className={`mt-1 numeral text-2xl ${risk.color}`}>{risk.level}</div>
            <div className="mt-0.5 mono text-[10px] uppercase tracking-wider text-muted-foreground">
              peak priority {maxPriority.toFixed(0)} / 100
            </div>
          </div>

          {/* Metrics stack */}
          <div className="divide-y divide-border">
            <MetricRow label="FLOWS" value={stats.total_flows.toLocaleString("en-US")} />
            <MetricRow label="HOSTS" value={stats.active_hosts.toString()} />
            <MetricRow label="VOLUME" value={formatBytes(stats.total_bytes)} />
            <MetricRow
              label="TOP PORT"
              value={ports[0] ? `${ports[0].port} ${ports[0].service}` : "—"}
              delta={ports[0] ? ports[0].count.toLocaleString("en-US") : ""}
            />
          </div>

          {/* Alert feed */}
          <div className="flex-1 border-t border-border">
            <div className="border-b border-border px-4 py-2 flex items-center justify-between">
              <div className="section-label">/ STORED INCIDENT FEED</div>
              <a
                href="/alerts"
                className="mono text-[10px] uppercase tracking-wider text-signal hover:text-foreground"
              >
                ALL ▸
              </a>
            </div>
            <div className="divide-y divide-border">
              {alerts.slice(0, 8).map((alert: Alert) => (
                <a key={alert.id} href="/alerts" className="block px-4 py-2.5 data-row">
                  <div className="flex items-start gap-2">
                    <span
                      className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${
                        alert.severity === "CRITICAL"
                          ? "bg-severity-critical"
                          : alert.severity === "HIGH"
                            ? "bg-severity-high"
                            : alert.severity === "MEDIUM"
                              ? "bg-severity-medium"
                              : "bg-severity-low"
                      }`}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] text-foreground truncate">{alert.type}</span>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      <div className="mono text-[10px] text-muted-foreground truncate mt-0.5">
                        {alert.src_ip} → {alert.dst_ip}
                      </div>
                    </div>
                  </div>
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Adapters — bottom drawer */}
      <div className="border-t border-border bg-surface/60">
        <button
          onClick={() => setAdaptersOpen(!adaptersOpen)}
          className="w-full flex items-center justify-between px-6 py-2.5 hover:bg-signal/[0.03] transition-colors"
        >
          <div className="flex items-center gap-3">
            <Wifi className="h-3.5 w-3.5 text-signal" />
            <span className="text-[13px] text-foreground tracking-tight">Capture Adapters</span>
            <span className="mono text-[10px] uppercase tracking-wider text-muted-foreground">
              {activeCount}/{interfaces.length} active
            </span>
          </div>
          <ChevronDown
            className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${adaptersOpen ? "rotate-180" : ""}`}
          />
        </button>
        {adaptersOpen && (
          <div className="border-t border-border">
            {captureError && (
              <div className="border-b border-severity-critical/30 bg-severity-critical/10 px-6 py-2 mono text-[10px] text-severity-critical">
                {captureError}
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-px bg-border">
              {interfaces.map((iface) => (
                <div key={iface.id} className="bg-background p-4">
                  <div className="flex items-start justify-between">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Circle
                          className={`h-2 w-2 shrink-0 ${iface.status === "up" ? "fill-ok text-ok" : "fill-muted-foreground text-muted-foreground"}`}
                        />
                        <span className="text-[13px] text-foreground truncate tracking-tight">
                          {iface.name}
                        </span>
                      </div>
                      <div className="mt-0.5 mono text-[10px] text-muted-foreground truncate">
                        {iface.ipv4 ?? iface.mac}
                      </div>
                      <div className="mt-1 mono text-[10px] uppercase tracking-wider">
                        <span className={iface.capturing ? "text-ok" : "text-muted-foreground"}>
                          {iface.capturing ? "● CAPTURING" : "○ IDLE"}
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => toggleCapture(iface.id, iface.capturing)}
                      disabled={
                        captureBusy === iface.id ||
                        iface.status !== "up" ||
                        health.daemon !== "online"
                      }
                      title={
                        health.daemon !== "online"
                          ? "Start the WatchTower daemon first"
                          : iface.capturing
                            ? "Stop capture"
                            : "Start capture"
                      }
                      className={`shrink-0 grid h-7 w-7 place-items-center border transition-colors ${
                        iface.capturing
                          ? "border-severity-critical/40 text-severity-critical hover:bg-severity-critical/10"
                          : "border-signal/40 text-signal hover:bg-signal/10"
                      } disabled:cursor-not-allowed disabled:opacity-30`}
                    >
                      {captureBusy === iface.id ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : iface.capturing ? (
                        <Square className="h-3 w-3" strokeWidth={2} />
                      ) : (
                        <Play className="h-3 w-3" strokeWidth={2} />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatusPill({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-muted-foreground">{label}</span>
      <span className={color}>{value}</span>
    </span>
  );
}

function MetricRow({
  label,
  value,
  delta,
  up,
}: {
  label: string;
  value: string;
  delta?: string;
  up?: boolean;
}) {
  return (
    <div className="px-4 py-3 flex items-center justify-between">
      <div>
        <div className="section-label">{label}</div>
        <div className="numeral text-lg text-foreground mt-0.5">{value}</div>
      </div>
      {delta && (
        <div
          className={`flex items-center gap-1 mono text-[11px] ${up ? "text-ok" : "text-muted-foreground"}`}
        >
          {up === true ? (
            <ArrowUpRight className="h-3 w-3" />
          ) : up === false ? (
            <ArrowDownRight className="h-3 w-3" />
          ) : null}
          {delta}
        </div>
      )}
    </div>
  );
}

function RiskBar({ score }: { score: number }) {
  const color =
    score >= 80
      ? "bg-severity-critical"
      : score >= 50
        ? "bg-severity-high"
        : score >= 20
          ? "bg-severity-medium"
          : "bg-signal";
  return (
    <div className="mt-2 ml-6 h-[2px] bg-border">
      <div className={`h-full ${color}`} style={{ width: `${score}%` }} />
    </div>
  );
}
