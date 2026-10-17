import { createFileRoute, useNavigate } from "@tanstack/react-router";
import cytoscape, { type Core } from "cytoscape";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Loader2,
  Network,
  Play,
  Plus,
  RefreshCw,
  RotateCw,
  ServerCog,
  ShieldAlert,
  Square,
  Trash2,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useSensorScope } from "@/components/useSensorScope";
import {
  createMeshEnrollment,
  fetchFleetSummary,
  meshControllerAction,
  revokeMeshNode,
  setupMeshController,
} from "@/lib/api.functions";
import { stepUpWithPin } from "@/lib/auth";
import type { FleetNode, FleetSummary } from "@/types/watchtower";

export const Route = createFileRoute("/fleet")({
  head: () => ({ meta: [{ title: "Sensor Fleet - Watchtower" }] }),
  loader: async () => fetchFleetSummary(),
  component: FleetPage,
});

function FleetPage() {
  const initial = Route.useLoaderData() as FleetSummary;
  const [fleet, setFleet] = useState(initial);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [setupOpen, setSetupOpen] = useState(!initial.controller.authority_ready);
  const [mode, setMode] = useState<"local" | "vpn" | "public">("vpn");
  const [address, setAddress] = useState("");
  const [nodeName, setNodeName] = useState("");
  const [joinCode, setJoinCode] = useState("");
  const [stepUpPin, setStepUpPin] = useState("");
  const pending = useRef<(() => Promise<unknown>) | null>(null);
  const { setScope } = useSensorScope();
  const navigate = useNavigate();

  const refresh = async () => setFleet(await fetchFleetSummary());
  const guarded = async (label: string, operation: () => Promise<unknown>) => {
    setBusy(label);
    setNotice(null);
    try {
      await operation();
      pending.current = null;
      setStepUpPin("");
      await refresh();
      setNotice({ kind: "ok", text: `${label} completed.` });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : `${label} failed`;
      if (/step.?up|recent authentication|authentication proof/i.test(message)) {
        pending.current = operation;
        setNotice({
          kind: "error",
          text: "Re-authenticate once to complete this sensitive change.",
        });
      } else {
        setNotice({ kind: "error", text: message });
      }
    } finally {
      setBusy(null);
    }
  };

  const retry = async () => {
    setBusy("re-authentication");
    try {
      await stepUpWithPin(stepUpPin);
      const operation = pending.current;
      pending.current = null;
      if (operation) await operation();
      await refresh();
      setStepUpPin("");
      setNotice({ kind: "ok", text: "Operator verified and operation completed." });
    } catch (cause) {
      setNotice({
        kind: "error",
        text: cause instanceof Error ? cause.message : "Re-authentication failed",
      });
    } finally {
      setBusy(null);
    }
  };

  const selectNode = (node: FleetNode) => {
    setScope(node.status === "local" ? "local" : node.id);
    void navigate({ to: "/" });
  };

  const configuration = (fleet.controller.configuration || {}) as Record<string, unknown>;
  const runtime = (fleet.controller.runtime || {}) as Record<string, unknown>;
  const controllerRunning = Boolean(runtime.running);

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-surface/60">
        <div className="flex items-center gap-6 px-6 py-3 mono text-[11px] uppercase tracking-wider">
          <span className="section-label section-label-accent">FLT</span>
          <span className="text-foreground">/ Sensor Command Center</span>
          <span className="text-muted-foreground">
            {fleet.totals.ready}/{fleet.totals.sensors} ready
          </span>
          <button
            title="Refresh fleet"
            onClick={() => void refresh()}
            className="ml-auto text-muted-foreground hover:text-signal"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </header>

      <div className="space-y-5 p-6">
        <div className="grid grid-cols-2 gap-px bg-border lg:grid-cols-5">
          <Metric label="SENSORS" value={fleet.totals.sensors} />
          <Metric label="READY" value={fleet.totals.ready} />
          <Metric label="CAPTURING" value={fleet.totals.capturing} />
          <Metric
            label="URGENT ALERTS"
            value={fleet.totals.urgent_alerts}
            warning={fleet.totals.urgent_alerts > 0}
          />
          <Metric label="DEDUP FINDINGS" value={fleet.totals.deduplicated_findings} />
        </div>

        {notice && (
          <div
            className={`border px-4 py-3 mono text-[11px] ${notice.kind === "ok" ? "border-ok/40 bg-ok/10 text-ok" : "border-severity-high/40 bg-severity-high/10 text-severity-high"}`}
          >
            {notice.text}
          </div>
        )}
        {pending.current && (
          <div className="flex flex-wrap items-center gap-3 border border-severity-high/40 bg-background p-3">
            <ShieldAlert className="h-4 w-4 text-severity-high" />
            <input
              type="password"
              value={stepUpPin}
              onChange={(event) => setStepUpPin(event.target.value)}
              placeholder="Operator PIN"
              className="h-8 min-w-52 border border-border bg-background px-2 mono text-[11px] text-foreground outline-none focus:border-signal"
            />
            <button
              disabled={stepUpPin.length < 6 || busy === "re-authentication"}
              onClick={() => void retry()}
              className="h-8 border border-signal px-3 mono text-[10px] uppercase text-signal disabled:opacity-30"
            >
              Verify and continue
            </button>
          </div>
        )}

        <section className="border-y border-border py-4">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <div className="section-label">/ MESH CONTROLLER</div>
              <div className="mt-1 mono text-[10px] text-muted-foreground">
                {String(configuration.mode || "not configured")} /{" "}
                {String(configuration.advertised_address || "no address")} /{" "}
                {controllerRunning ? "running" : String(runtime.state || "stopped")}
              </div>
            </div>
            <div className="ml-auto flex gap-1">
              <IconAction
                title="Configure controller"
                onClick={() => setSetupOpen((value) => !value)}
                icon={<ServerCog className="h-3.5 w-3.5" />}
              />
              <IconAction
                title="Start controller"
                disabled={controllerRunning || Boolean(busy)}
                onClick={() =>
                  void guarded("controller start", () =>
                    meshControllerAction({ data: { action: "start" } }),
                  )
                }
                icon={<Play className="h-3.5 w-3.5" />}
              />
              <IconAction
                title="Stop controller"
                disabled={!controllerRunning || Boolean(busy)}
                onClick={() =>
                  void guarded("controller stop", () =>
                    meshControllerAction({ data: { action: "stop" } }),
                  )
                }
                icon={<Square className="h-3.5 w-3.5" />}
              />
              <IconAction
                title="Restart controller"
                disabled={!controllerRunning || Boolean(busy)}
                onClick={() =>
                  void guarded("controller restart", () =>
                    meshControllerAction({ data: { action: "restart" } }),
                  )
                }
                icon={<RotateCw className="h-3.5 w-3.5" />}
              />
            </div>
          </div>
          {setupOpen && (
            <div className="mt-4 grid gap-px bg-border lg:grid-cols-[1fr_1.2fr_auto]">
              <div className="bg-background p-3">
                <div className="section-label">CONNECTIVITY</div>
                <div className="mt-2 flex">
                  {(["vpn", "local", "public"] as const).map((item) => (
                    <button
                      key={item}
                      onClick={() => setMode(item)}
                      className={`h-8 flex-1 border mono text-[9px] uppercase ${mode === item ? "border-signal bg-signal/10 text-signal" : "border-border text-muted-foreground"}`}
                    >
                      {item}
                    </button>
                  ))}
                </div>
              </div>
              <label className="bg-background p-3">
                <span className="section-label">CONTROLLER ADDRESS</span>
                <input
                  value={address}
                  onChange={(event) => setAddress(event.target.value)}
                  placeholder={
                    mode === "vpn" ? "VPN address or hostname" : "Auto-detect when blank"
                  }
                  className="mt-2 h-8 w-full border border-border bg-background px-2 mono text-[10px] text-foreground outline-none focus:border-signal"
                />
              </label>
              <div className="flex items-center bg-background p-3">
                <button
                  onClick={() =>
                    void guarded("controller setup", () =>
                      setupMeshController({
                        data: {
                          mode,
                          address: address || undefined,
                          acknowledge_public_risk: mode === "public",
                        },
                      }),
                    )
                  }
                  className="h-8 border border-signal px-3 mono text-[10px] uppercase text-signal"
                >
                  Apply setup
                </button>
              </div>
              {mode === "public" && (
                <div className="bg-background p-3 text-[11px] text-severity-high lg:col-span-3">
                  Direct-public mode exposes the mTLS listeners to the internet. VPN-overlay mode is
                  recommended.
                </div>
              )}
            </div>
          )}
        </section>

        <FleetTopology nodes={fleet.nodes} onSelect={selectNode} />

        <section>
          <div className="flex flex-wrap items-end gap-3 border-b border-border pb-3">
            <div>
              <div className="section-label">/ ENROLL SENSOR</div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                Generate one package, verify the displayed CA fingerprint on the sensor, then join.
              </p>
            </div>
            <input
              value={nodeName}
              onChange={(event) => setNodeName(event.target.value)}
              placeholder="Sensor name"
              className="ml-auto h-8 border border-border bg-background px-2 mono text-[10px] text-foreground outline-none focus:border-signal"
            />
            <button
              disabled={!fleet.controller.authority_ready || Boolean(busy)}
              onClick={() =>
                void guarded("join package", async () => {
                  const result = await createMeshEnrollment({
                    data: { name: nodeName || undefined, ttl_seconds: 1800, max_uses: 1 },
                  });
                  setJoinCode(String(result.join_code || ""));
                })
              }
              className="flex h-8 items-center gap-2 border border-signal px-3 mono text-[10px] uppercase text-signal disabled:opacity-30"
            >
              <Plus className="h-3.5 w-3.5" /> Add sensor
            </button>
          </div>
          {joinCode && (
            <div className="mt-3 flex items-start gap-3 border border-signal/40 bg-signal/5 p-3">
              <code className="max-h-24 min-w-0 flex-1 overflow-auto break-all mono text-[9px] text-foreground">
                {joinCode}
              </code>
              <button
                title="Copy enrollment package"
                onClick={() => navigator.clipboard.writeText(joinCode)}
                className="grid h-8 w-8 shrink-0 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal"
              >
                <Clipboard className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </section>

        <div className="grid gap-px bg-border md:grid-cols-2 xl:grid-cols-3">
          {fleet.nodes.map((node) => (
            <SensorPanel
              key={node.id}
              node={node}
              onOpen={() => selectNode(node)}
              onRemove={() =>
                void guarded("node decommission", () =>
                  revokeMeshNode({
                    data: { node_id: node.id, reason: "Decommissioned from fleet command center" },
                  }),
                )
              }
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function FleetTopology({
  nodes,
  onSelect,
}: {
  nodes: FleetNode[];
  onSelect: (node: FleetNode) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const graph = useRef<Core | null>(null);
  useEffect(() => {
    if (!host.current) return;
    const elements: cytoscape.ElementDefinition[] = [
      { data: { id: "controller", label: "WatchTower Controller", type: "controller" } },
      ...nodes.map((node) => ({
        data: { id: node.id, label: node.name, type: node.readiness, risk: node.priority_score },
      })),
      ...nodes.map((node) => ({
        data: { id: `link-${node.id}`, source: "controller", target: node.id },
      })),
    ];
    graph.current = cytoscape({
      container: host.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e6f0ed",
            "font-family": "ui-monospace, monospace",
            "font-size": 9,
            "text-valign": "bottom",
            "text-margin-y": 8,
            "text-outline-color": "#091112",
            "text-outline-width": 2,
            "background-color": "#42d8a1",
            width: 25,
            height: 25,
          },
        },
        {
          selector: 'node[type = "controller"]',
          style: { shape: "diamond", width: 38, height: 38, "background-color": "#54a8ff" },
        },
        {
          selector: 'node[type = "offline"], node[type = "decommissioned"]',
          style: { "background-color": "#687878" },
        },
        {
          selector: 'node[type = "capability_sync"], node[type = "first_telemetry_sync"]',
          style: { "background-color": "#ffb84d" },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#385454",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#42d8a1",
            "curve-style": "bezier",
          },
        },
      ],
      layout: { name: "concentric", minNodeSpacing: 60, animate: false, fit: true, padding: 45 },
    });
    graph.current.on("tap", "node", (event) => {
      const node = nodes.find((item) => item.id === event.target.id());
      if (node) onSelect(node);
    });
    return () => graph.current?.destroy();
  }, [nodes, onSelect]);
  return (
    <div className="border border-border">
      <div className="border-b border-border bg-surface px-3 py-2 section-label">
        / SENSOR-LEVEL TOPOLOGY
      </div>
      <div ref={host} className="h-80 bg-background grid-bg-fine" />
    </div>
  );
}

function SensorPanel({
  node,
  onOpen,
  onRemove,
}: {
  node: FleetNode;
  onOpen: () => void;
  onRemove: () => void;
}) {
  const spool = node.spool_capacity_bytes
    ? Math.round((node.spool_bytes * 100) / node.spool_capacity_bytes)
    : 0;
  return (
    <article className="bg-background p-4">
      <div className="flex items-start gap-3">
        <span
          className={`mt-1.5 h-2 w-2 rounded-full ${node.readiness === "ready" ? "bg-ok" : node.readiness === "offline" || node.readiness === "decommissioned" ? "bg-muted-foreground" : "bg-severity-medium"}`}
        />
        <div className="min-w-0 flex-1">
          <button
            onClick={onOpen}
            className="truncate text-left text-[13px] text-foreground hover:text-signal"
          >
            {node.name}
          </button>
          <div className="mt-1 mono text-[9px] uppercase text-muted-foreground">
            {node.readiness.replaceAll("_", " ")} / {node.platform || "unknown platform"}
          </div>
        </div>
        {node.status !== "local" && node.readiness !== "decommissioned" && (
          <button
            title="Decommission sensor"
            onClick={onRemove}
            className="text-muted-foreground hover:text-severity-critical"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-y-2 mono text-[10px]">
        <dt className="text-muted-foreground">Capture</dt>
        <dd className="text-right text-foreground">
          {node.capture_active ? `${node.active_sessions} active` : "idle"}
        </dd>
        <dt className="text-muted-foreground">Ingest lag</dt>
        <dd className="text-right text-foreground">
          {node.ingestion_lag_seconds == null
            ? "-"
            : `${Number(node.ingestion_lag_seconds).toFixed(1)}s`}
        </dd>
        <dt className="text-muted-foreground">Alerts</dt>
        <dd
          className={`text-right ${node.urgent_alerts ? "text-severity-high" : "text-foreground"}`}
        >
          {node.alert_count} / {node.urgent_alerts} urgent
        </dd>
        <dt className="text-muted-foreground">Priority</dt>
        <dd className="text-right text-foreground">{node.priority_score.toFixed(1)}</dd>
        <dt className="text-muted-foreground">Spool</dt>
        <dd className="text-right text-foreground">{spool}%</dd>
      </dl>
    </article>
  );
}

function Metric({
  label,
  value,
  warning = false,
}: {
  label: string;
  value: number;
  warning?: boolean;
}) {
  return (
    <div className="bg-background p-4">
      <div className="section-label">{label}</div>
      <div
        className={`mt-2 numeral text-2xl ${warning ? "text-severity-high" : "text-foreground"}`}
      >
        {value.toLocaleString()}
      </div>
    </div>
  );
}

function IconAction({
  title,
  icon,
  onClick,
  disabled = false,
}: {
  title: string;
  icon: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      title={title}
      disabled={disabled}
      onClick={onClick}
      className="grid h-8 w-8 place-items-center border border-border text-muted-foreground hover:border-signal hover:text-signal disabled:opacity-30"
    >
      {icon}
    </button>
  );
}
