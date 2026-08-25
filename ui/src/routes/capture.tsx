import { createFileRoute } from "@tanstack/react-router";
import { Circle, Loader2, Play, RefreshCw, Square } from "lucide-react";
import { useEffect, useState } from "react";
import {
  fetchHealth,
  fetchInterfaces,
  fetchPipelineHealth,
  fetchSessions,
  queueMeshNodeCommand,
  startEngine,
  stopEngine,
} from "@/lib/api.functions";
import type {
  CaptureSession,
  HealthStatus,
  NetworkInterface,
  PipelineHealth,
} from "@/types/watchtower";
import { useSensorScope } from "@/components/useSensorScope";
import { captureStartBackend, selectCaptureBackend } from "@/lib/capture-backend";

export const Route = createFileRoute("/capture")({
  head: () => ({ meta: [{ title: "Capture Operations - Watchtower" }] }),
  loader: async () => {
    const [interfaces, sessions, health, pipeline] = await Promise.all([
      fetchInterfaces(),
      fetchSessions({ data: { limit: 50 } }),
      fetchHealth(),
      fetchPipelineHealth(),
    ]);
    return { interfaces, sessions, health, pipeline };
  },
  component: CapturePage,
});

function CapturePage() {
  const initial = Route.useLoaderData();
  const { selectedNodeId, isRemote, nodes } = useSensorScope();
  const bridgeNodes = nodes.filter(
    (node) =>
      node.status !== "local" &&
      node.status !== "revoked" &&
      node.status !== "decommissioned" &&
      Array.isArray(node.capabilities?.capture_devices),
  );
  // In the normal one-sensor desktop deployment, the controller itself has
  // no capture NIC. Route the Capture page to its enrolled native sensor.
  const captureNodeId = isRemote
    ? selectedNodeId
    : !selectedNodeId && bridgeNodes.length === 1
      ? bridgeNodes[0].id
      : undefined;
  const delegatedCapture = Boolean(captureNodeId);
  const captureTarget = nodes.find((node) => node.id === captureNodeId);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>(initial.interfaces);
  const [sessions, setSessions] = useState<CaptureSession[]>(initial.sessions);
  const [health, setHealth] = useState<HealthStatus>(initial.health);
  const [pipeline, setPipeline] = useState<PipelineHealth>(initial.pipeline);
  const [backends, setBackends] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const refresh = async (clearMessage = false) => {
    const [localInterfaces, nextSessions, nextHealth, nextPipeline] = await Promise.all([
      delegatedCapture ? Promise.resolve([] as NetworkInterface[]) : fetchInterfaces(),
      fetchSessions({ data: { limit: 50, node: captureNodeId || selectedNodeId } }),
      fetchHealth(),
      fetchPipelineHealth(),
    ]);
    let displayedInterfaces = localInterfaces;
    if (delegatedCapture && captureNodeId) {
      const selected = nodes.find((node) => node.id === captureNodeId);
      const rawDevices = Array.isArray(selected?.capabilities?.capture_devices)
        ? (selected?.capabilities?.capture_devices as Array<Record<string, unknown>>)
        : [];
      const activeSessions = new Map(
        nextSessions
          .filter((session) =>
            ["running", "active", "draining"].includes(String(session.status).toLowerCase()),
          )
          .map((session) => [session.device_id, session]),
      );
      displayedInterfaces = rawDevices.map((device) => {
        const deviceId = String(device.device_id || device.name || "");
        const active = activeSessions.get(deviceId);
        return {
          id: String(device.device_id || device.name || ""),
          device_id: String(device.device_id || device.name || ""),
          source_type: String(device.source_type || "network"),
          name: String(device.name || device.device_id || "capture source"),
          description: String(device.description || ""),
          status: device.available === false ? "down" : "up",
          mac: null,
          ipv4: null,
          addresses: [],
          backends: Array.isArray(device.backends) ? device.backends.map(String) : [],
          capturing: Boolean(active),
          unavailable_reason: String(device.unavailable_reason || ""),
          engine: active ? { backend: active.backend } : null,
        };
      });
    }
    setInterfaces(displayedInterfaces);
    setBackends((current) =>
      Object.fromEntries(
        displayedInterfaces.flatMap((item) => {
          const selected = current[item.id];
          return selected &&
            item.backends.some((backend) => backend.toLowerCase() === selected.toLowerCase())
            ? [[item.id, selected]]
            : [];
        }),
      ),
    );
    setSessions(nextSessions);
    setHealth(nextHealth);
    setPipeline(nextPipeline);
    if (clearMessage) setMessage(null);
  };

  useEffect(() => {
    void refresh(true);
    // refresh is intentionally scoped to the global sensor transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [captureNodeId, delegatedCapture, selectedNodeId, nodes]);

  const toggle = async (item: NetworkInterface) => {
    setBusy(item.id);
    setMessage(null);
    try {
      if (item.capturing) {
        if (delegatedCapture && captureNodeId) {
          await queueMeshNodeCommand({
            data: {
              node_id: captureNodeId,
              action: "capture.stop",
              arguments: { interface: item.id },
            },
          });
        } else {
          await stopEngine({ data: { interface_id: item.id } });
        }
      } else {
        const selectedBackend = captureStartBackend(item, backends[item.id]);
        if (selectedBackend === null) throw new Error("No supported capture backend is available");
        if (delegatedCapture && captureNodeId) {
          await queueMeshNodeCommand({
            data: {
              node_id: captureNodeId,
              action: "capture.start",
              arguments: {
                interface: item.id,
                source_type: item.source_type,
                ...(selectedBackend ? { backend: selectedBackend } : {}),
              },
            },
          });
        } else {
          await startEngine({
            data: {
              interface_id: item.id,
              backend: selectedBackend,
              source_type: item.source_type,
            },
          });
        }
      }
      setMessage(
        `${item.name}: capture ${delegatedCapture ? "command queued" : item.capturing ? "draining" : "started"}`,
      );
      await refresh();
      if (delegatedCapture) {
        window.setTimeout(() => void refresh(), 6000);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Capture action failed");
      await refresh().catch(() => undefined);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="min-h-screen">
      <header className="flex items-center gap-4 border-b border-border bg-surface/60 px-6 py-3">
        <span className="section-label section-label-accent">CAP</span>
        <span className="mono text-[11px] uppercase text-foreground">/ Capture Operations</span>
        <span
          className={`ml-auto mono text-[10px] uppercase ${delegatedCapture ? "text-ok" : health.daemon === "online" ? "text-ok" : "text-severity-high"}`}
        >
          {delegatedCapture
            ? `sensor ${captureTarget?.status || "connecting"}`
            : `daemon ${health.daemon}`}
        </span>
        <button
          onClick={() => refresh(true)}
          title="Refresh capture state"
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
        {delegatedCapture && (
          <div className="border border-signal/30 bg-signal/5 px-4 py-3 mono text-[11px] text-signal">
            CAPTURE TARGET / {captureTarget?.name || "Native Sensor"}
          </div>
        )}
        {!delegatedCapture && !selectedNodeId && bridgeNodes.length > 1 && (
          <div className="border border-severity-medium/40 bg-severity-medium/10 px-4 py-3 mono text-[11px] text-severity-medium">
            SELECT A SENSOR SCOPE BEFORE STARTING CAPTURE
          </div>
        )}
        {(pipeline.status !== "ok" || pipeline.active_sessions > 0) && (
          <div
            className={`border px-4 py-3 mono text-[11px] ${pipeline.status === "ok" ? "border-signal/30 bg-signal/5 text-signal" : "border-severity-high/40 bg-severity-high/10 text-severity-high"}`}
          >
            PIPELINE {pipeline.status.toUpperCase()} /{" "}
            {pipeline.pending_packets.toLocaleString("en-US")} pending /{" "}
            {pipeline.queue_lag_ms.toFixed(1)} ms current lag /{" "}
            {Number(pipeline.queue_lag_max_ms || 0).toFixed(1)} ms peak /{" "}
            {pipeline.detector_failures} detector failures
          </div>
        )}
        <section className="panel">
          <div className="border-b border-border px-4 py-2.5 text-sm text-foreground">
            Capture Sources
          </div>
          <div className="divide-y divide-border">
            {interfaces.map((item) => (
              <div
                key={item.id}
                className="grid items-center gap-4 p-4 data-row md:grid-cols-[1fr_130px_auto]"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <Circle
                    className={`h-2 w-2 shrink-0 ${item.capturing ? "fill-signal text-signal" : item.status === "up" ? "fill-ok text-ok" : "fill-muted-foreground text-muted-foreground"}`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-[13px] text-foreground">
                      {item.name}{" "}
                      <span className="mono text-[10px] text-muted-foreground">
                        / {item.source_type}
                      </span>
                    </div>
                    <div className="truncate mono text-[10px] uppercase text-muted-foreground">
                      {item.ipv4 || item.description || "no address"}
                      {item.capturing
                        ? ` / ${selectCaptureBackend(item) || "unavailable"} core`
                        : ""}
                    </div>
                    {item.unavailable_reason && (
                      <div className="mt-1 text-[11px] text-severity-high">
                        {item.unavailable_reason}
                      </div>
                    )}
                    {!selectCaptureBackend(item) && !item.unavailable_reason && (
                      <div className="mt-1 text-[11px] text-severity-high">
                        No supported capture backend is available
                      </div>
                    )}
                  </div>
                </div>
                <select
                  aria-label={`${item.name} capture backend`}
                  value={
                    item.capturing ? selectCaptureBackend(item) || "" : backends[item.id] || ""
                  }
                  onChange={(event) =>
                    setBackends((current) => ({ ...current, [item.id]: event.target.value }))
                  }
                  disabled={item.capturing}
                  className="h-8 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground disabled:opacity-40"
                >
                  {selectCaptureBackend(item) ? (
                    <option value="">operator default</option>
                  ) : (
                    <option value="">unavailable</option>
                  )}
                  {item.backends.map((backend) => (
                    <option key={backend}>{backend}</option>
                  ))}
                </select>
                <button
                  onClick={() => toggle(item)}
                  disabled={
                    busy === item.id ||
                    item.status !== "up" ||
                    (!item.capturing && !selectCaptureBackend(item))
                  }
                  className={`flex h-8 min-w-24 items-center justify-center gap-2 border px-3 mono text-[10px] uppercase disabled:opacity-30 ${item.capturing ? "border-severity-critical/50 text-severity-critical" : "border-signal/50 text-signal"}`}
                >
                  {busy === item.id ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : item.capturing ? (
                    <Square className="h-3 w-3" />
                  ) : (
                    <Play className="h-3 w-3" />
                  )}
                  {item.capturing ? "Stop" : "Start"}
                </button>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="border-b border-border px-4 py-2.5 text-sm text-foreground">
            Recent Capture Sessions
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] mono text-[10px]">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="p-3">INTERFACE</th>
                  <th>STATUS</th>
                  <th>CORE</th>
                  <th>SESSION</th>
                  <th>PROCESSED</th>
                  <th>PENDING</th>
                  <th>DROPS</th>
                  <th>MAX LAG</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr key={session.id} className="border-b border-border/60">
                    <td className="p-3 text-foreground">
                      {session.interface || session.device_id}
                    </td>
                    <td>{String(session.processing_state || session.status).toUpperCase()}</td>
                    <td>{session.backend}</td>
                    <td>{session.id}</td>
                    <td>{session.processed_packets || 0}</td>
                    <td>{session.pending_packets || 0}</td>
                    <td>
                      {(session.dropped_packets || 0) +
                        (session.snapshot_dropped || 0) +
                        (session.evidence_dropped || 0)}
                    </td>
                    <td>{Number(session.queue_lag_max_ms || 0).toFixed(1)} ms</td>
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
