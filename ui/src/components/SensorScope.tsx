import { useEffect, useMemo, useState } from "react";
import { fetchMeshNodes } from "@/lib/api.functions";
import type { SensorNode } from "@/types/watchtower";
import {
  SensorScopeContext,
  type SensorScopeState,
  type ScopeValue,
  useSensorScope,
} from "@/components/useSensorScope";
const storageKey = "watchtower.sensor.scope";

export function SensorScopeProvider({ children }: { children: React.ReactNode }) {
  const [scope, updateScope] = useState<ScopeValue>("all");
  const [nodes, setNodes] = useState<SensorNode[]>([]);

  useEffect(() => {
    const stored = window.localStorage.getItem(storageKey);
    if (stored) updateScope(stored);
    const refreshNodes = () =>
      fetchMeshNodes({ data: { limit: 500 } })
        .then(setNodes)
        .catch(() => setNodes([]));
    void refreshNodes();
    const timer = window.setInterval(() => void refreshNodes(), 5000);
    return () => window.clearInterval(timer);
  }, []);

  const localNode = nodes.find((node) => node.status === "local");
  const selectedNodeId = scope === "all" ? undefined : scope === "local" ? localNode?.id : scope;
  const selected = nodes.find((node) => node.id === selectedNodeId);
  const selectedLabel =
    scope === "all" ? "All Sensors" : scope === "local" ? "Local Sensor" : selected?.name || scope;

  const value = useMemo<SensorScopeState>(
    () => ({
      scope,
      nodes,
      selectedNodeId,
      selectedLabel,
      isRemote: Boolean(selectedNodeId && selectedNodeId !== localNode?.id),
      setScope: (next) => {
        updateScope(next);
        window.localStorage.setItem(storageKey, next);
      },
    }),
    [localNode?.id, nodes, scope, selectedLabel, selectedNodeId],
  );

  return <SensorScopeContext.Provider value={value}>{children}</SensorScopeContext.Provider>;
}

export function SensorScopeSelector({ compact = false }: { compact?: boolean }) {
  const { scope, setScope, nodes, selectedLabel } = useSensorScope();
  return (
    <label className="flex min-w-0 items-center gap-2">
      {!compact && <span className="section-label">SCOPE</span>}
      <select
        aria-label="Sensor scope"
        value={scope}
        onChange={(event) => setScope(event.target.value)}
        title={`Current sensor scope: ${selectedLabel}`}
        className="h-7 min-w-0 max-w-56 border border-border bg-background px-2 mono text-[10px] uppercase text-foreground outline-none hover:border-signal focus:border-signal"
      >
        <option value="all">All Sensors</option>
        <option value="local">Local Sensor</option>
        {nodes
          .filter((node) => node.status !== "local")
          .map((node) => (
            <option key={node.id} value={node.id}>
              {node.name}
            </option>
          ))}
      </select>
    </label>
  );
}
