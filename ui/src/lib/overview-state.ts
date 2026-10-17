import type { HealthStatus, NetworkInterface, TimelinePoint } from "@/types/watchtower";

type OverviewEvidenceData = {
  health: Pick<HealthStatus, "capture_state">;
  stats: { total_packets: number; total_flows: number; active_hosts: number };
  interfaces: Array<Pick<NetworkInterface, "capturing">>;
  timeline: Array<Pick<TimelinePoint, "packets_per_sec" | "bytes_per_sec" | "flows">>;
  protocols: unknown[];
  ports: unknown[];
  alerts: unknown[];
  entities: unknown[];
  topology: { nodes: unknown[]; edges: unknown[] };
};

export type OverviewEvidenceState =
  | "no-data"
  | "starting"
  | "collecting"
  | "monitoring"
  | "history";

export interface OverviewPosture {
  level: string;
  color: string;
  bg: string;
  border: string;
}

export function resolveOverviewEvidenceState(data: OverviewEvidenceData): OverviewEvidenceState {
  const hasEvidence =
    data.stats.total_packets > 0 ||
    data.stats.total_flows > 0 ||
    data.stats.active_hosts > 0 ||
    data.timeline.some(
      (point) => point.packets_per_sec > 0 || point.bytes_per_sec > 0 || point.flows > 0,
    ) ||
    data.protocols.length > 0 ||
    data.ports.length > 0 ||
    data.alerts.length > 0 ||
    data.entities.length > 0 ||
    data.topology.nodes.length > 0 ||
    data.topology.edges.length > 0;

  const captureActive =
    data.health.capture_state === "active" || data.interfaces.some((item) => item.capturing);

  if (hasEvidence) return captureActive ? "monitoring" : "history";
  if (data.health.capture_state === "starting") return "starting";
  if (captureActive) return "collecting";
  return "no-data";
}

export function resolveOverviewPosture(
  state: OverviewEvidenceState,
  scoredEntityCount: number,
  maxPriority: number,
): OverviewPosture {
  if (state === "no-data" || state === "starting" || state === "collecting") {
    return {
      level: "NO DATA",
      color: "text-muted-foreground",
      bg: "bg-surface",
      border: "border-border",
    };
  }
  if (scoredEntityCount === 0) {
    return {
      level: "UNASSESSED",
      color: "text-muted-foreground",
      bg: "bg-surface",
      border: "border-border",
    };
  }
  if (maxPriority >= 80) {
    return {
      level: "ELEVATED",
      color: "text-severity-critical",
      bg: "bg-severity-critical/10",
      border: "border-severity-critical/40",
    };
  }
  if (maxPriority >= 50) {
    return {
      level: "GUARDED",
      color: "text-severity-high",
      bg: "bg-severity-high/10",
      border: "border-severity-high/40",
    };
  }
  if (maxPriority >= 20) {
    return {
      level: "WATCH",
      color: "text-severity-medium",
      bg: "bg-severity-medium/10",
      border: "border-severity-medium/40",
    };
  }
  return { level: "NOMINAL", color: "text-ok", bg: "bg-ok/10", border: "border-ok/40" };
}
