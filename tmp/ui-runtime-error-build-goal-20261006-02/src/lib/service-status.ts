import type { HealthStatus } from "@/types/watchtower";

export type WorkspaceServiceState = "checking" | "offline" | "attention" | "ready";

function isNativeSensorStopped(health: HealthStatus): boolean {
  return (
    health.status === "offline" &&
    health.database === "ok" &&
    health.daemon === "offline" &&
    health.deployment_role === "native"
  );
}

export function resolveWorkspaceServiceState(health: HealthStatus | null): WorkspaceServiceState {
  if (!health) return "checking";
  if (isNativeSensorStopped(health)) return "attention";
  if (health.status === "offline") return "offline";
  if (health.status === "degraded" || health.capture_state === "failed") return "attention";
  return "ready";
}

export function describeServiceStatus(health: HealthStatus | null) {
  const state = resolveWorkspaceServiceState(health);
  const sensorStopped = health !== null && isNativeSensorStopped(health);
  const label =
    state === "checking"
      ? "Checking service"
      : sensorStopped
        ? "Sensor stopped"
        : state === "offline"
          ? "Service offline"
          : state === "attention"
            ? "Needs attention"
            : health?.deployment_role === "controller"
              ? health.capture_state === "active"
                ? "Monitoring"
                : "Controller ready"
              : health?.capture_state === "active"
                ? "Monitoring"
                : "Service ready";

  return {
    state,
    label,
    bannerText: sensorStopped
      ? "CONTROLLER AVAILABLE · SENSOR STOPPED · database ok, daemon offline"
      : health && health.status !== "ok"
        ? `CONTROL PLANE ${health.status.toUpperCase()} · ${health.message || `database ${health.database}, daemon ${health.daemon}`}`
        : null,
    sourceLabel:
      health?.capture_interface ||
      (health?.deployment_role === "controller" ? "Controller" : "Local sensor"),
    nativeDaemonApplicable: health !== null && health.daemon !== "not_applicable",
    nativeDaemonLabel: !health
      ? "Native daemon status unavailable"
      : health.daemon === "not_applicable"
        ? "Native daemon not used in this deployment"
        : `Native daemon ${health.daemon}`,
    nextAction: !health
      ? "Checking capture status"
      : health.next_action ||
        (health.capture_state === "active"
          ? "Review recent activity and alerts."
          : "No active capture."),
  };
}
