export type PluginCoverageState =
  | "ready"
  | "disabled_by_policy"
  | "unsupported_telemetry"
  | "unavailable_dependency"
  | "invalid_plugin";

export type PluginCoverageStatus = {
  state: PluginCoverageState;
  reason?: string;
  next_action?: string;
};

export type PluginStatusPresentation = {
  label: string;
  detail: string;
  nextAction: string;
};

const STATE_LABELS: Record<PluginCoverageState, string> = {
  ready: "Ready",
  disabled_by_policy: "Disabled by policy",
  unsupported_telemetry: "Telemetry not available",
  unavailable_dependency: "Dependency unavailable",
  invalid_plugin: "Plugin error",
};

export function pluginStatusPresentation(
  plugin: { enabled: boolean; valid: boolean },
  coverage?: PluginCoverageStatus,
): PluginStatusPresentation {
  if (coverage) {
    return {
      label: STATE_LABELS[coverage.state],
      detail: coverage.state === "ready" ? "" : coverage.reason || "",
      nextAction: coverage.state === "ready" ? "" : coverage.next_action || "",
    };
  }

  if (!plugin.valid) return { label: "Error", detail: "", nextAction: "" };
  if (!plugin.enabled) return { label: "Disabled by policy", detail: "", nextAction: "" };
  return { label: "Ready", detail: "", nextAction: "" };
}
