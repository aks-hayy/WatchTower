import type { AIContextScope } from "@/types/watchtower";

function formatTime(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

export function summarizeEffectiveScope(scope?: AIContextScope | null): string {
  if (!scope) return "General conversation (no capture scope)";
  const parts: string[] = [];
  if (scope.source) parts.push(`source ${scope.source}`);
  if (scope.interface) parts.push(`interface ${scope.interface}`);
  if (scope.session_id) parts.push(`session ${scope.session_id}`);
  if (scope.node_id) parts.push(`sensor ${scope.node_id}`);
  if (scope.case_id) parts.push(`case ${scope.case_id}`);
  if (scope.target_ips?.length) {
    parts.push(`${scope.target_ips.length} target${scope.target_ips.length === 1 ? "" : "s"}`);
  }
  if (scope.time_start != null || scope.time_end != null) {
    const start = scope.time_start != null ? formatTime(scope.time_start) : "start omitted";
    const end = scope.time_end != null ? formatTime(scope.time_end) : "current";
    parts.push(`time ${start}–${end}`);
  }
  return parts.length ? parts.join(" · ") : "No capture scope applied";
}
