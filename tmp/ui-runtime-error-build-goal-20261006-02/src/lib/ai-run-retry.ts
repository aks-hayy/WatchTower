import type { AIRun } from "@/types/watchtower";

export function canRetryInterruptedAIRun(
  run: Pick<AIRun, "status" | "mode" | "policy">,
  hasOriginMessage: boolean,
): boolean {
  const policy = run.policy || {};
  const mode = run.mode || String(policy.mode || "");
  return (
    run.status === "INTERRUPTED" &&
    mode !== "action" &&
    policy.read_only === true &&
    hasOriginMessage
  );
}
