const AI_RUN_EVENTS = [
  "queued",
  "running",
  "baseline_started",
  "round_started",
  "tool_started",
  "tool_complete",
  "tool_failed",
  "approval_required",
  "needs_scope",
  "cancelled",
  "interrupted",
  "complete",
  "failed",
  "terminal",
];

export function isTerminalAIRunStatus(status: string): boolean {
  return [
    "COMPLETE",
    "DEGRADED",
    "NEEDS_SCOPE",
    "FAILED",
    "REJECTED",
    "CANCELLED",
    "INTERRUPTED",
  ].includes(status);
}

export type AIRunTimerHost = {
  setInterval(callback: () => void, delay: number): number;
  clearInterval(id: number): void;
};

export function attachAIRunStream(
  events: EventSource,
  sync: () => void,
  timers: AIRunTimerHost,
): () => void {
  let fallbackTimer: number | undefined;
  const stopFallback = () => {
    if (fallbackTimer !== undefined) {
      timers.clearInterval(fallbackTimer);
      fallbackTimer = undefined;
    }
  };

  events.onopen = stopFallback;
  for (const name of AI_RUN_EVENTS) events.addEventListener(name, sync);
  events.onerror = () => {
    if (fallbackTimer === undefined) fallbackTimer = timers.setInterval(sync, 1500);
  };

  return () => {
    stopFallback();
    events.close();
  };
}
