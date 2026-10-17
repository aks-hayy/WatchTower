export interface PriorityEndpointCandidate {
  ip?: string | null;
  priority_score?: number | null;
}

export interface InvestigationSummary {
  ip: string;
  verdict: string;
  risk_score: number;
  confidence: number;
  role_confidence: number | null;
  summary: string;
  role: string;
  flow_count: number;
  alert_count: number;
  carved_file_count: number;
  correlation_count: number;
  findings: string[];
  next_actions: string[];
}

export function activeConversationIdFromSearch(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  return value.trim() || undefined;
}

export function selectHighestPriorityEndpoint(
  entities: ReadonlyArray<PriorityEndpointCandidate>,
): PriorityEndpointCandidate | null {
  return (
    entities
      .filter(
        (entity) => Boolean(entity.ip?.trim()) && Number.isFinite(Number(entity.priority_score)),
      )
      .map((entity) => ({
        ...entity,
        ip: entity.ip!.trim(),
        priority_score: Number(entity.priority_score),
      }))
      .sort((left, right) => {
        const scoreDelta = Number(right.priority_score) - Number(left.priority_score);
        return scoreDelta || String(left.ip).localeCompare(String(right.ip));
      })[0] || null
  );
}

export function latestRunIdForConversation(
  messages: ReadonlyArray<{ run_id?: string | null }>,
): string | null {
  return [...messages].reverse().find((message) => Boolean(message.run_id))?.run_id || null;
}

export function persistedRunIdsForConversation(
  messages: ReadonlyArray<{ run_id?: string | null }>,
): string[] {
  return [...new Set(messages.map((message) => message.run_id).filter(Boolean) as string[])];
}

export function isRawProviderNarration(content: string): boolean {
  return /^(this output appears to be|this is (?:an? )?(?:api|json) response|here(?:'|’)s a breakdown|the api appears to be)/i.test(
    content.trim(),
  );
}

export function buildPriorityInvestigationPrompt(endpoint: {
  ip: string;
  priority_score: number;
}): string {
  return [
    `First use the investigate tool for endpoint ${endpoint.ip}.`,
    `This endpoint was selected as the highest-priority endpoint in the current WatchTower scope with a priority score of ${endpoint.priority_score.toFixed(1)}.`,
    "Then explain the evidence, alerts, flows, confidence, and next actions in clear operator language, including any visibility limits.",
    "Do not describe the JSON format or repeat raw tool payloads; answer the investigation question directly and distinguish evidence from inference.",
  ].join(" ");
}

export function parseInvestigationResult(
  toolCalls: ReadonlyArray<{ tool_name: string; result_json?: string | null }>,
): InvestigationSummary | null {
  const call = toolCalls.find((item) => item.tool_name === "investigate" && item.result_json);
  if (!call?.result_json) return null;

  try {
    const payload = JSON.parse(call.result_json) as { data?: Record<string, unknown> };
    const data = payload.data;
    if (!data || typeof data !== "object") return null;
    const lookup = asRecord(data.lookup);
    const activity = asRecord(lookup.activity);
    const profile = asRecord(data.asset_profile);
    const arrayOfStrings = (value: unknown) =>
      Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
    const ip = typeof data.target === "string" ? data.target : "";
    if (!ip) return null;

    return {
      ip,
      verdict: typeof data.verdict === "string" ? data.verdict : "UNKNOWN",
      risk_score: Number.isFinite(Number(data.risk_score)) ? Number(data.risk_score) : 0,
      confidence: Number.isFinite(Number(data.confidence)) ? Number(data.confidence) : 0,
      role_confidence:
        typeof profile.role_confidence === "number" && Number.isFinite(profile.role_confidence)
          ? profile.role_confidence
          : null,
      summary:
        typeof data.summary === "string" ? data.summary : "No investigation summary was returned.",
      role: typeof profile.role === "string" ? profile.role : "Unknown endpoint role",
      flow_count: Number(activity.flow_count || 0),
      alert_count: Number(activity.alert_count || 0),
      carved_file_count: Number(activity.artifact_count || 0),
      correlation_count: Array.isArray(data.correlations) ? data.correlations.length : 0,
      findings: arrayOfStrings(data.findings),
      next_actions: arrayOfStrings(data.next_actions),
    };
  } catch {
    return null;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
