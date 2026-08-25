import { createServerFn } from "@tanstack/react-start";
import { getRequestHeader } from "@tanstack/react-start/server";
import type {
  Alert,
  AIConversation,
  AIContextScope,
  AIRun,
  AIStatus,
  CaptureSession,
  CarvedFile,
  CursorPage,
  DashboardData,
  Entity,
  Flow,
  HealthStatus,
  IpLookup,
  Investigation,
  JsonObject,
  NetworkInterface,
  SystemInfo,
  SensorNode,
  FleetSummary,
  EvidenceGraphStatus,
  PluginCalibrationRunResult,
  PluginCalibrationStatus,
  PluginInventory,
  PipelineHealth,
  RiskEntity,
  SigmaPreview,
  SigmaRule,
  TodayStats,
  TimelinePoint,
  TopologyEdge,
  TopologyNode,
} from "@/types/watchtower";

type Query = Record<string, string | number | boolean | null | undefined>;
type ApiRecord = JsonObject;

interface ApiStats {
  source: string;
  window_start?: number | null;
  window_end?: number | null;
  window_hours?: number;
  total_packets: number;
  total_bytes: number;
  total_flows: number;
  active_hosts: number;
  alerts: TodayStats["alerts"];
  top_talkers: TodayStats["top_talkers"];
  timeline: TimelinePoint[];
  protocols: Array<{ protocol: string; count: number; percentage: number }>;
  ports: Array<{ port: number; service: string; count: number; percentage: number }>;
}

interface DashboardSummary {
  generated_at: number;
  traffic: {
    packets: number;
    bytes: number;
    flows: number;
    active_hosts: number;
    protocols: ApiStats["protocols"];
    timeline: TimelinePoint[];
  };
  risk: CursorPage<ApiRecord>;
  alerts: CursorPage<ApiRecord>;
  pipeline: PipelineHealth;
}

function asRecord(value: unknown): ApiRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ApiRecord)
    : {};
}

class WatchtowerApiError extends Error {
  status: number;
  requestId?: string;

  constructor(message: string, status: number, requestId?: string) {
    super(requestId ? `${message} (request ${requestId})` : message);
    this.name = "WatchtowerApiError";
    this.status = status;
    this.requestId = requestId;
  }
}

function apiBase() {
  return (process.env.WATCHTOWER_API_URL || "http://127.0.0.1:8000/api/v1").replace(/\/$/, "");
}

function apiV2Base() {
  return apiBase().replace(/\/api\/v1$/, "/api/v2");
}

function queryString(query?: Query) {
  const params = new URLSearchParams();
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  });
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

async function requestApi<T>(
  path: string,
  init?: RequestInit,
  query?: Query,
  timeoutMs = 15_000,
): Promise<T> {
  return requestFrom<T>(apiBase(), path, init, query, timeoutMs);
}

async function requestApiV2<T>(
  path: string,
  init?: RequestInit,
  query?: Query,
  timeoutMs = 15_000,
): Promise<T> {
  return requestFrom<T>(apiV2Base(), path, init, query, timeoutMs);
}

async function requestFrom<T>(
  base: string,
  path: string,
  init?: RequestInit,
  query?: Query,
  timeoutMs = 15_000,
): Promise<T> {
  const cookie = getRequestHeader("cookie");
  const response = await fetch(`${base}${path}${queryString(query)}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
      ...(init?.headers || {}),
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
  const requestId = response.headers.get("X-Request-ID") || undefined;
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      String(asRecord(asRecord(payload).error).message || "") ||
      `WatchTower API returned HTTP ${response.status}`;
    throw new WatchtowerApiError(message, response.status, requestId);
  }
  return payload as T;
}

function offlineHealth(error: unknown): HealthStatus {
  return {
    status: "offline",
    version: "unknown",
    database: "unknown",
    daemon: "offline",
    daemon_healthy: false,
    message: error instanceof Error ? error.message : "WatchTower API is unavailable",
  };
}

function mapInterface(item: ApiRecord): NetworkInterface {
  const addresses = Array.isArray(item.addresses) ? item.addresses.map(String) : [];
  return {
    id: String(item.device_id),
    device_id: String(item.device_id),
    source_type: String(item.source_type || "network"),
    name: String(item.name || item.device_id),
    description: String(item.description || ""),
    status: item.available ? "up" : "down",
    mac: item.mac ? String(item.mac) : null,
    ipv4: addresses.find((address) => /^\d+\.\d+\.\d+\.\d+$/.test(address)) || null,
    addresses,
    backends: Array.isArray(item.backends) ? item.backends.map(String) : [],
    capturing: Boolean(item.capturing),
    unavailable_reason: String(item.unavailable_reason || ""),
    engine: item.engine ? asRecord(item.engine) : null,
  };
}

function mapEntity(item: ApiRecord): Entity {
  const rawRiskScore = Number(item.priority_score || 0);
  const contributors = Array.isArray(item.contributors)
    ? item.contributors.flatMap((value) => {
        const contributor = asRecord(value);
        if (!contributor.finding_type && !contributor.detector_id) return [];
        return [
          {
            finding_type: contributor.finding_type ? String(contributor.finding_type) : undefined,
            detector_id: contributor.detector_id ? String(contributor.detector_id) : undefined,
            correlation_group: contributor.correlation_group
              ? String(contributor.correlation_group)
              : undefined,
            effective_contribution: Number(contributor.effective_contribution || 0),
            explanation: contributor.explanation ? String(contributor.explanation) : undefined,
          },
        ];
      })
    : [];
  return {
    ...item,
    ip: String(item.ip || item.subject),
    mac: item.mac ? String(item.mac) : null,
    hostname: item.hostname ? String(item.hostname) : null,
    username: item.username ? String(item.username) : null,
    user: item.username ? String(item.username) : null,
    os: item.os ? String(item.os) : null,
    risk_score: Math.max(0, Math.min(100, rawRiskScore)),
    priority_score: Math.max(0, Math.min(100, rawRiskScore)),
    risk_level: String(item.risk_level || "LOW") as Entity["risk_level"],
    assessment_confidence: Number(item.assessment_confidence || 0),
    baseline_maturity: asRecord(item.baseline_maturity),
    processing_completeness: String(item.processing_completeness || "unknown"),
    contributors,
    raw_risk_score: rawRiskScore,
    confidence_score: Number(item.confidence_score || 0),
    identity_source: item.identity_source ? String(item.identity_source) : null,
    alert_count: Number(item.alert_count || 0),
    carved_file_count: Number(item.carved_file_count || 0),
    flow_count: Number(item.flow_count || 0),
    total_packets: Number(item.total_packets || 0),
    total_bytes: Number(item.total_bytes || 0),
    source: String(item.source || "live"),
  };
}

function mapAlert(item: ApiRecord): Alert {
  const evidence = asRecord(item.evidence);
  const impact = String(item.impact || item.severity || "LOW").toUpperCase() as Alert["severity"];
  return {
    ...item,
    id: Number(item.id),
    type: String(item.finding_type || item.type || "Unknown Detection"),
    severity: impact,
    impact,
    score: Number(item.effective_contribution || item.score || 0),
    effective_contribution: Number(item.effective_contribution || 0),
    current_entity_priority: Number(item.current_entity_priority || 0),
    risk_level: String(item.risk_level || "LOW") as Alert["risk_level"],
    assessment_confidence: Number(item.assessment_confidence || 0),
    disposition: item.disposition ? String(item.disposition) : null,
    scope: asRecord(item.scope),
    processing_completeness: String(item.processing_completeness || "unknown"),
    explanation: String(item.explanation || ""),
    entity_ip: String(item.entity_ip || "unknown"),
    src_ip: String(evidence.src_ip || item.entity_ip || "unknown"),
    dst_ip: String(evidence.dst_ip || evidence.destination_ip || "unknown"),
    timestamp: Number(item.last_seen || item.timestamp || 0),
    ai_verdict: item.ai_verdict ? String(item.ai_verdict) : null,
    source: String(item.source || "unknown"),
    evidence,
    capture_session_id: item.capture_session_id ? String(item.capture_session_id) : null,
    capture_interface: item.capture_interface ? String(item.capture_interface) : null,
    capture_backend: item.capture_backend ? String(item.capture_backend) : null,
    capture_type: String(item.capture_type || "network"),
    occurrence_count: Number(item.occurrence_count || 1),
  };
}

function mapFlow(item: ApiRecord): Flow {
  return {
    ...(item as unknown as Flow),
    id: Number(item.id),
    flow_id: String(item.flow_id || ""),
    src_ip: String(item.src_ip || "unknown"),
    dst_ip: String(item.dst_ip || "unknown"),
    src_port: Number(item.src_port || 0),
    dst_port: Number(item.dst_port || 0),
    protocol: String(item.protocol || "OTHER"),
    start_time: Number(item.start_time || 0),
    last_seen: Number(item.last_seen || 0),
    packet_count: Number(item.packet_count || 0),
    byte_count: Number(item.byte_count || 0),
    duration: Number(item.duration || 0),
    source: String(item.source || "unknown"),
    capture_session_id: item.capture_session_id ? String(item.capture_session_id) : null,
    capture_interface: item.capture_interface ? String(item.capture_interface) : null,
    capture_backend: item.capture_backend ? String(item.capture_backend) : null,
    capture_type: String(item.capture_type || "network"),
    sensor_node_id: item.sensor_node_id ? String(item.sensor_node_id) : null,
    l7_metadata: asRecord(item.l7_metadata),
    src_identity: item.src_identity
      ? (asRecord(item.src_identity) as unknown as Flow["src_identity"])
      : null,
    dst_identity: item.dst_identity
      ? (asRecord(item.dst_identity) as unknown as Flow["dst_identity"])
      : null,
  };
}

function mapEvidence(item: ApiRecord): CarvedFile {
  const vt = asRecord(item.vt_results);
  const positives = Number(vt.positives || vt.malicious || 0);
  const total = Number(vt.total || vt.engines || 0);
  return {
    ...item,
    id: Number(item.id),
    entity_ip: String(item.entity_ip || "unknown"),
    filename: String(item.filename || "unnamed"),
    extension: String(item.extension || "unknown"),
    filetype: String(item.extension || "unknown").toUpperCase(),
    size: Number(item.size || 0),
    sha256: String(item.sha256 || ""),
    vt_score: total ? `${positives}/${total}` : "not scanned",
    vt_status: positives > 0 ? "malicious" : total > 0 ? "clean" : "unknown",
    source_ip: String(item.entity_ip || "unknown"),
    source: String(item.source || "unknown"),
    timestamp: Number(item.timestamp || 0),
  };
}

async function getStats(node?: string) {
  return requestApi<ApiStats>("/stats", undefined, { node });
}

function emptyDashboard(health: HealthStatus): DashboardData {
  return {
    health,
    stats: {
      source: "live",
      total_packets: 0,
      total_bytes: 0,
      total_flows: 0,
      active_hosts: 0,
      alerts: { critical: 0, high: 0, medium: 0, low: 0 },
      top_talkers: [],
    },
    timeline: [],
    protocols: [],
    ports: [],
    alerts: [],
    interfaces: [],
    sessions: [],
    entities: [],
    topology: { nodes: [], edges: [] },
    pipeline: {
      status: "degraded",
      active_sessions: 0,
      pending_packets: 0,
      queue_lag_ms: 0,
      drop_stages: { capture: 0, snapshot: 0, evidence: 0 },
      detector_failures: 0,
      stale_analytics: false,
      generated_at: Date.now() / 1000,
    },
  };
}

export const fetchHealth = createServerFn({ method: "GET" }).handler(async () => {
  try {
    return await requestApi<HealthStatus>("/health");
  } catch (error) {
    return offlineHealth(error);
  }
});

export const fetchSystemInfo = createServerFn({ method: "GET" }).handler(async () =>
  requestApi<SystemInfo>("/system"),
);

export const fetchInterfaces = createServerFn({ method: "GET" }).handler(async () =>
  (await requestApi<ApiRecord[]>("/interfaces")).map(mapInterface),
);

export const fetchSessions = createServerFn({ method: "GET" })
  .validator((data: { interface?: string; limit?: number; node?: string } = {}) => data)
  .handler(async ({ data }) => requestApi<CaptureSession[]>("/sessions", undefined, data));

export const fetchTodayStats = createServerFn({ method: "GET" }).handler(async () => {
  const data = await getStats();
  return {
    source: data.source,
    window_start: data.window_start,
    window_end: data.window_end,
    window_hours: data.window_hours,
    total_packets: data.total_packets,
    total_bytes: data.total_bytes,
    total_flows: data.total_flows,
    active_hosts: data.active_hosts,
    alerts: data.alerts,
    top_talkers: data.top_talkers,
  } as TodayStats;
});

export const fetchTimeline = createServerFn({ method: "GET" }).handler(
  async () => (await getStats()).timeline as TimelinePoint[],
);

export const fetchProtocolDist = createServerFn({ method: "GET" }).handler(
  async () => (await getStats()).protocols,
);

export const fetchPortDist = createServerFn({ method: "GET" }).handler(
  async () => (await getStats()).ports,
);

export const fetchEntities = createServerFn({ method: "GET" })
  .validator(
    (
      data: {
        source?: string;
        interface?: string;
        session?: string;
        limit?: number;
        cursor?: string;
        node?: string;
      } = {},
    ) => data,
  )
  .handler(async ({ data }) => {
    const source = data.source || (data.node ? undefined : "live");
    const page = await requestApiV2<CursorPage<ApiRecord>>("/risk/entities", undefined, {
      ...data,
      source,
      limit: Math.min(100, data.limit || 100),
    });
    return { ...page, items: page.items.map(mapEntity) } as CursorPage<Entity>;
  });

export const fetchEntityDetail = createServerFn({ method: "GET" })
  .validator((data: { ip: string; source?: string; node?: string }) => data)
  .handler(async ({ data }) => {
    const source = data.source || (data.node ? undefined : "live");
    const [investigation, risk] = await Promise.all([
      requestApi<Investigation>(
        `/entities/${encodeURIComponent(data.ip)}/investigation`,
        undefined,
        { source, node: data.node },
      ),
      requestApiV2<ApiRecord>(`/risk/entities/${encodeURIComponent(data.ip)}/explain`, undefined, {
        source,
        node: data.node,
      }),
    ]);
    const priority = Number(risk.priority_score || 0);
    return {
      ...investigation,
      priority_score: priority,
      risk_score: priority,
      risk_level: String(risk.risk_level || "LOW"),
      assessment_confidence: Number(risk.assessment_confidence || 0),
      confidence: Number(risk.assessment_confidence || 0),
      scope: asRecord(risk.scope),
      baseline_maturity: asRecord(risk.baseline_maturity),
      processing_completeness: String(risk.processing_completeness || "unknown"),
      contributors: Array.isArray(risk.contributors) ? risk.contributors : [],
      verdict: String(risk.risk_level || investigation.verdict || "LOW"),
    } as Investigation;
  });

export const fetchLookup = createServerFn({ method: "GET" })
  .validator((data: { ip: string; source?: string; node?: string }) => data)
  .handler(async ({ data }) =>
    requestApi<IpLookup>(`/lookup/${encodeURIComponent(data.ip)}`, undefined, {
      source: data.source || (data.node ? undefined : "live"),
      node: data.node,
    }),
  );

export const fetchAlerts = createServerFn({ method: "GET" })
  .validator(
    (
      data: {
        source?: string;
        interface?: string;
        session?: string;
        entity?: string;
        severity?: string;
        limit?: number;
        cursor?: string;
        node?: string;
      } = {},
    ) => data,
  )
  .handler(async ({ data }) => {
    const page = await requestApiV2<CursorPage<ApiRecord>>("/alerts", undefined, {
      ...data,
      limit: Math.min(100, data.limit || 100),
    });
    return { ...page, items: page.items.map(mapAlert) } as CursorPage<Alert>;
  });

export const fetchFlows = createServerFn({ method: "GET" })
  .validator(
    (
      data: {
        source?: string;
        interface?: string;
        session?: string;
        entity?: string;
        protocol?: string;
        port?: number;
        limit?: number;
        cursor?: string;
        node?: string;
      } = {},
    ) => data,
  )
  .handler(async ({ data }) => {
    const page = await requestApiV2<CursorPage<ApiRecord>>("/flows", undefined, {
      ...data,
      limit: Math.min(100, data.limit || 100),
    });
    return { ...page, items: page.items.map(mapFlow) } as CursorPage<Flow>;
  });

export const fetchFlowDetail = createServerFn({ method: "GET" })
  .validator((data: { id: number }) => data)
  .handler(async ({ data }) => mapFlow(await requestApiV2<ApiRecord>(`/flows/${data.id}`)));

export const fetchFindingDetail = createServerFn({ method: "GET" })
  .validator((data: { id: number }) => data)
  .handler(async ({ data }) => requestApiV2<ApiRecord>(`/findings/${data.id}`));

export const setFindingDisposition = createServerFn({ method: "POST" })
  .validator(
    (data: {
      id: number;
      verdict: "true_positive" | "false_positive" | "benign_expected" | "unknown";
      reason: string;
    }) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>(`/findings/${data.id}/disposition`, {
      method: "POST",
      body: JSON.stringify({
        verdict: data.verdict,
        reason: data.reason,
        actor: "ui-operator",
        scope: "finding",
      }),
    }),
  );

export const fetchTopology = createServerFn({ method: "GET" })
  .validator(
    (data: { source?: string; interface?: string; session?: string; node?: string } = {}) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>("/topology", undefined, {
      ...data,
      limit: 100,
    }),
  );

export const fetchPipelineHealth = createServerFn({ method: "GET" }).handler(async () =>
  requestApiV2<PipelineHealth>("/pipeline/health"),
);

export const fetchCarvedFiles = createServerFn({ method: "GET" })
  .validator((data: { source?: string; entity?: string } = {}) => data)
  .handler(async ({ data }) =>
    (await requestApi<ApiRecord[]>("/evidence", undefined, data)).map(mapEvidence),
  );

export const fetchDashboard = createServerFn({ method: "GET" })
  .validator((data: { node?: string } = {}) => data)
  .handler(async ({ data }): Promise<DashboardData> => {
    let health: HealthStatus;
    let summary: DashboardSummary;
    try {
      [health, summary] = await Promise.all([
        requestApi<HealthStatus>("/health"),
        requestApiV2<DashboardSummary>("/dashboard/summary", undefined, {
          source: data.node ? undefined : "live",
          node: data.node,
        }),
      ]);
    } catch (error) {
      health = offlineHealth(error);
      return emptyDashboard(health);
    }
    const alerts = summary.alerts.items.map(mapAlert);
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((alert) => {
      const key = alert.severity.toLowerCase() as keyof typeof severityCounts;
      severityCounts[key] += 1;
    });
    return {
      health,
      stats: {
        source: data.node ? `node:${data.node}` : "live",
        total_packets: summary.traffic.packets,
        total_bytes: summary.traffic.bytes,
        total_flows: summary.traffic.flows,
        active_hosts: summary.traffic.active_hosts,
        alerts: severityCounts,
        top_talkers: [],
      },
      timeline: summary.traffic.timeline,
      protocols: summary.traffic.protocols,
      ports: [],
      alerts,
      interfaces: [],
      sessions: [],
      entities: summary.risk.items.map(mapEntity),
      topology: { nodes: [], edges: [] },
      pipeline: summary.pipeline,
    };
  });

export const startEngine = createServerFn({ method: "POST" })
  .validator((data: { interface_id: string; backend?: string; source_type?: string }) => data)
  .handler(async ({ data }) =>
    requestApi<JsonObject>("/capture/start", {
      method: "POST",
      body: JSON.stringify({
        interface: data.interface_id,
        backend: data.backend,
        source_type: data.source_type || "network",
      }),
    }),
  );

export const stopEngine = createServerFn({ method: "POST" })
  .validator((data: { interface_id: string }) => data)
  .handler(async ({ data }) => {
    const sessions = await requestApi<CaptureSession[]>("/sessions", undefined, {
      interface: data.interface_id,
      limit: 10,
    });
    const active = sessions.find((item) =>
      ["running", "draining"].includes(String(item.processing_state || item.status).toLowerCase()),
    );
    if (active) {
      return requestApiV2<JsonObject>(`/captures/${encodeURIComponent(active.id)}/stop`, {
        method: "POST",
        body: JSON.stringify({ reason: "operator_stop" }),
      });
    }
    return requestApi<JsonObject>("/capture/stop", {
      method: "POST",
      body: JSON.stringify({ interface: data.interface_id }),
    });
  });

export const runSigmaHunt = createServerFn({ method: "POST" })
  .validator(
    (data: { source?: string; interface?: string; rule?: string; persist?: boolean }) => data,
  )
  .handler(async ({ data }) =>
    requestApi<{
      matched: number;
      persisted: boolean;
      active_rules: number;
      rejected_rules: number;
    }>("/hunts/sigma", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const resetDatabase = createServerFn({ method: "POST" })
  .validator((data: { confirmation: string }) => data)
  .handler(async ({ data }) =>
    requestApi<JsonObject>("/database/reset", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const fetchPluginInventory = createServerFn({ method: "GET" }).handler(async () =>
  requestApi<PluginInventory>("/plugins"),
);

export const fetchPluginCalibrationStatus = createServerFn({ method: "GET" })
  .validator((data: { detector_id?: string } = {}) => data)
  .handler(async ({ data }) =>
    requestApi<PluginCalibrationStatus>("/plugins/calibration/status", undefined, data),
  );

export const runPluginCalibration = createServerFn({ method: "POST" })
  .validator(
    (data: { detector_id: string; finding_type?: string; backend?: "all" | "python" | "rust" }) =>
      data,
  )
  .handler(async ({ data }) =>
    requestApi<PluginCalibrationRunResult>(
      "/plugins/calibration/run",
      {
        method: "POST",
        body: JSON.stringify({
          detector_id: data.detector_id,
          finding_type: data.finding_type || null,
          backend: data.backend || "all",
        }),
      },
      undefined,
      600_000,
    ),
  );

export const promotePluginCalibration = createServerFn({ method: "POST" })
  .validator((data: { report_path: string; reviewer: string; reason: string }) => data)
  .handler(async ({ data }) =>
    requestApi<JsonObject>(
      "/plugins/calibration/promote",
      {
        method: "POST",
        body: JSON.stringify(data),
      },
      undefined,
      60_000,
    ),
  );

export const verifyPluginCalibration = createServerFn({ method: "POST" }).handler(async () =>
  requestApi<JsonObject>("/plugins/calibration/verify", { method: "POST" }),
);

export const fetchSigmaRules = createServerFn({ method: "GET" }).handler(async () =>
  requestApi<SigmaRule[]>("/sigma/rules"),
);

export const fetchSigmaStatus = createServerFn({ method: "GET" }).handler(async () =>
  requestApi<JsonObject>("/sigma/status"),
);

export const previewSigmaUrl = createServerFn({ method: "POST" })
  .validator((data: { url: string }) => data)
  .handler(async ({ data }) =>
    requestApi<SigmaPreview>("/sigma/preview", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const installSigmaUrl = createServerFn({ method: "POST" })
  .validator((data: { url: string; expected_sha256: string }) => data)
  .handler(async ({ data }) =>
    requestApi<SigmaPreview>("/sigma/install", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const syncSigmaCorpus = createServerFn({ method: "POST" }).handler(async () =>
  requestApi<JsonObject>("/sigma/sync", { method: "POST" }, undefined, 180_000),
);

export const rollbackSigmaCorpus = createServerFn({ method: "POST" }).handler(async () =>
  requestApi<JsonObject>("/sigma/rollback", { method: "POST" }),
);

export const fetchAIStatus = createServerFn({ method: "GET" }).handler(async () =>
  requestApiV2<AIStatus>("/ai/status"),
);

export const fetchAIConversations = createServerFn({ method: "GET" })
  .validator((data: { limit?: number } = {}) => data)
  .handler(async ({ data }) =>
    requestApiV2<AIConversation[]>("/ai/conversations", undefined, data),
  );

export const fetchAIConversation = createServerFn({ method: "GET" })
  .validator((data: { conversation_id: string }) => data)
  .handler(async ({ data }) =>
    requestApiV2<AIConversation>(`/ai/conversations/${encodeURIComponent(data.conversation_id)}`),
  );

export const createAIConversation = createServerFn({ method: "POST" })
  .validator(
    (data: { title?: string; provider?: "ollama" | "openai"; scope?: AIContextScope } = {}) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<AIConversation>("/ai/conversations", {
      method: "POST",
      body: JSON.stringify({
        title: data.title || "New investigation",
        provider: data.provider || "ollama",
        scope: data.scope || {},
      }),
    }),
  );

export const startAIRun = createServerFn({ method: "POST" })
  .validator(
    (data: {
      prompt: string;
      conversation_id?: string;
      provider: "ollama" | "openai";
      scope: AIContextScope;
      research_mode: "auto" | "off";
      mode?: "auto" | "general" | "investigate" | "action";
    }) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<AIRun>("/ai/runs", { method: "POST", body: JSON.stringify(data) }),
  );

export const fetchAIRun = createServerFn({ method: "GET" })
  .validator((data: { run_id: string }) => data)
  .handler(async ({ data }) => requestApiV2<AIRun>(`/ai/runs/${encodeURIComponent(data.run_id)}`));

export const approveAIAction = createServerFn({ method: "POST" })
  .validator((data: { approval_id: string; confirmation?: string }) => data)
  .handler(async ({ data }) =>
    requestApiV2<AIRun>(`/ai/approvals/${encodeURIComponent(data.approval_id)}/confirm`, {
      method: "POST",
      body: JSON.stringify({ confirmation: data.confirmation || "" }),
    }),
  );

export const rejectAIAction = createServerFn({ method: "POST" })
  .validator((data: { approval_id: string; reason?: string }) => data)
  .handler(async ({ data }) =>
    requestApiV2<AIRun>(`/ai/approvals/${encodeURIComponent(data.approval_id)}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason: data.reason || "operator rejected" }),
    }),
  );

export const fetchMeshNodes = createServerFn({ method: "GET" })
  .validator((data: { limit?: number } = {}) => data)
  .handler(async ({ data }) => requestApiV2<SensorNode[]>("/mesh/nodes", undefined, data));

export const fetchMeshStatus = createServerFn({ method: "GET" }).handler(async () =>
  requestApiV2<JsonObject>("/mesh/status"),
);

export const fetchFleetSummary = createServerFn({ method: "GET" }).handler(async () =>
  requestApiV2<FleetSummary>("/fleet/summary"),
);

export const setupMeshController = createServerFn({ method: "POST" })
  .validator(
    (data: {
      mode: "local" | "vpn" | "public";
      address?: string;
      enrollment_port?: number;
      ingest_port?: number;
      acknowledge_public_risk?: boolean;
    }) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>("/mesh/controller/setup", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const meshControllerAction = createServerFn({ method: "POST" })
  .validator((data: { action: "start" | "stop" | "restart" }) => data)
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>(`/mesh/controller/${data.action}`, { method: "POST" }),
  );

export const initializeMeshController = createServerFn({ method: "POST" })
  .validator((data: { host?: string } = {}) => data)
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>("/mesh/controller/init", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const createMeshEnrollment = createServerFn({ method: "POST" })
  .validator((data: { name?: string; ttl_seconds?: number; max_uses?: number } = {}) => data)
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>("/mesh/enrollments", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  );

export const revokeMeshNode = createServerFn({ method: "POST" })
  .validator((data: { node_id: string; reason: string }) => data)
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>(`/mesh/nodes/${encodeURIComponent(data.node_id)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason: data.reason }),
    }),
  );

export const queueMeshNodeCommand = createServerFn({ method: "POST" })
  .validator(
    (data: {
      node_id: string;
      action: "capture.start" | "capture.stop" | "case.export";
      arguments: JsonObject;
      ttl_seconds?: number;
    }) => data,
  )
  .handler(async ({ data }) =>
    requestApiV2<JsonObject>(`/mesh/nodes/${encodeURIComponent(data.node_id)}/commands`, {
      method: "POST",
      body: JSON.stringify({
        action: data.action,
        arguments: data.arguments,
        ttl_seconds: data.ttl_seconds || 300,
      }),
    }),
  );

export const fetchEvidenceGraphStatus = createServerFn({ method: "GET" }).handler(async () =>
  requestApiV2<EvidenceGraphStatus>("/graph/status"),
);

export const materializeEvidenceGraph = createServerFn({ method: "POST" })
  .validator((data: { limit?: number } = {}) => data)
  .handler(async ({ data }) =>
    requestApiV2<EvidenceGraphStatus & { materialized: number }>(
      "/graph/materialize",
      { method: "POST" },
      data,
    ),
  );

export const fetchEvidenceGraphNeighborhood = createServerFn({ method: "GET" })
  .validator((data: { ip: string; node?: string; depth?: number; limit?: number }) => data)
  .handler(async ({ data }) => {
    const { ip, ...query } = data;
    return requestApiV2<{
      root: string;
      nodes: ApiRecord[];
      edges: ApiRecord[];
      truncated: boolean;
    }>(`/graph/neighborhood/${encodeURIComponent(ip)}`, undefined, query);
  });
