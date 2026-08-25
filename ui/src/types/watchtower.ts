export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface CursorPage<T> {
  items: T[];
  next_cursor: string | null;
  limit: number;
}

export interface HealthStatus {
  status: "ok" | "degraded" | "offline";
  version: string;
  database: string;
  daemon: "online" | "offline";
  daemon_healthy: boolean;
  message?: string;
}

export interface SystemInfo {
  hostname: string;
  platform: string;
  uptime: number;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  is_admin: boolean;
  capture_capable: boolean;
  version: string;
}

export interface NetworkInterface {
  id: string;
  device_id: string;
  source_type: string;
  name: string;
  description: string;
  status: "up" | "down";
  mac: string | null;
  ipv4: string | null;
  addresses: string[];
  backends: string[];
  capturing: boolean;
  unavailable_reason: string;
  engine?: JsonObject | null;
}

export interface CaptureSession {
  id: string;
  sensor_node_id?: string | null;
  source_type: string;
  device_id: string;
  interface: string | null;
  backend: string;
  source: string;
  status: string;
  started_at: number;
  ended_at?: number | null;
  received_packets?: number;
  emitted_packets?: number;
  processed_packets?: number;
  dropped_packets?: number;
  detector_errors?: number;
  evidence_dropped?: number;
  snapshot_dropped?: number;
  pending_packets?: number;
  queue_lag_ms?: number;
  queue_lag_max_ms?: number;
  processing_state?: string;
  complete?: boolean;
  completeness?: string;
  completion_reason?: string | null;
}

export interface SensorNode {
  id: string;
  name: string;
  status: string;
  platform?: string | null;
  agent_version?: string | null;
  capabilities?: JsonObject;
  health?: JsonObject;
  last_seen_at?: number | null;
  certificate_fingerprint?: string | null;
}

export interface FleetNode extends SensorNode {
  readiness: string;
  capture_active: boolean;
  active_sessions: number;
  alert_count: number;
  urgent_alerts: number;
  finding_count: number;
  priority_score: number;
  ingestion_lag_seconds?: number | null;
  spool_bytes: number;
  spool_capacity_bytes: number;
  clock_skew_seconds?: number | null;
  certificate_expires_in_seconds?: number | null;
}

export interface FleetSummary {
  generated_at: number;
  nodes: FleetNode[];
  totals: {
    sensors: number;
    ready: number;
    capturing: number;
    urgent_alerts: number;
    deduplicated_findings: number;
  };
  controller: JsonObject;
}

export interface EvidenceGraphStatus {
  enabled: boolean;
  available: boolean;
  uri?: string | null;
  reason?: string;
  freshness: "current" | "stale" | "unavailable" | string;
  pending: number;
  failed: number;
  last_materialized_at?: number | null;
}

export interface RiskContributor {
  finding_type?: string;
  detector_id?: string;
  correlation_group?: string;
  effective_contribution?: number;
  explanation?: string;
}

export interface RiskEntity {
  subject: string;
  priority_score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  assessment_confidence: number;
  scope: { type: string; id: string };
  baseline_maturity: { state?: string; sample_count?: number; mature?: boolean };
  processing_completeness: string;
  contributors: RiskContributor[];
}

export interface PipelineHealth {
  status: "ok" | "degraded";
  generated_at: number;
  active_sessions: number;
  pending_packets: number;
  queue_lag_ms: number;
  queue_lag_max_ms?: number;
  drop_stages: { capture: number; snapshot: number; evidence: number };
  detector_failures: number;
  stale_analytics: boolean;
  database_pool?: {
    size?: number;
    checked_out?: number;
    checked_in?: number;
    overflow?: number;
    capacity?: number;
    peak_checked_out?: number;
    timeouts?: number;
    sqlite_lock_contention?: number;
  };
  shutdown_stages?: JsonObject;
}

export interface TodayStats {
  source: string;
  window_start?: number | null;
  window_end?: number | null;
  window_hours?: number;
  total_packets: number;
  total_bytes: number;
  total_flows: number;
  active_hosts: number;
  alerts: { critical: number; high: number; medium: number; low: number };
  top_talkers: Array<{ ip: string; bytes: number; hostname: string }>;
}

export interface TimelinePoint {
  timestamp: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  flows: number;
}

export interface ProtocolEntry {
  protocol: string;
  count: number;
  percentage: number;
}

export interface PortEntry {
  port: number;
  service: string;
  count: number;
  percentage: number;
}

export interface Entity {
  ip: string;
  mac: string | null;
  hostname: string | null;
  username: string | null;
  user: string | null;
  os: string | null;
  vendor?: string | null;
  device_type?: string | null;
  asset_role?: string | null;
  risk_score: number;
  priority_score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  assessment_confidence: number;
  baseline_maturity: RiskEntity["baseline_maturity"];
  processing_completeness: string;
  contributors: RiskContributor[];
  raw_risk_score?: number;
  confidence_score: number;
  identity_source: string | null;
  alert_count: number;
  carved_file_count: number;
  flow_count: number;
  total_packets: number;
  total_bytes: number;
  source: string;
}

export interface LookupName {
  type: string;
  value: string;
  source: string;
}

export interface LookupService {
  name: string;
  port: number;
  protocol: string;
  direction: "served" | "consumed" | string;
  packets: number;
  bytes: number;
}

export interface LookupPeer {
  ip: string;
  bytes: number;
  packets: number;
}

export interface IpLookup {
  ip: string;
  source: string;
  generated_at: number;
  scope: string;
  subnet: string | null;
  ip_version: number;
  is_private: boolean;
  is_global: boolean;
  summary: string;
  endpoint_identity?: EndpointIdentitySummary | null;
  endpoint_processes?: EndpointProcessObservation[];
  identity: {
    hostname?: string | null;
    reverse_dns?: string | null;
    mac?: string | null;
    vendor?: string | null;
    organization?: string | null;
    company?: string | null;
    device_type?: string | null;
    asset_role?: string | null;
    os?: string | null;
    username?: string | null;
    full_name?: string | null;
    identity_source?: string | null;
    identity_confidence?: number;
  };
  enrichment: {
    scope: string;
    subnet?: string | null;
    ip_version: number;
    asn?: string | null;
    isp?: string | null;
    org?: string | null;
    reverse_dns?: string | null;
    observed_name_count: number;
    source: string;
  };
  asset_profile: JsonObject;
  activity: {
    flow_count: number;
    alert_count: number;
    artifact_count: number;
    total_packets: number;
    total_bytes: number;
    outbound_bytes: number;
    inbound_bytes: number;
    protocols: string[];
    first_seen?: number | null;
    last_seen?: number | null;
  };
  services: LookupService[];
  peers: { internal: LookupPeer[]; external: LookupPeer[] };
  observed_names: LookupName[];
  location: {
    label: string;
    city?: string | null;
    country?: string | null;
    latitude: number;
    longitude: number;
  };
  gaps: string[];
  next_actions: string[];
}

export interface Alert {
  id: number;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  score: number;
  explanation: string;
  entity_ip: string;
  src_ip: string;
  dst_ip: string;
  timestamp: number;
  ai_verdict: string | null;
  source: string;
  evidence: JsonObject;
  capture_session_id: string | null;
  capture_interface: string | null;
  capture_backend: string | null;
  capture_type: string;
  occurrence_count: number;
  impact?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  effective_contribution?: number;
  current_entity_priority?: number;
  risk_level?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  assessment_confidence?: number;
  disposition?: string | null;
  scope?: JsonObject;
  processing_completeness?: string;
}

export interface Flow {
  id: number;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  start_time: number;
  last_seen: number;
  packet_count: number;
  byte_count: number;
  duration: number;
  source: string;
  capture_session_id: string | null;
  capture_interface: string | null;
  capture_backend: string | null;
  capture_type: string;
  sensor_node_id?: string | null;
  l7_metadata: JsonObject;
  src_identity?: EndpointIdentitySummary | null;
  dst_identity?: EndpointIdentitySummary | null;
}

export interface EndpointProcessObservation {
  id: string;
  observed_at: number;
  event_type: string;
  image?: string | null;
  pid?: number | null;
  user_name?: string | null;
  service_names?: string[];
  local_ip?: string | null;
  local_port?: number | null;
  remote_ip?: string | null;
  remote_port?: number | null;
  protocol?: string | null;
}

export interface EndpointIdentitySummary {
  entity_ip: string;
  identity_type: string;
  identity_label: string;
  confidence: number;
  verification: string;
  identity_state?:
    | "confirmed_endpoint"
    | "probable_endpoint"
    | "unconfirmed_target"
    | "protocol_group"
    | "address_only"
    | string;
  evidence_completeness?: number;
  next_action?: string | null;
  observation_count?: number;
  model_version: string;
  updated_at?: number | null;
  source?: string;
  capture_interface?: string | null;
  capture_session_id?: string | null;
}

export interface TopologyNode {
  data: {
    id: string;
    label: string;
    type: string;
    risk: number;
    risk_level?: string;
    assessment_confidence?: number;
  };
}

export interface TopologyEdge {
  data: { source: string; target: string; weight: number };
}

export interface CarvedFile {
  id: number;
  entity_ip: string;
  filename: string;
  extension: string;
  filetype: string;
  size: number;
  md5?: string;
  sha256: string;
  vt_score: string;
  vt_status: string;
  source_ip: string;
  source: string;
  timestamp: number;
  capture_session_id?: string | null;
}

export interface Investigation {
  target: string;
  source: string;
  generated_at: number;
  verdict: string;
  risk_score: number;
  priority_score: number;
  risk_level: string;
  assessment_confidence: number;
  scope: JsonObject;
  baseline_maturity: JsonObject;
  processing_completeness: string;
  contributors: RiskContributor[];
  confidence: number;
  summary: string;
  asset_profile: JsonObject;
  findings: string[];
  alert_groups: JsonObject[];
  correlations: JsonObject[];
  timeline: Array<{ timestamp: number; type: string; ref: string; summary: string }>;
  evidence: JsonObject[];
  next_actions: string[];
  lookup?: IpLookup;
}

export interface PcapResult {
  id: string;
  status: string;
  filename: string;
  file_size: number;
  source: string;
  mode: string;
  backend: string;
  progress: number;
  bytes_processed: number;
  duration_seconds: number;
  error?: string | null;
  summary: JsonObject;
  packet_count: number;
  flow_count: number;
  entity_count: number;
  alert_count: number;
  entities: Entity[];
  alerts: Alert[];
  protocols: ProtocolEntry[];
  ports: PortEntry[];
}

export interface DashboardData {
  health: HealthStatus;
  stats: TodayStats;
  timeline: TimelinePoint[];
  protocols: ProtocolEntry[];
  ports: PortEntry[];
  alerts: Alert[];
  interfaces: NetworkInterface[];
  sessions: CaptureSession[];
  entities: Entity[];
  topology: { nodes: TopologyNode[]; edges: TopologyEdge[] };
  pipeline: PipelineHealth;
}

export interface PluginRecord {
  name: string;
  type?: string;
  source_type?: string;
  enabled: boolean;
  valid: boolean;
  errors: number;
  last_error: string;
  api_version: number;
  supported_link_types?: string[];
  device_count?: number;
  backends?: string[];
  detector_id?: string;
  calibrated?: boolean;
  calibration_level?:
    | "NOT_APPLICABLE"
    | "UNCALIBRATED"
    | "CORPUS_VALIDATED"
    | "FIELD_CALIBRATED"
    | "MIXED";
  calibration?: PluginCalibrationRecord[];
}

export interface PluginCalibrationRecord {
  finding_type: string;
  calibration_level: "UNCALIBRATED" | "CORPUS_VALIDATED" | "FIELD_CALIBRATED";
  effective_cap: number;
  attestation_digest: string;
  stale_reason: string;
  metrics?: {
    precision?: number;
    recall?: number;
    false_alert_rate?: number;
  };
}

export interface PluginInventory {
  parsers: PluginRecord[];
  detectors: PluginRecord[];
  hardware: PluginRecord[];
}

export interface CalibrationReportSummary {
  report_path: string;
  digest: string;
  created_at: number;
  backend_selection: string;
  passed: boolean;
  awarded_level: "UNCALIBRATED" | "CORPUS_VALIDATED" | "FIELD_CALIBRATED";
  failures: string[];
  field_failures: string[];
  runner_peak_memory_bytes?: number;
  target: {
    detector_id?: string;
    detector_version?: string;
    finding_type?: string;
    policy_digest?: string;
  };
  metrics: {
    positive_cases?: number;
    benign_cases?: number;
    true_positive?: number;
    false_positive?: number;
    true_negative?: number;
    false_negative?: number;
    precision?: number;
    recall?: number;
    false_alert_rate?: number;
    evidence_completeness?: number;
    execution_seconds?: number;
    peak_memory_bytes?: number;
    backend_parity?: boolean;
    deterministic?: boolean;
    secrets_redacted?: boolean;
    state_within_limit?: boolean;
  };
}

export interface PluginCalibrationTarget extends PluginCalibrationRecord {
  detector_id: string;
  detector_version: string;
  report_count: number;
  corpus_available?: boolean;
  corpus_case_count?: number;
  corpus_error?: string;
  latest_report?: CalibrationReportSummary | null;
}

export interface PluginCalibrationStatus {
  model_version: string;
  targets: PluginCalibrationTarget[];
}

export interface PluginCalibrationRunResult {
  detector_id: string;
  passed: boolean;
  reports: CalibrationReportSummary[];
}

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status: string;
  level: string;
  category: string;
  source: string;
  path: string | null;
  compatible: boolean;
  errors: string[];
}

export interface SigmaPreview extends SigmaRule {
  url: string;
  sha256: string;
  content: string;
  installed?: boolean;
}

export interface AIContextScope {
  source?: string | null;
  interface?: string | null;
  session_id?: string | null;
  node_id?: string | null;
  time_start?: number | null;
  time_end?: number | null;
  case_id?: string | null;
  target_ips?: string[];
  max_records?: number;
}

export interface AICitation {
  id?: string;
  kind: "watchtower" | "external" | string;
  reference: string;
  source: string;
  url?: string | null;
  summary: string;
  timestamp?: number | null;
  retrieved_at?: number | null;
  content_hash?: string | null;
  scope?: AIContextScope;
}

export interface AIMessage {
  id: string;
  role: "user" | "assistant" | string;
  content: string;
  created_at: number;
  citations: AICitation[];
  run_id?: string | null;
}

export interface AIConversation {
  id: string;
  title: string;
  provider: "ollama" | "openai" | string;
  scope: AIContextScope;
  created_at: number;
  updated_at: number;
  archived: boolean;
  messages?: AIMessage[];
}

export interface AIToolCall {
  id: string;
  tool_name: string;
  risk_tier: "read" | "confirm" | "typed" | string;
  status: string;
  arguments_json: string;
  result_json?: string | null;
  created_at: number;
}

export interface AIApproval {
  id: string;
  run_id: string;
  invocation_id: string;
  tool_name: string;
  risk_tier: "confirm" | "typed" | string;
  status: string;
  requester?: string;
  confirmation_phrase?: string | null;
  scope_json: string;
  expires_at: number;
}

export interface AIRun {
  id: string;
  conversation_id: string;
  provider: string;
  status:
    | "QUEUED"
    | "RUNNING"
    | "AWAITING_APPROVAL"
    | "COMPLETE"
    | "DEGRADED"
    | "NEEDS_SCOPE"
    | "FAILED"
    | "REJECTED"
    | string;
  final_text?: string | null;
  error?: string | null;
  scope: AIContextScope;
  policy: JsonObject;
  created_at: number;
  updated_at: number;
  tool_calls: AIToolCall[];
  approvals: AIApproval[];
  citations: AICitation[];
  analyst_version?: string;
  rounds?: number;
  tool_call_count?: number;
  context_chars?: number;
  citation_coverage?: number;
  mode?: "general" | "investigate" | "action" | string;
  validation_status?: "validated" | "degraded" | "not_run" | string;
  supported_claims?: number;
  inferred_claims?: number;
  blocked_claims?: number;
  numeric_accuracy?: number;
}

export interface AIProviderStatus {
  name: "ollama" | "openai" | string;
  available: boolean;
  model?: string;
  detail: string;
  label?: string;
  local?: boolean;
  configured?: boolean;
  credential_configured?: boolean;
  requires_credential?: boolean;
  supports_tools?: boolean;
  supports_research?: boolean;
  base_url?: string;
  description?: string;
  agentic_ready?: boolean;
  capability_probe?: string;
  native_tool_calls?: boolean;
  latency_ms?: number;
}

export interface AIResearchSource {
  name: string;
  lane: "authoritative" | "threat_intelligence" | "open_web" | string;
  enabled: boolean;
  credential_required: boolean;
}

export interface AIStatus {
  mode: string;
  providers: AIProviderStatus[];
  tools: Array<{ name: string; description: string; risk_tier: string; active: boolean }>;
  research_sources: AIResearchSource[];
}
