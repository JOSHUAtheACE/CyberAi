export interface Workspace {
  id: number;
  slug: string;
  name: string;
  environment: "LIVE" | "DEMO" | "REPLAY" | string;
  description?: string;
  internal_cidrs?: string[];
}

export interface Role {
  code: string;
  name: string;
  permissions: string[];
  description?: string;
}

export interface User {
  id: number;
  name: string;
  email: string;
  role: Role;
  is_demo: boolean;
  is_active: boolean;
  last_login_at: string | null;
}

export interface SessionInfo {
  user: User;
  csrf_token: string | null;
  demo_mode_enabled: boolean;
  workspaces: Workspace[];
  session_expires_at: string | null;
}

export interface KpiComparison {
  value: number;
  direction: "up" | "down" | "flat";
}

export interface Kpi {
  key: string;
  label: string;
  value: number | null;
  unit: string;
  help: string;
  comparison: KpiComparison | null;
  updated_at: string | null;
  note?: string | null;
}

export interface Insight {
  id: string;
  title: string;
  body: string;
  severity: string;
  confidence?: number | null;
  confidence_type?: string | null;
  alert_ids: string[];
  alert_id?: number | null;
  flow_ids: number[];
  detector: string | null;
  window: { start: string | null; end: string | null } | string;
  data_source: string;
  grounded: boolean;
}

export interface EvidencePreview {
  feature: string;
  observed: string | null;
  unit: string | null;
}

export interface EvidenceItem {
  id?: number;
  kind?: string;
  feature: string;
  observed_value: string | null;
  baseline_value: string | null;
  unit: string | null;
  description: string | null;
  flow_ids?: number[];
}

export interface AlertSummary {
  id: number;
  alert_code: string;
  first_seen: string;
  last_seen: string;
  threat_class: string;
  severity: string;
  confidence: number;
  confidence_type: string;
  detector_code: string;
  source_ip: string;
  source_port: number;
  dest_ip: string;
  dest_port: number;
  protocol: string;
  status: string;
  assignee: string | null;
  assignee_id: number | null;
  data_source: string;
  environment: string;
  scenario_id: string | null;
  summary: string;
  recurrence: number;
  flow_count: number;
  evidence_preview: EvidencePreview[];
  relation?: string;
}

export interface Flow {
  id: number;
  reference: string;
  ts: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  app_proto: string | null;
  bytes_total: number;
  bytes_out: number;
  bytes_in: number;
  packets: number;
  duration_ms: number;
  tcp_flags: string | null;
  direction: string | null;
  dns_query: string | null;
  dns_qtype: string | null;
  dns_rcode: string | null;
  tls_sni: string | null;
  tls_ja3: string | null;
  tls_version: string | null;
  tls_cipher: string | null;
  src_city: string | null;
  src_country: string | null;
  dst_city: string | null;
  dst_country: string | null;
  geo_source: string | null;
  scenario_id: string | null;
  suspicious?: boolean;
}

export interface CaseNote {
  id: number;
  author: string;
  body: string;
  created_at: string;
}

export interface InvestigationCase {
  id: number;
  case_code: string;
  alert_id: number;
  title: string;
  status: string;
  owner: string | null;
  owner_id: number | null;
  created_at: string;
  updated_at: string | null;
  notes: CaseNote[];
}

export interface EnrichmentRecord {
  id: number;
  provider: string;
  indicator: string;
  status: string;
  cached: boolean;
  payload: Record<string, unknown> | null;
  error: string | null;
  retrieved_at: string;
}

export interface AlertFacet {
  value: string;
  count: number;
}

export interface AlertsListResponse {
  items: AlertSummary[];
  total: number;
  page: number;
  page_size: number;
  period: { label: string; start: string; end: string };
  workspace: { slug: string; name: string; environment: string };
  facets: {
    statuses: AlertFacet[];
    severities: AlertFacet[];
    detectors: AlertFacet[];
    threat_classes: AlertFacet[];
  };
}

export interface AlertMeta {
  statuses: string[];
  severities: string[];
  detectors: { code: string; name: string; threat_class: string }[];
  assignees: { id: number; name: string; email: string; role: string }[];
  confidence_types: string[];
  notes: string[];
}

export interface AlertDetail extends AlertSummary {
  evidence: EvidenceItem[];
  baseline: Record<string, number> | null;
  flow_ids: number[];
  flows: Flow[];
  detection_reason: string;
  workspace_id: number;
  created_at: string;
  updated_at: string;
  detector: { code: string; confidence_type: string; model_version_id: number | null };
  related: AlertSummary[];
  similar: AlertSummary[];
  case: InvestigationCase | null;
  enrichment: EnrichmentRecord[];
  evidence_flow_coverage: {
    referenced: number;
    loaded: number;
    truncated: boolean;
    note: string;
  };
}

export interface OverviewResponse {
  workspace: { id: number; slug: string; name: string; environment: string };
  range: { key: string; label: string; start: string; end: string };
  has_data: boolean;
  kpis: Kpi[];
  totals: {
    flows: number;
    bytes_in: number;
    bytes_out: number;
    packets: number;
    unique_sources: number;
    avg_duration_ms: number;
    alerts: number;
    critical: number;
    high: number;
    duration: number;
  };
  previous: Record<string, number>;
  recent_alerts: AlertSummary[];
  insights: Insight[];
  sources: { total: number; connected: number; disconnected: number };
  generated_at: string;
  known_limitations: string[];
}

export interface TrafficResponse {
  range: { key: string; label: string; start: string; end: string; bucket: string };
  has_data: boolean;
  timeline: { bucket: string; bytes_in_mib: number; bytes_out_mib: number; packets: number; flows: number; pps: number }[];
  protocols: { protocol: string; count: number; share: number }[];
  directions: { direction: string; count: number }[];
  top_sources: { ip: string; bytes: number }[];
  top_destinations: { ip: string; bytes: number }[];
  top_ports: { port: number | string; count: number }[];
  duration_distribution: { bucket: string; count: number }[];
  summary: { flows: number; bytes_total: number; packets: number; avg_flow_bytes: number };
  truncated: boolean;
}

export interface ThreatsResponse {
  range: { key: string; label: string; start: string; end: string };
  has_data: boolean;
  total_alerts: number;
  severity_distribution: { severity: string; count: number }[];
  category_distribution: { category: string; count: number }[];
  detector_distribution: { detector: string; count: number }[];
  trend: { bucket: string; total: number; critical: number; high: number; medium: number; low: number; informational: number }[];
  critical_timeline: {
    id: number;
    alert_code: string;
    first_seen: string;
    threat_class: string;
    source_ip: string;
    dest_ip: string;
    status: string;
  }[];
  top_sources: { ip: string; alerts: number }[];
  top_destinations: { ip: string; alerts: number }[];
  relationships: { source: string; destination: string; alerts: number; severity: string }[];
  insights: Insight[];
  note: string;
}

export interface GeoArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  srcCity: string | null;
  srcCountry: string | null;
  dstCity: string | null;
  dstCountry: string | null;
  count: number;
  bytes: number;
  severity: string;
  flow_ids: number[];
  geo_source: string;
}

export interface GeoResponse {
  range: { key: string; label: string; start: string; end: string };
  status: "ready" | "insufficient_visibility" | string;
  message: string | null;
  arcs: GeoArc[];
  nodes: {
    name: string;
    country: string | null;
    lat: number;
    lng: number;
    volume: number;
    connections: number;
    severity: string;
  }[];
  unknown_locations: {
    source_without_location: number;
    destination_without_location: number;
    flows_total: number;
  };
  geo: {
    provider: string;
    configured: boolean;
    database_path: string | null;
    accuracy_notice: string;
  };
  demo_geo: boolean;
  notice: string;
}

export interface TopologyNode {
  id: string;
  label: string;
  internal: boolean;
  bytes: number;
  flows: number;
  protocols: string[];
  threat: boolean;
  severity: string | null;
  alerts: number;
  threat_classes: string[];
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  bytes: number;
  packets: number;
  flows: number;
  port: number | null;
  first_seen: string;
  last_seen: string;
  direction: string | null;
  suspicious: boolean;
}

export interface TopologyResponse {
  range: { key: string; label: string; start: string; end: string };
  has_data: boolean;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  meta: {
    nodes_total: number;
    edges_total: number;
    displayed_nodes: number;
    displayed_edges: number;
    truncated: boolean;
    derived_from: string;
  };
}

export interface HostProfile {
  ip: string;
  workspace: { slug: string; environment: string };
  period: { label: string; start: string; end: string };
  geo: { city: string | null; country: string | null; source: string | null };
  role: string;
  totals: { observations: number; outbound_flows: number; inbound_flows: number; bytes: number };
  timeline: { bucket: string; sent_mib: number; received_mib: number; flows: number }[];
  top_peers: { ip: string; flows: number }[];
  top_destination_ports: { port: number; flows: number }[];
  protocols: { protocol: string; flows: number }[];
  alerts: AlertSummary[];
  notice: string;
}

export interface DetectionModule {
  code: string;
  name: string;
  threat_class: string;
  technique: string;
  description: string;
  status: string;
  enabled: boolean;
  model_name: string;
  version: string;
  supported_inputs: string[];
  feature_count: number;
  thresholds: Record<string, number | number[]>;
  last_run_at: string | null;
  detections_total: number;
}

export interface DetectionCatalogItem extends DetectionModule {
  slug: string | null;
  confidence_badge: string;
}

export interface DetectionCatalogResponse {
  modules: DetectionCatalogItem[];
  notes: string[];
}

export interface DetectorPage {
  slug: string;
  workspace: { slug: string; name: string; environment: string };
  range: { key: string; label: string; start: string; end: string };
  module: {
    code: string;
    name: string;
    threat_class: string;
    technique: string;
    description: string;
    version: string;
    model_name: string;
    status: string;
    confidence_badge: string;
    thresholds: Record<string, number | number[]>;
  };
  kpis: { key: string; label: string; value: number | string | null; unit: string; help: string; note?: string }[];
  availability: Record<string, boolean>;
  coverage_note: string | null;
  charts: Record<string, Record<string, unknown>[]>;
  analysis: { label: string; value: string | number; note?: string }[];
  tables: Record<string, unknown>[];
  alerts: AlertSummary[];
  has_data: boolean;
}

export interface ModelVersion {
  id: number;
  detector_code: string;
  name: string;
  version: string;
  algorithm: string;
  confidence_type: string;
  dataset_name: string;
  dataset_version: string;
  dataset_licence: string;
  features: string[] | Record<string, unknown> | null;
  status: string;
  loaded: boolean;
  metrics_summary: {
    precision: number;
    recall: number;
    f1: number;
    false_positive_rate: number;
    roc_auc: number | null;
    threshold: number;
  };
  trained_at: string;
  artifact_exists: boolean;
}

export interface Evaluation {
  model_id: number;
  name: string;
  version: string;
  algorithm: string;
  confidence_type: string;
  dataset: {
    name: string;
    version: string;
    licence: string;
    train_period: string | null;
    validation_period: string | null;
    test_period: string | null;
    sample_count: number;
    class_distribution: Record<string, number> | null;
  };
  scores: {
    precision: number;
    recall: number;
    f1: number;
    false_positive_rate: number;
    roc_auc: number | null;
  };
  confusion: { tp: number; fp: number; fn: number; tn: number } | null;
  threshold: number | null;
  pr_curve: { recall: number; precision: number }[] | null;
  roc_curve: { fpr: number; tpr: number }[] | null;
  feature_importance: { feature: string; importance: number }[] | Record<string, number> | null;
  drift: Record<string, unknown> | null;
  splits: Record<string, unknown> | null;
  inference_latency_ms: number | null;
  comments: string | string[] | null;
  evaluated_at: string;
}

export interface AiOverview {
  generated_at: string;
  models: ModelVersion[];
  detectors: (DetectionModule & {
    ml_supported: boolean;
    model_code: string | null;
    model: ModelVersion | null;
    evaluation: Evaluation | null;
  })[];
  active_model_versions: Record<string, ModelVersion>;
  dataset_provenance: {
    names: string[];
    versions: string[];
    description: string;
    licence: string;
    not_production_accuracy: boolean;
  };
  score_semantics: { type: string; meaning: string }[];
  coverage_notes: { detector: string; reason: string }[];
  disclaimer: string;
}

export interface ReportItem {
  id: number;
  reference: string;
  kind: string;
  kind_label: string;
  title: string;
  environment: string;
  workspace_id: number;
  workspace: string | null;
  period: { start: string; end: string; label?: string };
  status: string;
  created_at: string;
  params: Record<string, unknown>;
  summary: Record<string, unknown> | null;
  peek: { alerts?: number | null; flows?: number | null; critical?: number | null };
  created_by?: string;
}

export interface ReportsListResponse {
  items: ReportItem[];
  total: number;
  page: number;
  page_size: number;
  kinds: { value: string; label: string }[];
}

export interface Provider {
  provider: string;
  display_name: string;
  category: string;
  docs_url: string;
  credential_env: string[];
  credentials_present: Record<string, boolean>;
  configured: boolean;
  enabled: boolean;
  status: string;
  last_success_at: string | null;
  last_error: string | null;
  rate_limit: string | { requests_per_minute?: number; tracking?: string } | null;
  attribution: string | null;
  notes: string | null;
  external_requests_allowed: boolean;
  credential_values_exposed: boolean;
}

export interface IntelProvidersResponse {
  providers: Provider[];
  external_enrichment_allowed: boolean;
  policy: { headline: string; rules: string[]; enable_via: string };
  cache: { indicators: number; enrichment_results: number; ttl_hours: number };
}

export interface IntelIndicator {
  id: number;
  provider: string;
  indicator: string;
  type: string;
  verdict: string;
  confidence: number | null;
  first_seen: string | null;
  last_seen: string | null;
  source_url: string | null;
  licence: string | null;
  retrieved_at: string;
  valid_until: string | null;
}

export interface ReplayDataset {
  id: number;
  scenario_id: string;
  name: string;
  threat_class: string;
  description: string;
  expected_features: string[];
  ground_truth: { threat: string; technique: string; labeled: boolean } | string;
  timespan: string | { start: string; end: string } | null;
  flow_count: number;
}

export interface UploadedReplayDataset {
  id: number;
  reference: string;
  filename: string | null;
  kind: string;
  records: number;
  environment: string;
  finished_at: string | null;
}

export interface ReplayDatasetsResponse {
  demo_datasets: ReplayDataset[];
  uploaded_datasets: UploadedReplayDataset[];
  speeds: number[];
  categories: { slug: string; detector: string }[];
  notes: string[];
}

export interface ReplaySession {
  id: number;
  reference: string;
  dataset_id: number | null;
  job_id: number | null;
  dataset_label: string;
  environment: string;
  demo: boolean;
  status: string;
  running: boolean;
  speed: number;
  cursor: number;
  total_records: number;
  records_processed: number;
  remaining_records: number;
  progress: number;
  alerts_generated: number;
  current_rate: number;
  processing_latency_ms: number | null;
  categories: string[];
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  recent_alerts?: AlertSummary[];
}

export interface TrafficSource {
  id: number;
  name: string;
  kind: string;
  identifier: string;
  status: string;
  workspace_id: number;
  last_seen_at: string | null;
  last_record_at: string | null;
  records_total: number;
  records_invalid: number;
  records_dropped: number;
  records_per_second: number;
  avg_latency_ms: number | null;
  has_key: boolean;
  config: Record<string, unknown>;
  stale?: boolean;
  connection_state?: string;
}

export interface SourcesResponse {
  workspace: { slug: string; name: string; environment: string };
  sources: TrafficSource[];
  collector_kinds: {
    kind: string;
    label: string;
    transport: string;
    record_contract: string;
  }[];
  ingest_endpoint: string;
  contract: {
    method: string;
    auth_headers: string[];
    body: Record<string, unknown>;
    notes: string[];
  };
}

export interface CaptureSummary {
  packet_count: number;
  capture_start: string | null;
  capture_end: string | null;
  validation: Record<string, unknown>;
}

export interface IngestionJob {
  id: number;
  reference: string;
  kind: string;
  environment: string;
  status: string;
  progress: number;
  filename: string | null;
  size_bytes: number;
  sha256: string | null;
  records_total: number;
  records_valid: number;
  records_rejected: number;
  alerts_generated: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stats: Record<string, unknown>;
  capture: CaptureSummary | null;
}

export interface JobsResponse {
  items: IngestionJob[];
  total: number;
  page: number;
  page_size: number;
  status_counts: Record<string, number>;
}

export interface PreviewResponse {
  kind: string;
  format?: string;
  valid: boolean;
  filename: string;
  size_bytes: number;
  record_count?: number;
  packet_count?: number;
  flow_count?: number;
  capture_start?: string;
  capture_end?: string;
  link_types?: number[];
  timestamp_range?: { start: string | null; end: string | null } | null;
  quality?: Record<string, unknown>;
  preview?: Record<string, unknown>[];
  sample_flows?: Record<string, unknown>[];
  notes?: string[];
  errors?: string[];
}

export interface SystemStatus {
  active_detectors: number;
  last_flow_at: string | null;
  geo: {
    provider: string;
    configured: boolean;
    database_path: string | null;
    accuracy_notice: string;
  };
  external_enrichment: boolean;
  llm_enabled: boolean;
  retention_days: number;
  storage: { upload_limit_mb: number; mode: string };
}

export interface AdminUser {
  id: number;
  name: string;
  email: string;
  role: Role;
  is_demo: boolean;
  is_active: boolean;
  last_login_at: string | null;
}

export interface RoleDefinition {
  code: string;
  name: string;
  description: string;
  permissions: string[];
  users: number;
}

export interface RolesResponse {
  roles: RoleDefinition[];
  permissions: { code: string; label: string }[];
  note: string;
}

export interface AuditEvent {
  id: number;
  ts: string;
  actor: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  meta: Record<string, unknown> | null;
}

export interface AuditResponse {
  items: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
  actions: { value: string; count: number }[];
}

export interface PlatformSettings {
  runtime: {
    demo_mode: { key: string; enabled: boolean; description: string; updated_at: string | null };
  };
  workspaces: Workspace[];
  limits: {
    upload_mb: number;
    max_preview_records: number;
    collector_records_per_request: number;
    retention_days: number;
  };
  notes: string[];
}

export interface AdminOverview {
  users: { total: number; active: number; disabled: number };
  records: { flows: number; alerts: number; reports: number; replay_sessions: number };
  audit_events: number;
  recent_events: { id: number; ts: string; level: string; category: string; message: string }[];
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}
