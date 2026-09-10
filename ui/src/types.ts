export interface Stats {
  queries_today: number;
  blocked_today: number;
  allowed_today: number;
  cache_hits: number;
  avg_latency_ms: number;
}
export interface Telemetry {
  queries: number[];
  blocked: number[];
  cache: number[];
  latency: number[];
}
export interface QueryEvent {
  domain: string;
  timestamp: string;
  status: string;
  client_ip: string;
}
export interface Device {
  ip: string;
  name: string;
  profile: string;
}
export interface DomainCount {
  domain: string;
  count: number;
}
export interface Domains {
  top_domains: DomainCount[];
  infrastructure: DomainCount[];
  unknown: DomainCount[];
}
export interface Policy {
  allowed: string[];
  denied: string[];
  device_allowed: Record<string, string[]>;
  device_denied: Record<string, string[]>;
}
export interface Blocklist {
  name: string;
  enabled: boolean;
  rule_count: number;
}
export interface Schedule {
  id: string;
  label: string;
  domain: string;
  action: "Allow" | "Block";
  days: number[];
  start_minutes: number;
  end_minutes: number;
  device_id: string | null;
  enabled: boolean;
}
export interface PrivacyConfig {
  enabled: boolean;
  default_budget: number;
  device_budgets: Record<string, number>;
}
export interface PrivacyDevice {
  device: string;
  total_queries: number;
  unique_domains: number;
  blocked_queries: number;
  tracking_companies: number;
  advertising_identifiers: number;
  applications: number;
  network_spread: number;
  country_spread: number;
  quiet_hour_queries: number;
  score: number;
}
export interface Privacy {
  config: PrivacyConfig;
  devices: PrivacyDevice[];
}
export interface GraphNode {
  id: string;
  label: string;
  kind: string;
}
export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  count: number;
  first_seen: string;
  last_seen: string;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  hours: number;
  edge_limit?: number;
  min_count?: number;
  truncated?: boolean;
  observation_limit?: number;
}
export interface Upstream {
  enabled: boolean;
  mode: string;
  resolvers: string[];
}
export interface Action {
  domain: string;
  action_type: string;
  payload_url: string | null;
  method: string | null;
  shell_command: string | null;
  html_content: string | null;
  success_msg: string | null;
  token?: string | null;
}
export interface ActionLog {
  id: number;
  domain: string;
  outcome: string;
  detail: string | null;
  triggered_at: string;
}
export interface Telegram {
  enabled: boolean;
  bot_token: string;
  bot_token_configured: boolean;
  chat_id: string;
  threat_threshold: number;
  notify_on_block: boolean;
}
export interface Dhcp {
  enabled: boolean;
  server_ip: string;
  router_ip: string;
  subnet_mask: string;
  start_ip: string;
  end_ip: string;
  lease_duration_secs: number;
}
export interface Result {
  success: boolean;
  message: string;
}
