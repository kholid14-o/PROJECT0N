export type Environment = 'test' | 'live';
export type ApiScope = 'events:write' | 'endpoints:manage' | 'logs:read';
export type ConsoleTab =
  | 'overview'
  | 'keys'
  | 'endpoints'
  | 'events'
  | 'playground'
  | 'errors';

export interface User {
  id: string;
  email: string;
  name: string;
  created_at: string;
}

export interface Project {
  id: string;
  user_id: string;
  name: string;
  rate_limit_per_minute: number;
  webhook_signing_secret: string;
  created_at: string;
}

export interface ApiKeyItem {
  id: string;
  project_id: string;
  environment: Environment;
  name: string;
  key_prefix: string;
  scopes: ApiScope[];
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface SandboxSink {
  id: string;
  project_id: string;
  url: string;
  mode: 'healthy' | 'server_error' | 'timeout';
  created_at: string;
}

export interface WebhookEndpointItem {
  id: string;
  project_id: string;
  environment: Environment;
  url: string;
  description: string;
  signing_secret: string;
  subscribed_events: string[];
  is_active: boolean;
  created_at: string;
  sandbox_sink: SandboxSink | null;
}

export interface DeliveryAttemptItem {
  id: string;
  event_id: string;
  endpoint_id: string;
  endpoint_url: string;
  endpoint_description: string;
  attempt_number: number;
  status: 'pending' | 'success' | 'failed';
  http_status_code: number | null;
  response_body: string | null;
  latency_ms: number | null;
  error_message: string | null;
  next_retry_at: string | null;
  attempted_at: string | null;
  created_at: string;
}

export interface EventItem {
  id: string;
  project_id: string;
  environment: Environment;
  event_type: string;
  payload: Record<string, unknown>;
  source_ip: string;
  idempotency_key: string | null;
  created_at: string;
  attempts: DeliveryAttemptItem[];
}

export interface GatewayLogItem {
  id: string;
  project_id: string | null;
  environment: string | null;
  method: string;
  path: string;
  status_code: number;
  error_code: string | null;
  message: string | null;
  latency_ms: number;
  source_ip: string;
  request_id: string;
  created_at: string;
}

export interface GatewayMetrics {
  events_ingested: number;
  active_keys: number;
  active_endpoints: number;
  blocked_requests: number;
  deliveries: {
    success?: number;
    failed?: number;
    pending?: number;
  };
}

export interface SandboxReceipt {
  id: string;
  sink_id: string;
  event_id: string;
  headers: Record<string, string>;
  payload: Record<string, unknown>;
  responded_status: number;
  received_at: string;
}
