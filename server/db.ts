import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  generateId,
  generateSigningSecret,
  hashPassword,
  sha256Hex,
  type Environment,
} from './security.ts';

export interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  created_at: string;
}

export interface ProjectRow {
  id: string;
  user_id: string;
  name: string;
  rate_limit_per_minute: number;
  webhook_signing_secret: string;
  created_at: string;
}

export interface ApiKeyRow {
  id: string;
  project_id: string;
  environment: Environment;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: string; // JSON string
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface WebhookEndpointRow {
  id: string;
  project_id: string;
  environment: Environment;
  url: string;
  description: string;
  signing_secret: string;
  subscribed_events: string; // JSON string
  is_active: number;
  created_at: string;
}

export interface EventRow {
  id: string;
  project_id: string;
  environment: Environment;
  event_type: string;
  payload: string; // JSON string
  source_ip: string;
  idempotency_key: string | null;
  created_at: string;
}

export interface DeliveryAttemptRow {
  id: string;
  event_id: string;
  endpoint_id: string;
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

export interface GatewayLogRow {
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

export interface SandboxSinkRow {
  id: string;
  project_id: string;
  url: string;
  mode: 'healthy' | 'server_error' | 'timeout';
  created_at: string;
}

export interface SandboxSinkReceiptRow {
  id: string;
  sink_id: string;
  event_id: string;
  headers_json: string;
  payload_json: string;
  responded_status: number;
  received_at: string;
}

export function createDatabase(dbPath?: string): DatabaseSync {
  const targetPath = dbPath ?? path.resolve(process.cwd(), 'gatepulse.db');
  const db = new DatabaseSync(targetPath);

  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
      webhook_signing_secret TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      environment TEXT NOT NULL CHECK (environment IN ('test', 'live')),
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      scopes TEXT NOT NULL,
      last_used_at TEXT,
      revoked_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS webhook_endpoints (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      environment TEXT NOT NULL CHECK (environment IN ('test', 'live')),
      url TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      signing_secret TEXT NOT NULL,
      subscribed_events TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS idempotency_keys (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      environment TEXT NOT NULL CHECK (environment IN ('test', 'live')),
      idempotency_key TEXT NOT NULL,
      request_payload_hash TEXT NOT NULL,
      response_code INTEGER NOT NULL,
      response_body TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(project_id, environment, idempotency_key)
    );

    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      environment TEXT NOT NULL CHECK (environment IN ('test', 'live')),
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      idempotency_key TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS delivery_attempts (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
      attempt_number INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'success', 'failed')),
      http_status_code INTEGER,
      response_body TEXT,
      latency_ms INTEGER,
      error_message TEXT,
      next_retry_at TEXT,
      attempted_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_request_logs (
      id TEXT PRIMARY KEY,
      project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
      environment TEXT,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      error_code TEXT,
      message TEXT,
      latency_ms INTEGER NOT NULL,
      source_ip TEXT NOT NULL,
      request_id TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sandbox_sinks (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      url TEXT NOT NULL UNIQUE,
      mode TEXT NOT NULL DEFAULT 'healthy' CHECK (mode IN ('healthy', 'server_error', 'timeout')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sandbox_sink_receipts (
      id TEXT PRIMARY KEY,
      sink_id TEXT NOT NULL REFERENCES sandbox_sinks(id) ON DELETE CASCADE,
      event_id TEXT NOT NULL,
      headers_json TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      responded_status INTEGER NOT NULL,
      received_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_events_proj_env ON events(project_id, environment, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_attempts_pending ON delivery_attempts(status, next_retry_at);
    CREATE INDEX IF NOT EXISTS idx_attempts_event ON delivery_attempts(event_id);
    CREATE INDEX IF NOT EXISTS idx_gateway_logs_proj ON api_request_logs(project_id, created_at DESC);
  `);

  return db;
}

export const DEMO_USER_EMAIL = 'dev@gatepulse.dev';

export function seedDemoDataIfEmpty(db: DatabaseSync): void {
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  if (existingUsers.count > 0) return;

  const now = new Date();
  const iso = (offsetSeconds: number) => new Date(now.getTime() + offsetSeconds * 1000).toISOString();

  const userId = 'usr_demo_001';
  const projectId = 'prj_acme_001';
  const projectSecret = 'whsec_demo_a83f10c94e7b2d6f81a4c5e90b3d7f21';

  db.prepare(
    'INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, DEMO_USER_EMAIL, 'Alya Pratama', hashPassword('gatepulse123'), iso(-86400));

  db.prepare(
    'INSERT INTO projects (id, user_id, name, rate_limit_per_minute, webhook_signing_secret, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(projectId, userId, 'Acme Commerce Core', 60, projectSecret, iso(-86400));

  // Pre-seed hashed API keys (plain-text keys are NEVER stored in the DB)
  const testWriteHash = sha256Hex('gp_test_91f0c4a8d2e7b5130f6c8a2e4d9b7f10a3c5e7d9b1f3a5c7e9d1b3f5a7c9e1d3');
  const testReadHash = sha256Hex('gp_test_22b8e1c4a9d7f0315c8e2a4b6d9f1c3e5a7b9d1f3c5e7a9b1d3f5c7e9a1b3d5f');
  const testRevokedHash = sha256Hex('gp_test_00deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234');
  const liveWriteHash = sha256Hex('gp_live_77c3e9a1b5d2f8046e1a3c5b7d9f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f');

  const insertKey = db.prepare(
    `INSERT INTO api_keys (id, project_id, environment, name, key_prefix, key_hash, scopes, last_used_at, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  insertKey.run(
    'key_test_01',
    projectId,
    'test',
    'Checkout Service (Test)',
    'gp_test_91f0c4a8',
    testWriteHash,
    JSON.stringify(['events:write', 'endpoints:manage', 'logs:read']),
    iso(-420),
    null,
    iso(-43200)
  );
  insertKey.run(
    'key_test_02',
    projectId,
    'test',
    'Analytics Reader (Scoped)',
    'gp_test_22b8e1c4',
    testReadHash,
    JSON.stringify(['logs:read']),
    iso(-1800),
    null,
    iso(-36000)
  );
  insertKey.run(
    'key_test_03',
    projectId,
    'test',
    'Rotated CI Runner',
    'gp_test_00deadbe',
    testRevokedHash,
    JSON.stringify(['events:write']),
    iso(-15000),
    iso(-7200),
    iso(-80000)
  );
  insertKey.run(
    'key_live_01',
    projectId,
    'live',
    'Production Billing Gateway',
    'gp_live_77c3e9a1',
    liveWriteHash,
    JSON.stringify(['events:write', 'logs:read']),
    iso(-120),
    null,
    iso(-70000)
  );

  // Managed sandbox sinks in TEST mode
  const sinkUrl1 = 'https://sink.gatepulse.dev/r/orders-staging';
  const sinkUrl2 = 'https://sink.gatepulse.dev/r/analytics-staging';

  db.prepare('INSERT INTO sandbox_sinks (id, project_id, url, mode, created_at) VALUES (?, ?, ?, ?, ?)').run(
    'snk_01',
    projectId,
    sinkUrl1,
    'healthy',
    iso(-36000)
  );
  db.prepare('INSERT INTO sandbox_sinks (id, project_id, url, mode, created_at) VALUES (?, ?, ?, ?, ?)').run(
    'snk_02',
    projectId,
    sinkUrl2,
    'server_error',
    iso(-35000)
  );

  const insertEndpoint = db.prepare(
    `INSERT INTO webhook_endpoints (id, project_id, environment, url, description, signing_secret, subscribed_events, is_active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  insertEndpoint.run(
    'ep_test_01',
    projectId,
    'test',
    sinkUrl1,
    'Order Fulfillment Sandbox Sink',
    generateSigningSecret(),
    JSON.stringify(['order.*', 'payment.captured']),
    1,
    iso(-36000)
  );
  insertEndpoint.run(
    'ep_test_02',
    projectId,
    'test',
    sinkUrl2,
    'Audit & Retry Demo Sink (Simulated 500)',
    generateSigningSecret(),
    JSON.stringify(['*']),
    1,
    iso(-35000)
  );
  insertEndpoint.run(
    'ep_live_01',
    projectId,
    'live',
    'https://webhooks.acme-commerce.example/v1/gatepulse',
    'Primary Production Fulfillment Consumer',
    generateSigningSecret(),
    JSON.stringify(['order.paid', 'order.refunded']),
    1,
    iso(-60000)
  );

  // Seed historical events & delivery attempts
  const insertEvent = db.prepare(
    `INSERT INTO events (id, project_id, environment, event_type, payload, source_ip, idempotency_key, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertAttempt = db.prepare(
    `INSERT INTO delivery_attempts (id, event_id, endpoint_id, attempt_number, status, http_status_code, response_body, latency_ms, error_message, next_retry_at, attempted_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const evt1 = 'evt_0192b8c4d1a07e4f8c2a1b3d';
  const evt2 = 'evt_0192b8c4e8f27a1b9d4c2e6f';
  const evt3 = 'evt_0192b8c504a17c3d5e7f9a1b';
  const evtLive1 = 'evt_0192b8c529d47f1e3a5c7b9d';

  insertEvent.run(
    evt1,
    projectId,
    'test',
    'order.paid',
    JSON.stringify({
      order_id: 'ord_99481',
      amount_idr: 450000,
      currency: 'IDR',
      customer_email: 'budi@example.com',
    }),
    '203.0.113.42',
    'req_uuid_99281',
    iso(-1800)
  );
  insertAttempt.run(
    'att_01',
    evt1,
    'ep_test_01',
    1,
    'success',
    200,
    JSON.stringify({ received: true, sink: 'orders-staging' }),
    28,
    null,
    null,
    iso(-1799),
    iso(-1800)
  );
  insertAttempt.run(
    'att_02',
    evt1,
    'ep_test_02',
    1,
    'failed',
    500,
    JSON.stringify({ error: 'Simulated downstream worker failure' }),
    41,
    'HTTP 500 Internal Server Error',
    null,
    iso(-1799),
    iso(-1800)
  );
  insertAttempt.run(
    'att_03',
    evt1,
    'ep_test_02',
    2,
    'failed',
    500,
    JSON.stringify({ error: 'Simulated downstream worker failure' }),
    38,
    'HTTP 500 Internal Server Error',
    null,
    iso(-1789),
    iso(-1799)
  );

  insertEvent.run(
    evt2,
    projectId,
    'test',
    'user.registered',
    JSON.stringify({
      user_id: 'usr_8841',
      plan: 'developer_pro',
      region: 'ap-southeast-1',
    }),
    '203.0.113.88',
    'req_uuid_99282',
    iso(-900)
  );
  insertAttempt.run(
    'att_04',
    evt2,
    'ep_test_02',
    1,
    'failed',
    500,
    JSON.stringify({ error: 'Simulated downstream worker failure' }),
    34,
    'HTTP 500 Internal Server Error',
    null,
    iso(-899),
    iso(-900)
  );

  insertEvent.run(
    evt3,
    projectId,
    'test',
    'order.shipped',
    JSON.stringify({
      order_id: 'ord_99481',
      carrier: 'JNE Express',
      tracking_number: 'JNE99102841',
    }),
    '203.0.113.42',
    null,
    iso(-300)
  );
  insertAttempt.run(
    'att_05',
    evt3,
    'ep_test_01',
    1,
    'success',
    200,
    JSON.stringify({ received: true, sink: 'orders-staging' }),
    19,
    null,
    null,
    iso(-299),
    iso(-300)
  );

  insertEvent.run(
    evtLive1,
    projectId,
    'live',
    'order.paid',
    JSON.stringify({
      order_id: 'ord_live_55120',
      amount_idr: 1250000,
      currency: 'IDR',
    }),
    '198.51.100.14',
    'idem_live_55120',
    iso(-600)
  );
  insertAttempt.run(
    'att_live_01',
    evtLive1,
    'ep_live_01',
    1,
    'success',
    200,
    JSON.stringify({ status: 'ok' }),
    64,
    null,
    null,
    iso(-599),
    iso(-600)
  );

  // Seed gateway security audit logs so Inspector shows real security telemetry
  const insertLog = db.prepare(
    `INSERT INTO api_request_logs (id, project_id, environment, method, path, status_code, error_code, message, latency_ms, source_ip, request_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insertLog.run(
    generateId('log'),
    projectId,
    'test',
    'POST',
    '/v1/events',
    202,
    null,
    'Event order.paid diterima dan dimasukkan ke antrean pengiriman.',
    7,
    '203.0.113.42',
    'req_a18f20c4b1',
    iso(-300)
  );
  insertLog.run(
    generateId('log'),
    projectId,
    'test',
    'POST',
    '/v1/events',
    401,
    'INVALID_HMAC_SIGNATURE',
    'Tanda tangan digital pada header X-Signature tidak cocok dengan payload dan timestamp yang dikirim.',
    3,
    '198.51.100.77',
    'req_8f92a10c4b',
    iso(-240)
  );
  insertLog.run(
    generateId('log'),
    projectId,
    'test',
    'POST',
    '/v1/events',
    403,
    'INSUFFICIENT_SCOPE',
    'API Key gp_test_22b8e1c4 tidak memiliki scope izin events:write.',
    2,
    '203.0.113.99',
    'req_7c11e509ab',
    iso(-180)
  );
  insertLog.run(
    generateId('log'),
    projectId,
    'live',
    'POST',
    '/v1/events',
    202,
    null,
    'Event order.paid diterima dan dimasukkan ke antrean pengiriman.',
    8,
    '198.51.100.14',
    'req_904b77d21c',
    iso(-600)
  );
}
