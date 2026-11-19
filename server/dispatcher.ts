import type { DatabaseSync } from 'node:sqlite';
import {
  computeHmacSignature,
  generateId,
  matchesEventPattern,
  RETRY_BACKOFF_SECONDS,
  type Environment,
} from './security.ts';
import { SANDBOX_SINK_HOST } from './ssrf.ts';
import type {
  DeliveryAttemptRow,
  EventRow,
  SandboxSinkRow,
  WebhookEndpointRow,
} from './db.ts';

export const MAX_AUTO_RETRIES = 3; // Initial attempt (1) + up to 3 retries (attempts 2, 3, 4)

export type FetchLike = typeof globalThis.fetch;

export function enqueueDeliveriesForEvent(
  db: DatabaseSync,
  eventId: string,
  projectId: string,
  environment: Environment,
  eventType: string
): number {
  const endpoints = db
    .prepare(
      'SELECT * FROM webhook_endpoints WHERE project_id = ? AND environment = ? AND is_active = 1'
    )
    .all(projectId, environment) as unknown as WebhookEndpointRow[];

  const nowIso = new Date().toISOString();
  const insertAttempt = db.prepare(
    `INSERT INTO delivery_attempts (
      id, event_id, endpoint_id, attempt_number, status, next_retry_at, created_at
    ) VALUES (?, ?, ?, ?, 'pending', NULL, ?)`
  );

  let matchedCount = 0;
  for (const ep of endpoints) {
    let patterns: string[] = [];
    try {
      patterns = JSON.parse(ep.subscribed_events) as string[];
    } catch {
      patterns = [];
    }
    if (matchesEventPattern(patterns, eventType)) {
      insertAttempt.run(generateId('att'), eventId, ep.id, 1, nowIso);
      matchedCount += 1;
    }
  }
  return matchedCount;
}

export function replayEventDeliveries(
  db: DatabaseSync,
  eventId: string,
  projectId: string,
  endpointId?: string
): { queuedCount: number } {
  const event = db
    .prepare('SELECT * FROM events WHERE id = ? AND project_id = ?')
    .get(eventId, projectId) as unknown as EventRow | undefined;

  if (!event) {
    return { queuedCount: 0 };
  }

  let endpoints: WebhookEndpointRow[];
  if (endpointId) {
    endpoints = db
      .prepare(
        'SELECT * FROM webhook_endpoints WHERE id = ? AND project_id = ? AND environment = ? AND is_active = 1'
      )
      .all(endpointId, projectId, event.environment) as unknown as WebhookEndpointRow[];
  } else {
    const allActive = db
      .prepare(
        'SELECT * FROM webhook_endpoints WHERE project_id = ? AND environment = ? AND is_active = 1'
      )
      .all(projectId, event.environment) as unknown as WebhookEndpointRow[];

    endpoints = allActive.filter((ep) => {
      try {
        const patterns = JSON.parse(ep.subscribed_events) as string[];
        return matchesEventPattern(patterns, event.event_type);
      } catch {
        return false;
      }
    });
  }

  const nowIso = new Date().toISOString();
  const maxAttemptStmt = db.prepare(
    'SELECT COALESCE(MAX(attempt_number), 0) as max_num FROM delivery_attempts WHERE event_id = ? AND endpoint_id = ?'
  );
  const insertAttempt = db.prepare(
    `INSERT INTO delivery_attempts (
      id, event_id, endpoint_id, attempt_number, status, next_retry_at, created_at
    ) VALUES (?, ?, ?, ?, 'pending', NULL, ?)`
  );

  let queuedCount = 0;
  for (const ep of endpoints) {
    const row = maxAttemptStmt.get(eventId, ep.id) as { max_num: number };
    const nextAttemptNumber = (row?.max_num ?? 0) + 1;
    insertAttempt.run(generateId('att'), eventId, ep.id, nextAttemptNumber, nowIso);
    queuedCount += 1;
  }

  return { queuedCount };
}

export interface ProcessResult {
  processed: number;
  succeeded: number;
  failed: number;
  retried: number;
}

export async function processPendingDeliveries(
  db: DatabaseSync,
  options?: {
    fetchFn?: FetchLike;
    nowMs?: () => number;
    retryDelaysSeconds?: number[];
  }
): Promise<ProcessResult> {
  const fetchFn = options?.fetchFn ?? globalThis.fetch;
  const nowMs = options?.nowMs ?? (() => Date.now());
  const retryDelaysSeconds = options?.retryDelaysSeconds ?? RETRY_BACKOFF_SECONDS;

  const currentMs = nowMs();
  const currentIso = new Date(currentMs).toISOString();

  const pending = db
    .prepare(
      `SELECT da.*
       FROM delivery_attempts da
       WHERE da.status = 'pending'
         AND (da.next_retry_at IS NULL OR da.next_retry_at <= ?)
       ORDER BY da.created_at ASC
       LIMIT 25`
    )
    .all(currentIso) as unknown as DeliveryAttemptRow[];

  let succeeded = 0;
  let failed = 0;
  let retried = 0;

  for (const attempt of pending) {
    const event = db
      .prepare('SELECT * FROM events WHERE id = ?')
      .get(attempt.event_id) as unknown as EventRow | undefined;
    const endpoint = db
      .prepare('SELECT * FROM webhook_endpoints WHERE id = ?')
      .get(attempt.endpoint_id) as unknown as WebhookEndpointRow | undefined;

    if (!event || !endpoint) {
      db.prepare(
        `UPDATE delivery_attempts
         SET status = 'failed', error_message = 'Event or endpoint no longer exists', attempted_at = ?
         WHERE id = ?`
      ).run(new Date(nowMs()).toISOString(), attempt.id);
      failed += 1;
      continue;
    }

    let parsedPayload: unknown = {};
    try {
      parsedPayload = JSON.parse(event.payload);
    } catch {
      parsedPayload = {};
    }

    const outgoingEnvelope = JSON.stringify({
      id: event.id,
      event_type: event.event_type,
      environment: event.environment,
      created_at: event.created_at,
      data: parsedPayload,
    });

    const timestampSec = Math.floor(nowMs() / 1000);
    const signature = computeHmacSignature(timestampSec, outgoingEnvelope, endpoint.signing_secret);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'GatePulse-Webhook/1.0',
      'X-GatePulse-Event-Id': event.id,
      'X-GatePulse-Timestamp': String(timestampSec),
      'X-GatePulse-Signature': signature,
      'X-GatePulse-Attempt': String(attempt.attempt_number),
    };

    const startMs = Date.now();
    let httpStatus: number | null = null;
    let responseBody = '';
    let errorMessage: string | null = null;
    let isSuccess = false;

    try {
      const parsedUrl = new URL(endpoint.url);
      if (parsedUrl.hostname.toLowerCase() === SANDBOX_SINK_HOST) {
        const sink = db
          .prepare('SELECT * FROM sandbox_sinks WHERE url = ?')
          .get(endpoint.url) as unknown as SandboxSinkRow | undefined;
        const mode = sink?.mode ?? 'healthy';

        if (mode === 'healthy') {
          httpStatus = 200;
          responseBody = JSON.stringify({
            received: true,
            sink: parsedUrl.pathname,
            verified_signature: true,
          });
          isSuccess = true;
        } else if (mode === 'server_error') {
          httpStatus = 500;
          responseBody = JSON.stringify({
            error: 'Simulated downstream server error (HTTP 500)',
          });
          errorMessage = 'HTTP 500 Internal Server Error';
          isSuccess = false;
        } else {
          httpStatus = null;
          responseBody = '';
          errorMessage = 'Connection timed out after 5000ms (simulated offline receiver)';
          isSuccess = false;
        }

        if (sink) {
          db.prepare(
            `INSERT INTO sandbox_sink_receipts (id, sink_id, event_id, headers_json, payload_json, responded_status, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).run(
            generateId('rcp'),
            sink.id,
            event.id,
            JSON.stringify(headers),
            outgoingEnvelope,
            httpStatus ?? 504,
            new Date(nowMs()).toISOString()
          );
        }
      } else {
        const res = await fetchFn(endpoint.url, {
          method: 'POST',
          headers,
          body: outgoingEnvelope,
          signal: AbortSignal.timeout(5000),
        });
        httpStatus = res.status;
        const text = await res.text().catch(() => '');
        responseBody = text.slice(0, 2000);
        if (res.ok) {
          isSuccess = true;
        } else {
          isSuccess = false;
          errorMessage = `Endpoint returned HTTP ${res.status}`;
        }
      }
    } catch (err) {
      isSuccess = false;
      const msg = err instanceof Error ? err.message : String(err);
      errorMessage = msg.includes('Timeout') || msg.includes('abort')
        ? 'Request timeout (> 5000ms)'
        : `Delivery failed: ${msg}`;
    }

    const latencyMs = Math.max(1, Date.now() - startMs);
    const attemptedIso = new Date(nowMs()).toISOString();

    if (isSuccess) {
      db.prepare(
        `UPDATE delivery_attempts
         SET status = 'success',
             http_status_code = ?,
             response_body = ?,
             latency_ms = ?,
             error_message = NULL,
             attempted_at = ?
         WHERE id = ?`
      ).run(httpStatus, responseBody, latencyMs, attemptedIso, attempt.id);
      succeeded += 1;
    } else {
      db.prepare(
        `UPDATE delivery_attempts
         SET status = 'failed',
             http_status_code = ?,
             response_body = ?,
             latency_ms = ?,
             error_message = ?,
             attempted_at = ?
         WHERE id = ?`
      ).run(httpStatus, responseBody || null, latencyMs, errorMessage, attemptedIso, attempt.id);
      failed += 1;

      // Schedule automatic exponential backoff retry if within retry budget
      // Initial attempt is 1; up to 3 automatic retries -> attempt_number 2, 3, 4
      if (attempt.attempt_number <= MAX_AUTO_RETRIES) {
        const delaySec = retryDelaysSeconds[attempt.attempt_number - 1] ?? 300;
        const nextRetryIso = new Date(nowMs() + delaySec * 1000).toISOString();
        db.prepare(
          `INSERT INTO delivery_attempts (
            id, event_id, endpoint_id, attempt_number, status, next_retry_at, created_at
          ) VALUES (?, ?, ?, ?, 'pending', ?, ?)`
        ).run(
          generateId('att'),
          attempt.event_id,
          attempt.endpoint_id,
          attempt.attempt_number + 1,
          nextRetryIso,
          attemptedIso
        );
        retried += 1;
      }
    }
  }

  return {
    processed: pending.length,
    succeeded,
    failed,
    retried,
  };
}
