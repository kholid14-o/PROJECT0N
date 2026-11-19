import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import type { DatabaseSync } from 'node:sqlite';
import {
  buildGatewayError,
  generateId,
  IDEMPOTENCY_TTL_SECONDS,
  MAX_PAYLOAD_BYTES,
  sha256Hex,
  SlidingWindowRateLimiter,
  validateEventPayload,
  validateTimestamp,
  verifyHmacSignature,
  type ApiScope,
  type Environment,
} from './security.ts';
import { validateWebhookUrl, type DnsLookupFn } from './ssrf.ts';
import { enqueueDeliveriesForEvent, replayEventDeliveries } from './dispatcher.ts';
import type { ApiKeyRow, ProjectRow } from './db.ts';

interface GatewayContext {
  requestId: string;
  startTimeMs: number;
  rawBody: string;
  parsedBody?: unknown;
  project?: ProjectRow;
  apiKey?: ApiKeyRow;
  environment?: Environment;
}

declare module 'express-serve-static-core' {
  interface Request {
    gateway?: GatewayContext;
  }
}

export interface GatewayOptions {
  db: DatabaseSync;
  rateLimiter?: SlidingWindowRateLimiter;
  nowMs?: () => number;
  dnsLookup?: DnsLookupFn;
  onEventQueued?: () => void;
}

function getSourceIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress ?? '127.0.0.1';
}

function recordGatewayLog(
  db: DatabaseSync,
  params: {
    projectId: string | null;
    environment: string | null;
    method: string;
    path: string;
    statusCode: number;
    errorCode: string | null;
    message: string | null;
    latencyMs: number;
    sourceIp: string;
    requestId: string;
  }
): void {
  try {
    db.prepare(
      `INSERT INTO api_request_logs (
        id, project_id, environment, method, path, status_code, error_code, message, latency_ms, source_ip, request_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      generateId('log'),
      params.projectId,
      params.environment,
      params.method,
      params.path,
      params.statusCode,
      params.errorCode,
      params.message,
      params.latencyMs,
      params.sourceIp,
      params.requestId,
      new Date().toISOString()
    );
  } catch {
    // Logging must never crash request handling
  }
}

export function createGatewayRouter(options: GatewayOptions): express.Router {
  const { db } = options;
  const rateLimiter = options.rateLimiter ?? new SlidingWindowRateLimiter(60_000);
  const nowMs = options.nowMs ?? (() => Date.now());
  const router = express.Router();

  const sendGatewayError = (
    req: Request,
    res: Response,
    status: number,
    type: Parameters<typeof buildGatewayError>[0],
    code: string,
    message: string
  ) => {
    const ctx = req.gateway;
    const requestId = ctx?.requestId ?? generateId('req');
    const latencyMs = Math.max(1, Date.now() - (ctx?.startTimeMs ?? Date.now()));
    recordGatewayLog(db, {
      projectId: ctx?.project?.id ?? null,
      environment: ctx?.environment ?? null,
      method: req.method,
      path: `/v1${req.path}`,
      statusCode: status,
      errorCode: code,
      message,
      latencyMs,
      sourceIp: getSourceIp(req),
      requestId,
    });
    res.status(status).json(buildGatewayError(type, code, message, requestId));
  };

  // Layer 1: Payload Size & Content-Type Guard (for methods with body)
  const rawBodyAndSizeGuard = (req: Request, res: Response, next: NextFunction) => {
    const requestId = generateId('req');
    req.gateway = {
      requestId,
      startTimeMs: Date.now(),
      rawBody: '',
    };
    res.setHeader('X-Request-Id', requestId);

    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      const contentType = req.headers['content-type'] ?? '';
      if (!contentType.toLowerCase().includes('application/json')) {
        sendGatewayError(
          req,
          res,
          400,
          'invalid_request_error',
          'INVALID_CONTENT_TYPE',
          'Header Content-Type harus berupa application/json.'
        );
        return;
      }

      const contentLengthHeader = req.headers['content-length'];
      if (contentLengthHeader) {
        const declaredLength = Number.parseInt(String(contentLengthHeader), 10);
        if (Number.isFinite(declaredLength) && declaredLength > MAX_PAYLOAD_BYTES) {
          sendGatewayError(
            req,
            res,
            413,
            'payload_too_large',
            'PAYLOAD_TOO_LARGE',
            `Ukuran body melebihi batas maksimal ${MAX_PAYLOAD_BYTES / 1024} KB (256 KB).`
          );
          return;
        }
      }

      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let aborted = false;

      req.on('data', (chunk: Buffer) => {
        if (aborted) return;
        totalBytes += chunk.length;
        if (totalBytes > MAX_PAYLOAD_BYTES) {
          aborted = true;
          sendGatewayError(
            req,
            res,
            413,
            'payload_too_large',
            'PAYLOAD_TOO_LARGE',
            `Ukuran payload melebihi batas maksimal ${MAX_PAYLOAD_BYTES / 1024} KB (256 KB).`
          );
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        if (aborted) return;
        const rawBody = Buffer.concat(chunks).toString('utf8');
        req.gateway!.rawBody = rawBody;
        if (!rawBody.trim()) {
          sendGatewayError(
            req,
            res,
            400,
            'invalid_request_error',
            'INVALID_JSON',
            'Body JSON tidak boleh kosong.'
          );
          return;
        }
        try {
          req.gateway!.parsedBody = JSON.parse(rawBody);
          next();
        } catch {
          sendGatewayError(
            req,
            res,
            400,
            'invalid_request_error',
            'INVALID_JSON',
            'Format JSON tidak valid (malformed JSON).'
          );
        }
      });

      req.on('error', () => {
        if (!aborted && !res.headersSent) {
          sendGatewayError(
            req,
            res,
            400,
            'invalid_request_error',
            'REQUEST_STREAM_ERROR',
            'Gagal membaca body permintaan.'
          );
        }
      });
      return;
    }

    next();
  };

  // Layer 2: API Key Authenticator & Scope Verifier
  const authenticateAndAuthorize = (requiredScope: ApiScope) => {
    return (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        sendGatewayError(
          req,
          res,
          401,
          'authentication_error',
          'INVALID_API_KEY',
          'Header Authorization dengan skema "Bearer gp_..." wajib disertakan.'
        );
        return;
      }

      const rawToken = authHeader.slice(7).trim();
      if (!rawToken.startsWith('gp_test_') && !rawToken.startsWith('gp_live_')) {
        sendGatewayError(
          req,
          res,
          401,
          'authentication_error',
          'INVALID_API_KEY',
          'Format API Key tidak valid. Gunakan kunci berawalan gp_test_ atau gp_live_.'
        );
        return;
      }

      const tokenHash = sha256Hex(rawToken);
      const keyRow = db
        .prepare('SELECT * FROM api_keys WHERE key_hash = ?')
        .get(tokenHash) as unknown as ApiKeyRow | undefined;

      if (!keyRow || keyRow.revoked_at !== null) {
        sendGatewayError(
          req,
          res,
          401,
          'authentication_error',
          'INVALID_API_KEY',
          'API Key tidak ditemukan atau telah dicabut (revoked).'
        );
        return;
      }

      const projectRow = db
        .prepare('SELECT * FROM projects WHERE id = ?')
        .get(keyRow.project_id) as unknown as ProjectRow | undefined;

      if (!projectRow) {
        sendGatewayError(
          req,
          res,
          401,
          'authentication_error',
          'INVALID_API_KEY',
          'Project pemilik API Key tidak ditemukan.'
        );
        return;
      }

      req.gateway!.apiKey = keyRow;
      req.gateway!.project = projectRow;
      req.gateway!.environment = keyRow.environment;

      let scopes: string[] = [];
      try {
        scopes = JSON.parse(keyRow.scopes) as string[];
      } catch {
        scopes = [];
      }

      if (!scopes.includes(requiredScope)) {
        sendGatewayError(
          req,
          res,
          403,
          'authorization_error',
          'INSUFFICIENT_SCOPE',
          `API Key "${keyRow.key_prefix}..." tidak memiliki scope izin "${requiredScope}".`
        );
        return;
      }

      db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(
        new Date(nowMs()).toISOString(),
        keyRow.id
      );

      next();
    };
  };

  // Layer 3: Dynamic Per-Project/Key Rate Limiter
  const applyRateLimit = (req: Request, res: Response, next: NextFunction) => {
    const project = req.gateway!.project!;
    const environment = req.gateway!.environment!;
    const bucketKey = `${project.id}:${environment}`;
    const decision = rateLimiter.consume(bucketKey, project.rate_limit_per_minute, nowMs());

    res.setHeader('X-RateLimit-Limit', String(decision.limit));
    res.setHeader('X-RateLimit-Remaining', String(decision.remaining));
    res.setHeader('X-RateLimit-Reset', String(decision.resetUnix));

    if (!decision.allowed) {
      res.setHeader('Retry-After', String(decision.retryAfterSeconds));
      sendGatewayError(
        req,
        res,
        429,
        'rate_limit_error',
        'RATE_LIMIT_EXCEEDED',
        `Batas kuota ${decision.limit} permintaan/menit untuk project "${project.name}" terlampaui. Coba lagi dalam ${decision.retryAfterSeconds} detik.`
      );
      return;
    }

    next();
  };

  // Layer 4: HMAC-SHA256 & Timestamp Replay Guard
  const verifyHmacAndReplay = (req: Request, res: Response, next: NextFunction) => {
    const project = req.gateway!.project!;
    const rawBody = req.gateway!.rawBody;
    const timestampHeader = req.headers['x-timestamp'] as string | undefined;
    const signatureHeader = req.headers['x-signature'] as string | undefined;

    const tsCheck = validateTimestamp(timestampHeader, Math.floor(nowMs() / 1000));
    if (!tsCheck.ok) {
      sendGatewayError(req, res, 401, 'authentication_error', tsCheck.code, tsCheck.message);
      return;
    }

    if (!signatureHeader) {
      sendGatewayError(
        req,
        res,
        401,
        'authentication_error',
        'INVALID_HMAC_SIGNATURE',
        'Header X-Signature wajib disertakan untuk verifikasi integritas payload.'
      );
      return;
    }

    const valid = verifyHmacSignature(
      timestampHeader!.trim(),
      rawBody,
      project.webhook_signing_secret,
      signatureHeader
    );
    if (!valid) {
      sendGatewayError(
        req,
        res,
        401,
        'authentication_error',
        'INVALID_HMAC_SIGNATURE',
        'Tanda tangan digital pada header X-Signature tidak cocok dengan payload dan timestamp yang dikirim.'
      );
      return;
    }

    next();
  };

  router.use(rawBodyAndSizeGuard);

  // POST /v1/events — Full 6-Layer Security Gateway Pipeline
  router.post(
    '/events',
    authenticateAndAuthorize('events:write'),
    applyRateLimit,
    verifyHmacAndReplay,
    (req: Request, res: Response) => {
      const ctx = req.gateway!;
      const project = ctx.project!;
      const environment = ctx.environment!;
      const currentMs = nowMs();
      const currentIso = new Date(currentMs).toISOString();

      // Layer 5: Idempotency Check
      const rawIdemKey = req.headers['idempotency-key'];
      const idempotencyKey =
        typeof rawIdemKey === 'string' && rawIdemKey.trim() ? rawIdemKey.trim() : null;
      const payloadHash = sha256Hex(ctx.rawBody);

      if (idempotencyKey) {
        if (idempotencyKey.length > 128) {
          sendGatewayError(
            req,
            res,
            422,
            'invalid_request_error',
            'INVALID_IDEMPOTENCY_KEY',
            'Panjang Idempotency-Key maksimal 128 karakter.'
          );
          return;
        }

        const existing = db
          .prepare(
            `SELECT * FROM idempotency_keys
             WHERE project_id = ? AND environment = ? AND idempotency_key = ? AND expires_at > ?`
          )
          .get(project.id, environment, idempotencyKey, currentIso) as
          | {
              request_payload_hash: string;
              response_code: number;
              response_body: string;
            }
          | undefined;

        if (existing) {
          if (existing.request_payload_hash !== payloadHash) {
            sendGatewayError(
              req,
              res,
              409,
              'conflict_error',
              'IDEMPOTENCY_CONFLICT',
              `Idempotency-Key "${idempotencyKey}" sudah pernah digunakan dengan isi payload yang berbeda.`
            );
            return;
          }

          res.setHeader('X-Idempotent-Replayed', 'true');
          const cachedBody = JSON.parse(existing.response_body);
          recordGatewayLog(db, {
            projectId: project.id,
            environment,
            method: 'POST',
            path: '/v1/events',
            statusCode: existing.response_code,
            errorCode: null,
            message: `Idempotent replay hit (${idempotencyKey})`,
            latencyMs: Math.max(1, Date.now() - ctx.startTimeMs),
            sourceIp: getSourceIp(req),
            requestId: ctx.requestId,
          });
          res.status(existing.response_code).json(cachedBody);
          return;
        }
      }

      // Layer 6: Strict Schema Validation & Database Persistence
      const validation = validateEventPayload(ctx.parsedBody);
      if (!validation.ok) {
        sendGatewayError(
          req,
          res,
          422,
          'invalid_request_error',
          'VALIDATION_ERROR',
          validation.message
        );
        return;
      }

      const eventId = generateId('evt');
      const sourceIp = getSourceIp(req);
      const serializedPayload = JSON.stringify(validation.payloadData);

      db.prepare(
        `INSERT INTO events (id, project_id, environment, event_type, payload, source_ip, idempotency_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        eventId,
        project.id,
        environment,
        validation.eventType,
        serializedPayload,
        sourceIp,
        idempotencyKey,
        currentIso
      );

      const matchedEndpoints = enqueueDeliveriesForEvent(
        db,
        eventId,
        project.id,
        environment,
        validation.eventType
      );

      const responseBody = {
        id: eventId,
        status: 'accepted',
        environment,
        event_type: validation.eventType,
        matched_endpoints: matchedEndpoints,
        request_id: ctx.requestId,
        created_at: currentIso,
      };

      if (idempotencyKey) {
        const expiresIso = new Date(currentMs + IDEMPOTENCY_TTL_SECONDS * 1000).toISOString();
        db.prepare(
          `INSERT INTO idempotency_keys (
            id, project_id, environment, idempotency_key, request_payload_hash, response_code, response_body, expires_at, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(project_id, environment, idempotency_key) DO UPDATE SET
            request_payload_hash = excluded.request_payload_hash,
            response_code = excluded.response_code,
            response_body = excluded.response_body,
            expires_at = excluded.expires_at`
        ).run(
          generateId('idem'),
          project.id,
          environment,
          idempotencyKey,
          payloadHash,
          202,
          JSON.stringify(responseBody),
          expiresIso,
          currentIso
        );
      }

      recordGatewayLog(db, {
        projectId: project.id,
        environment,
        method: 'POST',
        path: '/v1/events',
        statusCode: 202,
        errorCode: null,
        message: `Event ${validation.eventType} diterima (${matchedEndpoints} target endpoint).`,
        latencyMs: Math.max(1, Date.now() - ctx.startTimeMs),
        sourceIp,
        requestId: ctx.requestId,
      });

      options.onEventQueued?.();
      res.status(202).json(responseBody);
    }
  );

  // Programmatic REST API: GET /v1/events
  router.get(
    '/events',
    authenticateAndAuthorize('logs:read'),
    applyRateLimit,
    (req: Request, res: Response) => {
      const project = req.gateway!.project!;
      const environment = req.gateway!.environment!;
      const rows = db
        .prepare(
          'SELECT id, environment, event_type, payload, source_ip, idempotency_key, created_at FROM events WHERE project_id = ? AND environment = ? ORDER BY created_at DESC LIMIT 50'
        )
        .all(project.id, environment);
      res.json({ data: rows });
    }
  );

  // Programmatic REST API: POST /v1/events/:id/replay
  router.post(
    '/events/:id/replay',
    authenticateAndAuthorize('events:write'),
    applyRateLimit,
    (req: Request, res: Response) => {
      const project = req.gateway!.project!;
      const result = replayEventDeliveries(db, String(req.params.id), project.id);
      if (result.queuedCount === 0) {
        sendGatewayError(
          req,
          res,
          404,
          'invalid_request_error',
          'EVENT_OR_ENDPOINTS_NOT_FOUND',
          'Event tidak ditemukan atau tidak ada endpoint aktif yang berlangganan.'
        );
        return;
      }
      options.onEventQueued?.();
      res.status(202).json({ replayed: true, queued_attempts: result.queuedCount });
    }
  );

  // Programmatic REST API: POST /v1/endpoints (Anti-SSRF enforced)
  router.post(
    '/endpoints',
    authenticateAndAuthorize('endpoints:manage'),
    applyRateLimit,
    async (req: Request, res: Response) => {
      const project = req.gateway!.project!;
      const environment = req.gateway!.environment!;
      const body = (req.gateway!.parsedBody ?? {}) as Record<string, unknown>;
      const rawUrl = typeof body.url === 'string' ? body.url : '';
      const check = await validateWebhookUrl(rawUrl, environment, options.dnsLookup);
      if (!check.ok) {
        sendGatewayError(req, res, 422, 'invalid_request_error', check.code, check.message);
        return;
      }

      const subscribedEvents = Array.isArray(body.subscribed_events)
        ? body.subscribed_events.filter((item): item is string => typeof item === 'string')
        : ['*'];

      const endpointId = generateId('ep');
      const signingSecret = `whsec_${sha256Hex(generateId('sec')).slice(0, 40)}`;
      const createdAt = new Date(nowMs()).toISOString();

      db.prepare(
        `INSERT INTO webhook_endpoints (
          id, project_id, environment, url, description, signing_secret, subscribed_events, is_active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
      ).run(
        endpointId,
        project.id,
        environment,
        check.normalizedUrl,
        typeof body.description === 'string' ? body.description : '',
        signingSecret,
        JSON.stringify(subscribedEvents.length > 0 ? subscribedEvents : ['*']),
        createdAt
      );

      res.status(201).json({
        id: endpointId,
        environment,
        url: check.normalizedUrl,
        subscribed_events: subscribedEvents.length > 0 ? subscribedEvents : ['*'],
        signing_secret: signingSecret,
        created_at: createdAt,
      });
    }
  );

  return router;
}
