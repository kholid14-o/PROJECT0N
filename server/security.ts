import crypto from 'node:crypto';

export type Environment = 'test' | 'live';
export type ApiScope = 'events:write' | 'endpoints:manage' | 'logs:read';

export const ALL_SCOPES: ApiScope[] = ['events:write', 'endpoints:manage', 'logs:read'];

export const MAX_PAYLOAD_BYTES = 256 * 1024; // 256 KB
export const TIMESTAMP_TOLERANCE_SECONDS = 300; // 5 minutes
export const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60; // 24 hours
export const RETRY_BACKOFF_SECONDS = [10, 60, 300];
export const MAX_DELIVERY_ATTEMPTS = 3;

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function generateId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '')}`;
}

export function generateApiKey(environment: Environment): {
  rawKey: string;
  keyPrefix: string;
  keyHash: string;
} {
  // 256-bit high-entropy random secret
  const randomPart = crypto.randomBytes(32).toString('hex');
  const rawKey = `gp_${environment}_${randomPart}`;
  // Store visible prefix (first 16 chars e.g. gp_test_1a2b3c4d) and SHA-256 hash
  const keyPrefix = rawKey.slice(0, 16);
  const keyHash = sha256Hex(rawKey);
  return { rawKey, keyPrefix, keyHash };
}

export function generateSigningSecret(): string {
  return `whsec_${crypto.randomBytes(24).toString('hex')}`;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

export interface SessionPayload {
  userId: string;
  email: string;
  exp: number;
}

export function signSessionToken(payload: SessionPayload, secret: string): string {
  const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

export function verifySessionToken(token: string, secret: string): SessionPayload | null {
  const dotIdx = token.indexOf('.');
  if (dotIdx <= 0) return null;
  const data = token.slice(0, dotIdx);
  const sig = token.slice(dotIdx + 1);
  if (!data || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    const decoded = JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as SessionPayload;
    if (!decoded.userId || !decoded.email || typeof decoded.exp !== 'number') return null;
    if (decoded.exp < Math.floor(Date.now() / 1000)) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function computeHmacSignature(
  timestamp: string | number,
  rawBody: string,
  secret: string
): string {
  return crypto
    .createHmac('sha256', secret)
    .update(`${String(timestamp)}.${rawBody}`)
    .digest('hex');
}

export function normalizeProvidedSignature(headerValue: string): string {
  const trimmed = headerValue.trim();
  // Support both raw hex and Stripe-like "v1=<hex>" or "sha256=<hex>"
  if (trimmed.startsWith('v1=')) return trimmed.slice(3).trim().toLowerCase();
  if (trimmed.startsWith('sha256=')) return trimmed.slice(7).trim().toLowerCase();
  return trimmed.toLowerCase();
}

export function verifyHmacSignature(
  timestamp: string | number,
  rawBody: string,
  secret: string,
  providedSignatureHeader: string | undefined
): boolean {
  if (!providedSignatureHeader || !secret) return false;
  const normalizedProvided = normalizeProvidedSignature(providedSignatureHeader);
  if (!/^[a-f0-9]{64}$/.test(normalizedProvided)) return false;

  const expectedHex = computeHmacSignature(timestamp, rawBody, secret);
  const providedBuf = Buffer.from(normalizedProvided, 'hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (providedBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(providedBuf, expectedBuf);
}

export type TimestampValidationResult =
  | { ok: true; timestamp: number }
  | {
      ok: false;
      code: 'MISSING_TIMESTAMP' | 'INVALID_TIMESTAMP' | 'TIMESTAMP_EXPIRED';
      message: string;
    };

export function validateTimestamp(
  timestampHeader: string | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  toleranceSeconds: number = TIMESTAMP_TOLERANCE_SECONDS
): TimestampValidationResult {
  if (!timestampHeader || !timestampHeader.trim()) {
    return {
      ok: false,
      code: 'MISSING_TIMESTAMP',
      message: 'Header X-Timestamp wajib disertakan dengan Unix timestamp (detik).',
    };
  }
  const trimmed = timestampHeader.trim();
  if (!/^\d{1,12}$/.test(trimmed)) {
    return {
      ok: false,
      code: 'INVALID_TIMESTAMP',
      message: 'Format header X-Timestamp tidak valid. Gunakan angka Unix timestamp dalam detik.',
    };
  }
  const ts = Number.parseInt(trimmed, 10);
  if (!Number.isFinite(ts)) {
    return {
      ok: false,
      code: 'INVALID_TIMESTAMP',
      message: 'Nilai X-Timestamp tidak valid.',
    };
  }
  const diff = Math.abs(nowSeconds - ts);
  if (diff > toleranceSeconds) {
    return {
      ok: false,
      code: 'TIMESTAMP_EXPIRED',
      message: `Stempel waktu X-Timestamp berada di luar batas toleransi ${toleranceSeconds} detik (selisih ${diff} detik).`,
    };
  }
  return { ok: true, timestamp: ts };
}

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetUnix: number;
  retryAfterSeconds: number;
}

export class SlidingWindowRateLimiter {
  private buckets: Map<string, number[]> = new Map();
  private windowMs: number;

  constructor(windowMs: number = 60_000) {
    this.windowMs = windowMs;
  }

  consume(key: string, limit: number, nowMs: number = Date.now()): RateLimitDecision {
    const safeLimit = Math.max(1, Math.floor(limit));
    const cutoff = nowMs - this.windowMs;
    const existing = this.buckets.get(key) ?? [];
    const active = existing.filter((ts) => ts > cutoff);

    if (active.length >= safeLimit) {
      this.buckets.set(key, active);
      const oldest = active[0] ?? nowMs;
      const retryAfterMs = Math.max(1000, oldest + this.windowMs - nowMs);
      const retryAfterSeconds = Math.ceil(retryAfterMs / 1000);
      const resetUnix = Math.ceil((oldest + this.windowMs) / 1000);
      return {
        allowed: false,
        limit: safeLimit,
        remaining: 0,
        resetUnix,
        retryAfterSeconds,
      };
    }

    active.push(nowMs);
    this.buckets.set(key, active);
    const oldest = active[0] ?? nowMs;
    const resetUnix = Math.ceil((oldest + this.windowMs) / 1000);
    return {
      allowed: true,
      limit: safeLimit,
      remaining: Math.max(0, safeLimit - active.length),
      resetUnix,
      retryAfterSeconds: 0,
    };
  }

  reset(key?: string): void {
    if (key) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }
}

export function matchesEventPattern(subscribedEvents: string[], eventType: string): boolean {
  if (!Array.isArray(subscribedEvents) || subscribedEvents.length === 0) return false;
  for (const rawPattern of subscribedEvents) {
    const pattern = rawPattern.trim();
    if (!pattern) continue;
    if (pattern === '*') return true;
    if (pattern === eventType) return true;
    if (pattern.endsWith('.*')) {
      const prefix = pattern.slice(0, -1); // keeps trailing dot e.g. "order."
      if (eventType.startsWith(prefix)) return true;
    }
  }
  return false;
}

export type EventPayloadValidationResult =
  | { ok: true; eventType: string; payloadData: Record<string, unknown> }
  | { ok: false; message: string };

export function validateEventPayload(parsed: unknown): EventPayloadValidationResult {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      ok: false,
      message: 'Body JSON harus berupa objek valid dengan properti event_type dan data.',
    };
  }
  const obj = parsed as Record<string, unknown>;
  const eventType = obj.event_type;
  if (typeof eventType !== 'string' || !eventType.trim()) {
    return {
      ok: false,
      message: 'Kolom "event_type" wajib diisi dan harus berupa string non-kosong.',
    };
  }
  const trimmedType = eventType.trim();
  if (trimmedType.length > 128 || !/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(trimmedType)) {
    return {
      ok: false,
      message:
        'Kolom "event_type" hanya boleh berisi huruf, angka, titik (.), underscore (_), atau strip (-), maksimal 128 karakter.',
    };
  }

  const candidateData = obj.data !== undefined ? obj.data : obj.payload;
  if (candidateData === undefined) {
    return {
      ok: false,
      message: 'Kolom "data" (objek payload event) wajib disertakan.',
    };
  }
  if (!candidateData || typeof candidateData !== 'object' || Array.isArray(candidateData)) {
    return {
      ok: false,
      message: 'Kolom "data" harus berupa JSON object (bukan array atau primitif).',
    };
  }

  return {
    ok: true,
    eventType: trimmedType,
    payloadData: candidateData as Record<string, unknown>,
  };
}

export interface GatewayErrorBody {
  error: {
    type:
      | 'authentication_error'
      | 'authorization_error'
      | 'rate_limit_error'
      | 'invalid_request_error'
      | 'conflict_error'
      | 'payload_too_large';
    code: string;
    message: string;
    doc_url: string;
    request_id: string;
  };
}

export function buildGatewayError(
  type: GatewayErrorBody['error']['type'],
  code: string,
  message: string,
  requestId: string
): GatewayErrorBody {
  return {
    error: {
      type,
      code,
      message,
      doc_url: `/docs/errors#${code}`,
      request_id: requestId,
    },
  };
}
