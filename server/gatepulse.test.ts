import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  computeHmacSignature,
  generateApiKey,
  MAX_PAYLOAD_BYTES,
  SlidingWindowRateLimiter,
  validateTimestamp,
  verifyHmacSignature,
} from './security.ts';
import { isPrivateOrReservedIp, validateWebhookUrl } from './ssrf.ts';
import { createDatabase, seedDemoDataIfEmpty } from './db.ts';
import { createGatePulseApp } from './app.ts';
import { processPendingDeliveries } from './dispatcher.ts';

async function startTestServer(options?: {
  rateLimit?: number;
  nowMs?: () => number;
  dnsLookup?: (host: string) => Promise<Array<{ address: string; family: number }>>;
  fetchFn?: typeof globalThis.fetch;
}) {
  const db = createDatabase(':memory:');
  seedDemoDataIfEmpty(db);

  if (options?.rateLimit !== undefined) {
    db.prepare('UPDATE projects SET rate_limit_per_minute = ? WHERE id = ?').run(
      options.rateLimit,
      'prj_acme_001'
    );
  }

  const rateLimiter = new SlidingWindowRateLimiter(60_000);
  const { app, triggerWorker } = createGatePulseApp({
    db,
    rateLimiter,
    nowMs: options?.nowMs,
    dnsLookup:
      options?.dnsLookup ??
      (async (host) => {
        if (host === 'rebind.evil.test') return [{ address: '192.168.1.50', family: 4 }];
        return [{ address: '93.184.216.34', family: 4 }];
      }),
    fetchFn: options?.fetchFn,
    autoProcessQueue: false,
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const baseUrl = `http://127.0.0.1:${address.port}`;

  // Insert known test keys directly into DB (hashes only)
  const writeKey = generateApiKey('test');
  const readOnlyKey = generateApiKey('test');
  const revokedKey = generateApiKey('test');

  const insertKey = db.prepare(
    `INSERT INTO api_keys (id, project_id, environment, name, key_prefix, key_hash, scopes, created_at, revoked_at)
     VALUES (?, 'prj_acme_001', 'test', ?, ?, ?, ?, ?, ?)`
  );
  const nowIso = new Date().toISOString();
  insertKey.run(
    'key_unit_write',
    'Unit Write Key',
    writeKey.keyPrefix,
    writeKey.keyHash,
    JSON.stringify(['events:write', 'endpoints:manage', 'logs:read']),
    nowIso,
    null
  );
  insertKey.run(
    'key_unit_read',
    'Unit Read Key',
    readOnlyKey.keyPrefix,
    readOnlyKey.keyHash,
    JSON.stringify(['logs:read']),
    nowIso,
    null
  );
  insertKey.run(
    'key_unit_revoked',
    'Unit Revoked Key',
    revokedKey.keyPrefix,
    revokedKey.keyHash,
    JSON.stringify(['events:write']),
    nowIso,
    nowIso
  );

  const projectRow = db
    .prepare('SELECT webhook_signing_secret FROM projects WHERE id = ?')
    .get('prj_acme_001') as { webhook_signing_secret: string };

  return {
    db,
    baseUrl,
    writeRawKey: writeKey.rawKey,
    readOnlyRawKey: readOnlyKey.rawKey,
    revokedRawKey: revokedKey.rawKey,
    signingSecret: projectRow.webhook_signing_secret,
    triggerWorker,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test('Pure security: API key format, HMAC constant-time verify, and timestamp tolerance', () => {
  const generated = generateApiKey('live');
  assert.ok(generated.rawKey.startsWith('gp_live_'));
  assert.equal(generated.keyPrefix.length, 16);
  assert.equal(generated.keyHash.length, 64);

  const body = '{"event_type":"order.paid","data":{"id":"1"}}';
  const ts = 1_700_000_000;
  const sig = computeHmacSignature(ts, body, 'whsec_test');
  assert.equal(verifyHmacSignature(ts, body, 'whsec_test', sig), true);
  assert.equal(verifyHmacSignature(ts, body.replace('1', '2'), 'whsec_test', sig), false);

  assert.equal(validateTimestamp(String(ts), ts + 299).ok, true);
  const expired = validateTimestamp(String(ts), ts + 301);
  assert.equal(expired.ok, false);
  if (!expired.ok) assert.equal(expired.code, 'TIMESTAMP_EXPIRED');
});

test('Pure SSRF: Private, loopback, metadata, and IPv4-mapped IPv6 ranges are blocked', async () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.20.30.40'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.5'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);

  const localRes = await validateWebhookUrl('http://127.0.0.1:8000/hook', 'test');
  assert.equal(localRes.ok, false);
  if (!localRes.ok) assert.equal(localRes.code, 'SSRF_BLOCKED');

  const metaRes = await validateWebhookUrl('http://169.254.169.254/latest/meta-data/', 'test');
  assert.equal(metaRes.ok, false);

  const liveHttp = await validateWebhookUrl('http://api.example.com/hook', 'live', async () => [
    { address: '93.184.216.34', family: 4 },
  ]);
  assert.equal(liveHttp.ok, false);
  if (!liveHttp.ok) assert.equal(liveHttp.code, 'INSECURE_SCHEME');

  const rebind = await validateWebhookUrl('https://rebind.evil.test/hook', 'live', async () => [
    { address: '10.0.0.8', family: 4 },
  ]);
  assert.equal(rebind.ok, false);
  if (!rebind.ok) assert.equal(rebind.code, 'SSRF_BLOCKED');
});

test('Acceptance #1 & #2: Missing/Revoked API key returns 401; insufficient scope returns 403', async () => {
  const ctx = await startTestServer();
  try {
    const rawBody = JSON.stringify({ event_type: 'order.paid', data: { id: 'o1' } });
    const ts = Math.floor(Date.now() / 1000);
    const sig = computeHmacSignature(ts, rawBody, ctx.signingSecret);

    // 1a. Missing API Key
    const resMissing = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Timestamp': String(ts), 'X-Signature': sig },
      body: rawBody,
    });
    assert.equal(resMissing.status, 401);
    const bodyMissing = (await resMissing.json()) as { error: { code: string } };
    assert.equal(bodyMissing.error.code, 'INVALID_API_KEY');

    // 1b. Revoked API Key
    const resRevoked = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.revokedRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
      },
      body: rawBody,
    });
    assert.equal(resRevoked.status, 401);
    const bodyRevoked = (await resRevoked.json()) as { error: { code: string } };
    assert.equal(bodyRevoked.error.code, 'INVALID_API_KEY');

    // 2. Insufficient Scope (logs:read only)
    const resScope = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.readOnlyRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
      },
      body: rawBody,
    });
    assert.equal(resScope.status, 403);
    const bodyScope = (await resScope.json()) as { error: { code: string } };
    assert.equal(bodyScope.error.code, 'INSUFFICIENT_SCOPE');
  } finally {
    await ctx.close();
  }
});

test('Acceptance #3 & #4: Expired X-Timestamp and 1-char tampered JSON body return 401', async () => {
  const ctx = await startTestServer();
  try {
    const rawBody = JSON.stringify({ event_type: 'order.paid', data: { amount: 1000 } });
    const nowSec = Math.floor(Date.now() / 1000);

    // 3. Expired timestamp (> 5 mins ago)
    const staleTs = nowSec - 360;
    const staleSig = computeHmacSignature(staleTs, rawBody, ctx.signingSecret);
    const resExpired = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(staleTs),
        'X-Signature': staleSig,
      },
      body: rawBody,
    });
    assert.equal(resExpired.status, 401);
    const bodyExpired = (await resExpired.json()) as { error: { code: string } };
    assert.equal(bodyExpired.error.code, 'TIMESTAMP_EXPIRED');

    // 4. Tamper 1 character without updating X-Signature
    const validSig = computeHmacSignature(nowSec, rawBody, ctx.signingSecret);
    const tamperedBody = rawBody.replace('1000', '1009');
    const resTampered = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(nowSec),
        'X-Signature': validSig,
      },
      body: tamperedBody,
    });
    assert.equal(resTampered.status, 401);
    const bodyTampered = (await resTampered.json()) as { error: { code: string } };
    assert.equal(bodyTampered.error.code, 'INVALID_HMAC_SIGNATURE');
  } finally {
    await ctx.close();
  }
});

test('Acceptance #5: Exceeding project rate limit returns 429 with Retry-After header', async () => {
  const ctx = await startTestServer({ rateLimit: 2 });
  try {
    const rawBody = JSON.stringify({ event_type: 'ping.test', data: { seq: 1 } });
    const ts = Math.floor(Date.now() / 1000);
    const sig = computeHmacSignature(ts, rawBody, ctx.signingSecret);

    for (let i = 0; i < 2; i++) {
      const okRes = await fetch(`${ctx.baseUrl}/v1/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ctx.writeRawKey}`,
          'X-Timestamp': String(ts),
          'X-Signature': sig,
        },
        body: rawBody,
      });
      assert.equal(okRes.status, 202);
      assert.equal(okRes.headers.get('x-ratelimit-limit'), '2');
    }

    const limitedRes = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
      },
      body: rawBody,
    });
    assert.equal(limitedRes.status, 429);
    assert.ok(Number(limitedRes.headers.get('retry-after')) >= 1);
    const body = (await limitedRes.json()) as { error: { code: string } };
    assert.equal(body.error.code, 'RATE_LIMIT_EXCEEDED');
  } finally {
    await ctx.close();
  }
});

test('Acceptance #6: Idempotency-Key returns cached 202 without duplicate DB event, and 409 on payload conflict', async () => {
  const ctx = await startTestServer();
  try {
    const beforeCount = (
      ctx.db.prepare('SELECT COUNT(*) as c FROM events').get() as { c: number }
    ).c;

    const rawBody = JSON.stringify({ event_type: 'invoice.issued', data: { inv: 'INV-100' } });
    const ts = Math.floor(Date.now() / 1000);
    const sig = computeHmacSignature(ts, rawBody, ctx.signingSecret);

    const first = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
        'Idempotency-Key': 'idem_test_9911',
      },
      body: rawBody,
    });
    assert.equal(first.status, 202);
    const firstJson = (await first.json()) as { id: string };

    const second = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
        'Idempotency-Key': 'idem_test_9911',
      },
      body: rawBody,
    });
    assert.equal(second.status, 202);
    assert.equal(second.headers.get('x-idempotent-replayed'), 'true');
    const secondJson = (await second.json()) as { id: string };
    assert.equal(secondJson.id, firstJson.id);

    const afterCount = (
      ctx.db.prepare('SELECT COUNT(*) as c FROM events').get() as { c: number }
    ).c;
    assert.equal(afterCount, beforeCount + 1);

    // Same key with different payload -> 409 Conflict
    const diffBody = JSON.stringify({ event_type: 'invoice.issued', data: { inv: 'INV-999' } });
    const diffSig = computeHmacSignature(ts, diffBody, ctx.signingSecret);
    const conflict = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': diffSig,
        'Idempotency-Key': 'idem_test_9911',
      },
      body: diffBody,
    });
    assert.equal(conflict.status, 409);
    const conflictJson = (await conflict.json()) as { error: { code: string } };
    assert.equal(conflictJson.error.code, 'IDEMPOTENCY_CONFLICT');
  } finally {
    await ctx.close();
  }
});

test('Acceptance #7 & Layer 1: SSRF endpoint registration returns 422; >256KB payload returns 413', async () => {
  const ctx = await startTestServer();
  try {
    // 7. Registering 127.0.0.1 via Console API or /v1/endpoints returns 422
    const ssrfRes = await fetch(`${ctx.baseUrl}/v1/endpoints`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
      },
      body: JSON.stringify({ url: 'http://127.0.0.1:8000/internal', subscribed_events: ['*'] }),
    });
    assert.equal(ssrfRes.status, 422);
    const ssrfBody = (await ssrfRes.json()) as { error: { code: string } };
    assert.equal(ssrfBody.error.code, 'SSRF_BLOCKED');

    // Payload > 256 KB returns 413
    const hugeData = 'x'.repeat(MAX_PAYLOAD_BYTES + 1024);
    const hugeBody = JSON.stringify({ event_type: 'bulk.test', data: { blob: hugeData } });
    const ts = Math.floor(Date.now() / 1000);
    const hugeSig = computeHmacSignature(ts, hugeBody, ctx.signingSecret);
    const resHuge = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': hugeSig,
      },
      body: hugeBody,
    });
    assert.equal(resHuge.status, 413);
  } finally {
    await ctx.close();
  }
});

test('Acceptance #8: Unreachable client webhook still yields 202, records failure, and schedules exponential backoff retry', async () => {
  let fakeNowMs = 1_700_000_000_000;
  const ctx = await startTestServer({
    nowMs: () => fakeNowMs,
    fetchFn: async () => {
      throw new Error('ECONNREFUSED');
    },
  });
  try {
    // Register external endpoint that will fail when called
    const epRes = await fetch(`${ctx.baseUrl}/v1/endpoints`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
      },
      body: JSON.stringify({
        url: 'https://consumer.example.com/webhooks/gatepulse',
        subscribed_events: ['payment.failed'],
      }),
    });
    assert.equal(epRes.status, 201);
    const epJson = (await epRes.json()) as { id: string };

    const rawBody = JSON.stringify({
      event_type: 'payment.failed',
      data: { payment_id: 'pay_505' },
    });
    const ts = Math.floor(fakeNowMs / 1000);
    const sig = computeHmacSignature(ts, rawBody, ctx.signingSecret);

    const ingestRes = await fetch(`${ctx.baseUrl}/v1/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${ctx.writeRawKey}`,
        'X-Timestamp': String(ts),
        'X-Signature': sig,
      },
      body: rawBody,
    });
    assert.equal(ingestRes.status, 202);
    const ingestJson = (await ingestRes.json()) as { id: string };

    // Run worker Attempt 1 against unreachable fetchFn
    const run1 = await processPendingDeliveries(ctx.db, {
      fetchFn: async () => {
        throw new Error('ECONNREFUSED');
      },
      nowMs: () => fakeNowMs,
    });
    assert.ok(run1.failed >= 1);
    assert.ok(run1.retried >= 1);

    const attemptsAfter1 = ctx.db
      .prepare('SELECT * FROM delivery_attempts WHERE event_id = ? AND endpoint_id = ? ORDER BY attempt_number ASC')
      .all(ingestJson.id, epJson.id) as Array<{
      attempt_number: number;
      status: string;
      next_retry_at: string | null;
    }>;

    assert.equal(attemptsAfter1.length, 2);
    assert.equal(attemptsAfter1[0].attempt_number, 1);
    assert.equal(attemptsAfter1[0].status, 'failed');
    assert.equal(attemptsAfter1[1].attempt_number, 2);
    assert.equal(attemptsAfter1[1].status, 'pending');
    // Scheduled +10s later
    assert.equal(attemptsAfter1[1].next_retry_at, new Date(fakeNowMs + 10_000).toISOString());

    // Advance clock 10 seconds -> Attempt 2 runs and succeeds when receiver comes back online
    fakeNowMs += 10_000;
    const run2 = await processPendingDeliveries(ctx.db, {
      fetchFn: async () => new Response('{"ok":true}', { status: 200 }),
      nowMs: () => fakeNowMs,
    });
    assert.ok(run2.succeeded >= 1);

    const attempt2 = ctx.db
      .prepare('SELECT status, http_status_code FROM delivery_attempts WHERE event_id = ? AND endpoint_id = ? AND attempt_number = 2')
      .get(ingestJson.id, epJson.id) as { status: string; http_status_code: number };
    assert.equal(attempt2.status, 'success');
    assert.equal(attempt2.http_status_code, 200);
  } finally {
    await ctx.close();
  }
});
