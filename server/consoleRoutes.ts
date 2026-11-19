import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import type { DatabaseSync } from 'node:sqlite';
import {
  ALL_SCOPES,
  generateApiKey,
  generateId,
  generateSigningSecret,
  hashPassword,
  signSessionToken,
  verifyPassword,
  verifySessionToken,
  type ApiScope,
  type Environment,
} from './security.ts';
import { SANDBOX_SINK_HOST, validateWebhookUrl, type DnsLookupFn } from './ssrf.ts';
import { replayEventDeliveries } from './dispatcher.ts';
import {
  DEMO_USER_EMAIL,
  type ApiKeyRow,
  type DeliveryAttemptRow,
  type EventRow,
  type GatewayLogRow,
  type ProjectRow,
  type SandboxSinkReceiptRow,
  type SandboxSinkRow,
  type UserRow,
  type WebhookEndpointRow,
} from './db.ts';

const SESSION_COOKIE = 'gp_session';
const LOGGED_OUT_COOKIE = 'gp_logged_out';

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    result[key] = val;
  }
  return result;
}

function setCookieHeader(
  res: Response,
  name: string,
  value: string,
  options: { maxAgeSec?: number; httpOnly?: boolean } = {}
): void {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'SameSite=Lax'];
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (typeof options.maxAgeSec === 'number') parts.push(`Max-Age=${options.maxAgeSec}`);
  res.append('Set-Cookie', parts.join('; '));
}

export interface ConsoleRouterOptions {
  db: DatabaseSync;
  sessionSecret: string;
  dnsLookup?: DnsLookupFn;
  onEventQueued?: () => void;
}

export function createConsoleRouter(options: ConsoleRouterOptions): express.Router {
  const { db, sessionSecret } = options;
  const router = express.Router();

  router.use(express.json({ limit: '512kb' }));

  const issueSession = (res: Response, user: UserRow) => {
    const token = signSessionToken(
      {
        userId: user.id,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
      },
      sessionSecret
    );
    setCookieHeader(res, LOGGED_OUT_COOKIE, '', { maxAgeSec: 0 });
    setCookieHeader(res, SESSION_COOKIE, token, { maxAgeSec: 7 * 24 * 3600 });
  };

  const resolveUser = (req: Request, res: Response): UserRow | null => {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (token) {
      const payload = verifySessionToken(token, sessionSecret);
      if (payload) {
        const user = db
          .prepare('SELECT * FROM users WHERE id = ?')
          .get(payload.userId) as unknown as UserRow | undefined;
        if (user) return user;
      }
    }

    // Auto-enter demo workspace on first visit unless user explicitly logged out
    if (cookies[LOGGED_OUT_COOKIE] !== '1') {
      const demoUser = db
        .prepare('SELECT * FROM users WHERE email = ?')
        .get(DEMO_USER_EMAIL) as unknown as UserRow | undefined;
      if (demoUser) {
        issueSession(res, demoUser);
        return demoUser;
      }
    }

    return null;
  };

  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const user = resolveUser(req, res);
    if (!user) {
      res.status(401).json({ error: 'Sesi login tidak ditemukan atau telah berakhir.' });
      return;
    }
    (req as Request & { currentUser?: UserRow }).currentUser = user;
    next();
  };

  const getUserProject = (userId: string, projectId: string): ProjectRow | null => {
    const row = db
      .prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?')
      .get(projectId, userId) as unknown as ProjectRow | undefined;
    return row ?? null;
  };

  // --- Auth Endpoints ---
  router.get('/auth/me', (req: Request, res: Response) => {
    const user = resolveUser(req, res);
    if (!user) {
      res.status(401).json({ user: null });
      return;
    }
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        created_at: user.created_at,
      },
    });
  });

  router.post('/auth/demo', (_req: Request, res: Response) => {
    const demoUser = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(DEMO_USER_EMAIL) as unknown as UserRow | undefined;
    if (!demoUser) {
      res.status(404).json({ error: 'Akun demo tidak tersedia.' });
      return;
    }
    issueSession(res, demoUser);
    res.json({
      user: {
        id: demoUser.id,
        email: demoUser.email,
        name: demoUser.name,
        created_at: demoUser.created_at,
      },
    });
  });

  router.post('/auth/register', (req: Request, res: Response) => {
    const { email, password, name } = (req.body ?? {}) as {
      email?: string;
      password?: string;
      name?: string;
    };
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanEmail || !cleanEmail.includes('@')) {
      res.status(422).json({ error: 'Alamat email tidak valid.' });
      return;
    }
    if (!password || password.length < 6) {
      res.status(422).json({ error: 'Kata sandi minimal 6 karakter.' });
      return;
    }
    const existing = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(cleanEmail) as { id: string } | undefined;
    if (existing) {
      res.status(409).json({ error: 'Email sudah terdaftar. Silakan masuk menggunakan akun tersebut.' });
      return;
    }

    const nowIso = new Date().toISOString();
    const userId = generateId('usr');
    const displayName = cleanName || cleanEmail.split('@')[0];

    db.prepare(
      'INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, cleanEmail, displayName, hashPassword(password), nowIso);

    // Create default initial Project for the newly registered developer
    const projectId = generateId('prj');
    db.prepare(
      'INSERT INTO projects (id, user_id, name, rate_limit_per_minute, webhook_signing_secret, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(projectId, userId, `${displayName}'s Workspace`, 60, generateSigningSecret(), nowIso);

    const newUser = db
      .prepare('SELECT * FROM users WHERE id = ?')
      .get(userId) as unknown as UserRow;
    issueSession(res, newUser);
    res.status(201).json({
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        created_at: newUser.created_at,
      },
    });
  });

  router.post('/auth/login', (req: Request, res: Response) => {
    const { email, password } = (req.body ?? {}) as { email?: string; password?: string };
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (!cleanEmail || !password) {
      res.status(400).json({ error: 'Email dan kata sandi wajib diisi.' });
      return;
    }
    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(cleanEmail) as unknown as UserRow | undefined;
    if (!user || !verifyPassword(password, user.password_hash)) {
      res.status(401).json({ error: 'Email atau kata sandi salah.' });
      return;
    }
    issueSession(res, user);
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        created_at: user.created_at,
      },
    });
  });

  router.post('/auth/logout', (_req: Request, res: Response) => {
    setCookieHeader(res, SESSION_COOKIE, '', { maxAgeSec: 0 });
    setCookieHeader(res, LOGGED_OUT_COOKIE, '1', { maxAgeSec: 365 * 24 * 3600 });
    res.json({ ok: true });
  });

  // --- Projects ---
  router.get('/projects', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const rows = db
      .prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY created_at ASC')
      .all(user.id) as unknown as ProjectRow[];
    res.json({ projects: rows });
  });

  router.post('/projects', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const { name, rate_limit_per_minute } = (req.body ?? {}) as {
      name?: string;
      rate_limit_per_minute?: number;
    };
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName || cleanName.length > 80) {
      res.status(422).json({ error: 'Nama project wajib diisi (maksimal 80 karakter).' });
      return;
    }
    const rateLimit =
      typeof rate_limit_per_minute === 'number' &&
      Number.isFinite(rate_limit_per_minute) &&
      rate_limit_per_minute >= 1 &&
      rate_limit_per_minute <= 10000
        ? Math.floor(rate_limit_per_minute)
        : 60;

    const projectId = generateId('prj');
    const createdAt = new Date().toISOString();
    const secret = generateSigningSecret();
    db.prepare(
      'INSERT INTO projects (id, user_id, name, rate_limit_per_minute, webhook_signing_secret, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(projectId, user.id, cleanName, rateLimit, secret, createdAt);

    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId);
    res.status(201).json({ project });
  });

  router.patch('/projects/:projectId', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const { name, rate_limit_per_minute } = (req.body ?? {}) as {
      name?: string;
      rate_limit_per_minute?: number;
    };

    const nextName = typeof name === 'string' && name.trim() ? name.trim().slice(0, 80) : project.name;
    let nextLimit = project.rate_limit_per_minute;
    if (rate_limit_per_minute !== undefined) {
      if (
        typeof rate_limit_per_minute !== 'number' ||
        !Number.isFinite(rate_limit_per_minute) ||
        rate_limit_per_minute < 1 ||
        rate_limit_per_minute > 10000
      ) {
        res.status(422).json({ error: 'Rate limit harus antara 1 hingga 10.000 permintaan per menit.' });
        return;
      }
      nextLimit = Math.floor(rate_limit_per_minute);
    }

    db.prepare('UPDATE projects SET name = ?, rate_limit_per_minute = ? WHERE id = ?').run(
      nextName,
      nextLimit,
      project.id
    );
    const updated = db.prepare('SELECT * FROM projects WHERE id = ?').get(project.id);
    res.json({ project: updated });
  });

  router.post('/projects/:projectId/rotate-secret', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const newSecret = generateSigningSecret();
    db.prepare('UPDATE projects SET webhook_signing_secret = ? WHERE id = ?').run(
      newSecret,
      project.id
    );
    const updated = db.prepare('SELECT * FROM projects WHERE id = ?').get(project.id);
    res.json({ project: updated });
  });

  // --- API Keys ---
  router.get('/projects/:projectId/api-keys', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const env = req.query.environment === 'live' ? 'live' : 'test';
    const rows = db
      .prepare(
        `SELECT id, project_id, environment, name, key_prefix, scopes, last_used_at, revoked_at, created_at
         FROM api_keys
         WHERE project_id = ? AND environment = ?
         ORDER BY created_at DESC`
      )
      .all(project.id, env) as unknown as Array<Omit<ApiKeyRow, 'key_hash'>>;

    const formatted = rows.map((row) => ({
      ...row,
      scopes: JSON.parse(row.scopes) as ApiScope[],
    }));
    res.json({ api_keys: formatted });
  });

  router.post('/projects/:projectId/api-keys', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }

    const { name, environment, scopes } = (req.body ?? {}) as {
      name?: string;
      environment?: Environment;
      scopes?: string[];
    };
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName || cleanName.length > 80) {
      res.status(422).json({ error: 'Nama API Key wajib diisi (maksimal 80 karakter).' });
      return;
    }

    const env: Environment = environment === 'live' ? 'live' : 'test';
    const validScopes = Array.isArray(scopes)
      ? scopes.filter((s): s is ApiScope => (ALL_SCOPES as string[]).includes(s))
      : [];
    if (validScopes.length === 0) {
      res.status(422).json({ error: 'Pilih minimal satu scope izin untuk API Key ini.' });
      return;
    }

    const { rawKey, keyPrefix, keyHash } = generateApiKey(env);
    const id = generateId('key');
    const createdAt = new Date().toISOString();

    db.prepare(
      `INSERT INTO api_keys (
        id, project_id, environment, name, key_prefix, key_hash, scopes, last_used_at, revoked_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
    ).run(id, project.id, env, cleanName, keyPrefix, keyHash, JSON.stringify(validScopes), createdAt);

    // Return raw_key ONCE — never stored in plain text
    res.status(201).json({
      api_key: {
        id,
        project_id: project.id,
        environment: env,
        name: cleanName,
        key_prefix: keyPrefix,
        scopes: validScopes,
        last_used_at: null,
        revoked_at: null,
        created_at: createdAt,
      },
      raw_key: rawKey,
    });
  });

  router.post('/projects/:projectId/api-keys/:keyId/revoke', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const existing = db
      .prepare('SELECT * FROM api_keys WHERE id = ? AND project_id = ?')
      .get(String(req.params.keyId), project.id) as unknown as ApiKeyRow | undefined;
    if (!existing) {
      res.status(404).json({ error: 'API Key tidak ditemukan.' });
      return;
    }
    const revokedAt = existing.revoked_at ?? new Date().toISOString();
    db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ?').run(revokedAt, existing.id);
    res.json({ ok: true, revoked_at: revokedAt });
  });

  router.post('/projects/:projectId/api-keys/:keyId/rotate', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const existing = db
      .prepare('SELECT * FROM api_keys WHERE id = ? AND project_id = ?')
      .get(String(req.params.keyId), project.id) as unknown as ApiKeyRow | undefined;
    if (!existing) {
      res.status(404).json({ error: 'API Key tidak ditemukan.' });
      return;
    }

    const nowIso = new Date().toISOString();
    // Revoke old key immediately
    db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ?').run(nowIso, existing.id);

    // Issue replacement key with same name & scopes
    const { rawKey, keyPrefix, keyHash } = generateApiKey(existing.environment);
    const newId = generateId('key');
    const parsedScopes = JSON.parse(existing.scopes) as ApiScope[];
    db.prepare(
      `INSERT INTO api_keys (
        id, project_id, environment, name, key_prefix, key_hash, scopes, last_used_at, revoked_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`
    ).run(
      newId,
      project.id,
      existing.environment,
      existing.name,
      keyPrefix,
      keyHash,
      existing.scopes,
      nowIso
    );

    res.status(201).json({
      api_key: {
        id: newId,
        project_id: project.id,
        environment: existing.environment,
        name: existing.name,
        key_prefix: keyPrefix,
        scopes: parsedScopes,
        last_used_at: null,
        revoked_at: null,
        created_at: nowIso,
      },
      raw_key: rawKey,
    });
  });

  // --- Webhook Endpoints & Anti-SSRF Validation ---
  router.get('/projects/:projectId/endpoints', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const env = req.query.environment === 'live' ? 'live' : 'test';
    const rows = db
      .prepare(
        'SELECT * FROM webhook_endpoints WHERE project_id = ? AND environment = ? ORDER BY created_at DESC'
      )
      .all(project.id, env) as unknown as WebhookEndpointRow[];

    const sinks = db
      .prepare('SELECT * FROM sandbox_sinks WHERE project_id = ?')
      .all(project.id) as unknown as SandboxSinkRow[];
    const sinkMap = new Map(sinks.map((s) => [s.url, s]));

    const formatted = rows.map((row) => {
      const sink = sinkMap.get(row.url);
      return {
        ...row,
        is_active: Boolean(row.is_active),
        subscribed_events: JSON.parse(row.subscribed_events) as string[],
        sandbox_sink: sink ?? null,
      };
    });
    res.json({ endpoints: formatted });
  });

  router.post('/projects/:projectId/endpoints', requireAuth, async (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }

    const { url, description, environment, subscribed_events } = (req.body ?? {}) as {
      url?: string;
      description?: string;
      environment?: Environment;
      subscribed_events?: string[];
    };

    const env: Environment = environment === 'live' ? 'live' : 'test';
    const check = await validateWebhookUrl(url ?? '', env, options.dnsLookup);
    if (!check.ok) {
      res.status(422).json({
        error: check.message,
        code: check.code,
      });
      return;
    }

    const patterns = Array.isArray(subscribed_events)
      ? subscribed_events.map((s) => String(s).trim()).filter(Boolean)
      : ['*'];
    const finalPatterns = patterns.length > 0 ? patterns : ['*'];

    const endpointId = generateId('ep');
    const signingSecret = generateSigningSecret();
    const createdAt = new Date().toISOString();

    db.prepare(
      `INSERT INTO webhook_endpoints (
        id, project_id, environment, url, description, signing_secret, subscribed_events, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).run(
      endpointId,
      project.id,
      env,
      check.normalizedUrl,
      typeof description === 'string' ? description.trim().slice(0, 160) : '',
      signingSecret,
      JSON.stringify(finalPatterns),
      createdAt
    );

    if (check.isSandboxSink) {
      const existingSink = db
        .prepare('SELECT id FROM sandbox_sinks WHERE url = ?')
        .get(check.normalizedUrl) as { id: string } | undefined;
      if (!existingSink) {
        db.prepare(
          'INSERT INTO sandbox_sinks (id, project_id, url, mode, created_at) VALUES (?, ?, ?, ?, ?)'
        ).run(generateId('snk'), project.id, check.normalizedUrl, 'healthy', createdAt);
      }
    }

    res.status(201).json({
      endpoint: {
        id: endpointId,
        project_id: project.id,
        environment: env,
        url: check.normalizedUrl,
        description: typeof description === 'string' ? description.trim().slice(0, 160) : '',
        signing_secret: signingSecret,
        subscribed_events: finalPatterns,
        is_active: true,
        created_at: createdAt,
      },
    });
  });

  // Quick helper to spin up a built-in Sandbox Receiver Sink in TEST mode
  router.post('/projects/:projectId/sandbox-sinks', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }

    const { label, mode, subscribed_events } = (req.body ?? {}) as {
      label?: string;
      mode?: 'healthy' | 'server_error' | 'timeout';
      subscribed_events?: string[];
    };

    const slug = `${generateId('s').slice(2, 10)}`;
    const sinkUrl = `https://${SANDBOX_SINK_HOST}/r/${slug}`;
    const sinkMode = mode === 'server_error' || mode === 'timeout' ? mode : 'healthy';
    const createdAt = new Date().toISOString();
    const sinkId = generateId('snk');
    const endpointId = generateId('ep');
    const signingSecret = generateSigningSecret();
    const patterns =
      Array.isArray(subscribed_events) && subscribed_events.length > 0 ? subscribed_events : ['*'];

    db.prepare(
      'INSERT INTO sandbox_sinks (id, project_id, url, mode, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(sinkId, project.id, sinkUrl, sinkMode, createdAt);

    db.prepare(
      `INSERT INTO webhook_endpoints (
        id, project_id, environment, url, description, signing_secret, subscribed_events, is_active, created_at
      ) VALUES (?, ?, 'test', ?, ?, ?, ?, 1, ?)`
    ).run(
      endpointId,
      project.id,
      sinkUrl,
      typeof label === 'string' && label.trim()
        ? label.trim().slice(0, 120)
        : 'GatePulse Built-in Sandbox Receiver',
      signingSecret,
      JSON.stringify(patterns),
      createdAt
    );

    res.status(201).json({
      sink: { id: sinkId, project_id: project.id, url: sinkUrl, mode: sinkMode, created_at: createdAt },
      endpoint_id: endpointId,
    });
  });

  router.patch('/projects/:projectId/sandbox-sinks/:sinkId', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const { mode } = (req.body ?? {}) as { mode?: string };
    if (mode !== 'healthy' && mode !== 'server_error' && mode !== 'timeout') {
      res.status(422).json({ error: 'Mode sandbox sink harus healthy, server_error, atau timeout.' });
      return;
    }
    db.prepare('UPDATE sandbox_sinks SET mode = ? WHERE id = ? AND project_id = ?').run(
      mode,
      String(req.params.sinkId),
      project.id
    );
    res.json({ ok: true, mode });
  });

  router.get('/projects/:projectId/sandbox-sinks/:sinkId/receipts', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const sink = db
      .prepare('SELECT * FROM sandbox_sinks WHERE id = ? AND project_id = ?')
      .get(String(req.params.sinkId), project.id) as unknown as SandboxSinkRow | undefined;
    if (!sink) {
      res.status(404).json({ error: 'Sandbox sink tidak ditemukan.' });
      return;
    }
    const receipts = db
      .prepare('SELECT * FROM sandbox_sink_receipts WHERE sink_id = ? ORDER BY received_at DESC LIMIT 20')
      .all(sink.id) as unknown as SandboxSinkReceiptRow[];
    res.json({
      receipts: receipts.map((r) => ({
        ...r,
        headers: JSON.parse(r.headers_json),
        payload: JSON.parse(r.payload_json),
      })),
    });
  });

  router.patch('/projects/:projectId/endpoints/:endpointId', requireAuth, async (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const existing = db
      .prepare('SELECT * FROM webhook_endpoints WHERE id = ? AND project_id = ?')
      .get(String(req.params.endpointId), project.id) as unknown as WebhookEndpointRow | undefined;
    if (!existing) {
      res.status(404).json({ error: 'Webhook endpoint tidak ditemukan.' });
      return;
    }

    const { is_active, url, subscribed_events, description } = (req.body ?? {}) as {
      is_active?: boolean;
      url?: string;
      subscribed_events?: string[];
      description?: string;
    };

    let nextUrl = existing.url;
    if (typeof url === 'string' && url.trim() && url.trim() !== existing.url) {
      const check = await validateWebhookUrl(url, existing.environment, options.dnsLookup);
      if (!check.ok) {
        res.status(422).json({ error: check.message, code: check.code });
        return;
      }
      nextUrl = check.normalizedUrl;
    }

    const nextActive = typeof is_active === 'boolean' ? (is_active ? 1 : 0) : existing.is_active;
    const nextEvents = Array.isArray(subscribed_events)
      ? JSON.stringify(subscribed_events.filter(Boolean))
      : existing.subscribed_events;
    const nextDesc =
      typeof description === 'string' ? description.trim().slice(0, 160) : existing.description;

    db.prepare(
      'UPDATE webhook_endpoints SET url = ?, is_active = ?, subscribed_events = ?, description = ? WHERE id = ?'
    ).run(nextUrl, nextActive, nextEvents, nextDesc, existing.id);

    res.json({ ok: true });
  });

  router.delete('/projects/:projectId/endpoints/:endpointId', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    db.prepare('DELETE FROM webhook_endpoints WHERE id = ? AND project_id = ?').run(
      String(req.params.endpointId),
      project.id
    );
    res.json({ ok: true });
  });

  // --- Events, Delivery Attempts & Manual Replay ---
  router.get('/projects/:projectId/events', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const env = req.query.environment === 'live' ? 'live' : 'test';
    const eventRows = db
      .prepare(
        'SELECT * FROM events WHERE project_id = ? AND environment = ? ORDER BY created_at DESC LIMIT 60'
      )
      .all(project.id, env) as unknown as EventRow[];

    const endpoints = db
      .prepare('SELECT id, url, description FROM webhook_endpoints WHERE project_id = ?')
      .all(project.id) as unknown as Array<{ id: string; url: string; description: string }>;
    const endpointMap = new Map(endpoints.map((e) => [e.id, e]));

    const attemptsStmt = db.prepare(
      'SELECT * FROM delivery_attempts WHERE event_id = ? ORDER BY attempt_number ASC, created_at ASC'
    );

    const enriched = eventRows.map((evt) => {
      const attempts = attemptsStmt.all(evt.id) as unknown as DeliveryAttemptRow[];
      return {
        ...evt,
        payload: JSON.parse(evt.payload) as Record<string, unknown>,
        attempts: attempts.map((a) => ({
          ...a,
          endpoint_url: endpointMap.get(a.endpoint_id)?.url ?? 'Removed endpoint',
          endpoint_description: endpointMap.get(a.endpoint_id)?.description ?? '',
        })),
      };
    });

    res.json({ events: enriched });
  });

  router.post('/projects/:projectId/events/:eventId/replay', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const endpointId =
      typeof req.body?.endpoint_id === 'string' ? req.body.endpoint_id : undefined;

    const result = replayEventDeliveries(db, String(req.params.eventId), project.id, endpointId);
    if (result.queuedCount === 0) {
      res.status(404).json({
        error: 'Event tidak ditemukan atau tidak ada webhook endpoint aktif yang cocok.',
      });
      return;
    }
    options.onEventQueued?.();
    res.status(202).json({ replayed: true, queued_attempts: result.queuedCount });
  });

  // --- Gateway Security Logs & Metrics ---
  router.get('/projects/:projectId/gateway-logs', requireAuth, (req: Request, res: Response) => {
    const user = (req as Request & { currentUser: UserRow }).currentUser;
    const project = getUserProject(user.id, String(req.params.projectId));
    if (!project) {
      res.status(404).json({ error: 'Project tidak ditemukan.' });
      return;
    }
    const env = req.query.environment === 'live' ? 'live' : 'test';
    const logs = db
      .prepare(
        `SELECT * FROM api_request_logs
         WHERE (project_id = ? AND environment = ?) OR project_id IS NULL
         ORDER BY created_at DESC
         LIMIT 60`
      )
      .all(project.id, env) as unknown as GatewayLogRow[];

    const eventCount = (
      db
        .prepare('SELECT COUNT(*) as c FROM events WHERE project_id = ? AND environment = ?')
        .get(project.id, env) as { c: number }
    ).c;

    const activeKeyCount = (
      db
        .prepare(
          'SELECT COUNT(*) as c FROM api_keys WHERE project_id = ? AND environment = ? AND revoked_at IS NULL'
        )
        .get(project.id, env) as { c: number }
    ).c;

    const activeEndpointCount = (
      db
        .prepare(
          'SELECT COUNT(*) as c FROM webhook_endpoints WHERE project_id = ? AND environment = ? AND is_active = 1'
        )
        .get(project.id, env) as { c: number }
    ).c;

    const deliveryStats = db
      .prepare(
        `SELECT da.status, COUNT(*) as c
         FROM delivery_attempts da
         JOIN events e ON e.id = da.event_id
         WHERE e.project_id = ? AND e.environment = ?
         GROUP BY da.status`
      )
      .all(project.id, env) as Array<{ status: string; c: number }>;

    const blockedCount = (
      db
        .prepare(
          `SELECT COUNT(*) as c FROM api_request_logs
           WHERE ((project_id = ? AND environment = ?) OR project_id IS NULL) AND status_code >= 400`
        )
        .get(project.id, env) as { c: number }
    ).c;

    res.json({
      logs,
      metrics: {
        events_ingested: eventCount,
        active_keys: activeKeyCount,
        active_endpoints: activeEndpointCount,
        blocked_requests: blockedCount,
        deliveries: deliveryStats.reduce(
          (acc, row) => {
            acc[row.status] = row.c;
            return acc;
          },
          { success: 0, failed: 0, pending: 0 } as Record<string, number>
        ),
      },
    });
  });

  return router;
}
