import express from 'express';
import type { DatabaseSync } from 'node:sqlite';
import { createConsoleRouter } from './consoleRoutes.ts';
import { createGatewayRouter } from './gateway.ts';
import { processPendingDeliveries, type FetchLike } from './dispatcher.ts';
import type { SlidingWindowRateLimiter } from './security.ts';
import type { DnsLookupFn } from './ssrf.ts';

export interface AppDependencies {
  db: DatabaseSync;
  sessionSecret?: string;
  rateLimiter?: SlidingWindowRateLimiter;
  nowMs?: () => number;
  dnsLookup?: DnsLookupFn;
  fetchFn?: FetchLike;
  autoProcessQueue?: boolean;
}

export function createGatePulseApp(deps: AppDependencies): {
  app: express.Express;
  triggerWorker: () => Promise<void>;
} {
  const app = express();
  const sessionSecret =
    deps.sessionSecret ?? process.env.SESSION_SECRET ?? 'gatepulse-dev-secret-change-in-prod';

  let workerRunning = false;
  const triggerWorker = async () => {
    if (workerRunning) return;
    workerRunning = true;
    try {
      await processPendingDeliveries(deps.db, {
        fetchFn: deps.fetchFn,
        nowMs: deps.nowMs,
      });
    } finally {
      workerRunning = false;
    }
  };

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'gatepulse' });
  });

  app.use(
    '/v1',
    createGatewayRouter({
      db: deps.db,
      rateLimiter: deps.rateLimiter,
      nowMs: deps.nowMs,
      dnsLookup: deps.dnsLookup,
      onEventQueued: () => {
        if (deps.autoProcessQueue !== false) {
          setImmediate(() => {
            void triggerWorker();
          });
        }
      },
    })
  );

  app.use(
    '/api',
    createConsoleRouter({
      db: deps.db,
      sessionSecret,
      dnsLookup: deps.dnsLookup,
      onEventQueued: () => {
        if (deps.autoProcessQueue !== false) {
          setImmediate(() => {
            void triggerWorker();
          });
        }
      },
    })
  );

  return { app, triggerWorker };
}
