import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import { createDatabase, seedDemoDataIfEmpty } from './server/db.ts';
import { createGatePulseApp } from './server/app.ts';

async function startServer() {
  const db = createDatabase();
  seedDemoDataIfEmpty(db);

  const { app, triggerWorker } = createGatePulseApp({ db });

  // Background queue worker polling every 1 second for scheduled retries
  const workerInterval = setInterval(() => {
    void triggerWorker();
  }, 1000);
  workerInterval.unref();

  const isProd = process.env.NODE_ENV === 'production';
  const distDir = path.resolve(process.cwd(), 'dist');

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else if (fs.existsSync(distDir)) {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`GatePulse server running at http://localhost:${port}`);
  });
}

void startServer();
