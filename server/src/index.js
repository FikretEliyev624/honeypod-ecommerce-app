// TWO SEPARATE servers:
//   1) honeypot  — the internet-facing fake site (logging only)
//   2) api       — the INTERNAL dashboard API (+ the built UI in production)
// Never mix these two apps.
//
// SERVICE selects what this process runs:
//   both (default) — one process, two ports (local dev, VPS)
//   honeypot       — only the fake site, on PORT (one port per service on a PaaS)
//   dashboard      — only the dashboard, on PORT
import fs from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// .env lives at the project root (server/src → ../../)
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// Imported after dotenv so the env variables are already loaded.
const { default: honeypotRouter } = await import('./routes/honeypot.js');
const { default: apiRouter } = await import('./routes/api.js');
const { default: analyzeRouter } = await import('./routes/analyze.js');
const { prisma } = await import('./prisma.js');

const IS_PROD = process.env.NODE_ENV === 'production';

const SERVICE = (process.env.SERVICE || 'both').toLowerCase().trim();
if (!['both', 'honeypot', 'dashboard'].includes(SERVICE)) {
  console.error(`Unknown SERVICE: "${SERVICE}". Allowed values: both, honeypot, dashboard.`);
  process.exit(1);
}
const RUN_HONEYPOT = SERVICE === 'both' || SERVICE === 'honeypot';
const RUN_DASHBOARD = SERVICE === 'both' || SERVICE === 'dashboard';

// Hosting platforms (Render, Railway, Fly…) inject a single PORT. It applies only when
// this process runs one of the two servers.
const PLATFORM_PORT = SERVICE === 'both' ? 0 : Number(process.env.PORT) || 0;

const HONEYPOT_PORT = PLATFORM_PORT || Number(process.env.HONEYPOT_PORT) || 8080;
const API_PORT = PLATFORM_PORT || Number(process.env.API_PORT) || 3000;

// The honeypot is meant to be reachable; the dashboard is bound to loopback by default so
// a deployment never exposes it by accident. On a PaaS it must bind 0.0.0.0.
const HONEYPOT_HOST = process.env.HONEYPOT_HOST || '0.0.0.0';
const API_HOST = process.env.API_HOST || (PLATFORM_PORT ? '0.0.0.0' : '127.0.0.1');

// Built dashboard (npm run build). Served by the API app in production.
const CLIENT_DIST = path.resolve(__dirname, '../../client/dist');
const hasClientBuild = fs.existsSync(path.join(CLIENT_DIST, 'index.html'));

// Optional HTTP Basic auth — enabled only when both variables are set.
const DASHBOARD_USER = process.env.DASHBOARD_USER || '';
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || '';
const HAS_DASHBOARD_AUTH = Boolean(DASHBOARD_USER && DASHBOARD_PASSWORD);

// A publicly reachable dashboard without credentials would expose all collected data,
// so refuse to start instead.
const DASHBOARD_IS_PUBLIC = API_HOST !== '127.0.0.1' && API_HOST !== 'localhost';
if (RUN_DASHBOARD && IS_PROD && DASHBOARD_IS_PUBLIC && !HAS_DASHBOARD_AUTH) {
  console.error(
    `Refusing to start: the dashboard would listen on ${API_HOST} without authentication.\n` +
      'Set DASHBOARD_USER and DASHBOARD_PASSWORD, or bind it to 127.0.0.1 (API_HOST).',
  );
  process.exit(1);
}

// ── 1) Honeypot app ────────────────────────────────────────────────────────
const honeypot = express();
honeypot.disable('x-powered-by');
honeypot.disable('etag'); // a fake store should not leak cache validators
honeypot.set('trust proxy', true); // real client IP behind a reverse proxy
honeypot.use(honeypotRouter);

// ── 2) Dashboard API app (INTERNAL) ────────────────────────────────────────
const api = express();
api.disable('x-powered-by');
api.set('trust proxy', true);

// Uptime probes must work without credentials.
api.get('/health', (req, res) => res.json({ ok: true }));

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

if (HAS_DASHBOARD_AUTH) {
  api.use((req, res, next) => {
    const header = req.headers.authorization || '';
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      const [user, ...rest] = Buffer.from(encoded, 'base64').toString('utf8').split(':');
      if (safeEqual(user, DASHBOARD_USER) && safeEqual(rest.join(':'), DASHBOARD_PASSWORD)) {
        next();
        return;
      }
    }
    res.set('WWW-Authenticate', 'Basic realm="Honeypod dashboard", charset="UTF-8"');
    res.status(401).json({ error: 'Authentication required' });
  });
}

// In development the Vite dev server (port 5173) is a different origin; in production the
// dashboard is served from this same app, so CORS is not needed.
if (!IS_PROD) api.use(cors());

api.use(express.json({ limit: '256kb' }));
api.use(apiRouter);
api.use(analyzeRouter);

// Serve the built dashboard when it exists (production single-origin setup).
if (hasClientBuild) {
  api.use(express.static(CLIENT_DIST, { index: false, maxAge: '1h' }));
  // SPA fallback — everything that is not an /api route returns index.html.
  api.get(/^\/(?!api\/).*/, (req, res, next) => {
    if (req.method !== 'GET') return next();
    res.sendFile(path.join(CLIENT_DIST, 'index.html'));
  });
} else if (IS_PROD && RUN_DASHBOARD) {
  console.warn('[api] client/dist not found — run "npm run build" to serve the dashboard.');
}

// Shared error handler
api.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[api] error:', err);
  // Internal details are not leaked in production.
  res.status(500).json({ error: IS_PROD ? 'Internal server error' : err.message });
});

// ── Start whichever servers this process is responsible for ────────────────
const servers = [];

if (RUN_HONEYPOT) {
  servers.push(
    honeypot.listen(HONEYPOT_PORT, HONEYPOT_HOST, () => {
      console.log(`🍯 Honeypot (FAKE site):     http://${HONEYPOT_HOST}:${HONEYPOT_PORT}`);
    }),
  );
}

if (RUN_DASHBOARD) {
  servers.push(
    api.listen(API_PORT, API_HOST, () => {
      console.log(`📊 Dashboard (API + UI):     http://${API_HOST}:${API_PORT}`);
      console.log(`   LLM provider: ${process.env.LLM_PROVIDER || 'ollama'}`);
      if (hasClientBuild) console.log('   Dashboard UI served from client/dist');
      console.log(`   Basic auth: ${HAS_DASHBOARD_AUTH ? 'on' : 'off (localhost only)'}`);
    }),
  );
}

console.log(`   Service: ${SERVICE} · mode: ${IS_PROD ? 'production' : 'development'}`);

// Clean shutdown
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n${signal} — shutting down servers...`);
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  await prisma.$disconnect();
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
