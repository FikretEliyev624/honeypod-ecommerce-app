// İKİ AYRI server bir prosesdə:
//   1) honeypot  — internetə açılan saxta sayt (yalnız loglama)
//   2) api       — DAXİLİ dashboard API-si (internetə açılmır)
// Bu iki app-i qətiyyən qarışdırma.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// .env layihənin kökündədir (server/src → ../../)
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// dotenv-dən sonra import olunur ki, env dəyişənləri artıq yüklənmiş olsun.
const { default: honeypotRouter } = await import('./routes/honeypot.js');
const { default: apiRouter } = await import('./routes/api.js');
const { default: analyzeRouter } = await import('./routes/analyze.js');
const { prisma } = await import('./prisma.js');

const HONEYPOT_PORT = Number(process.env.HONEYPOT_PORT) || 8080;
const API_PORT = Number(process.env.API_PORT) || 3000;

// ── 1) Honeypot app ────────────────────────────────────────────────────────
const honeypot = express();
honeypot.disable('x-powered-by');
honeypot.set('trust proxy', true); // reverse proxy arxasında real IP üçün
honeypot.use(honeypotRouter);

// ── 2) Dashboard API app (DAXİLİ) ──────────────────────────────────────────
const api = express();
api.disable('x-powered-by');
api.use(cors()); // yalnız dev üçün — Vite proxy-si ilə işləyir
api.use(express.json({ limit: '256kb' }));
api.get('/health', (req, res) => res.json({ ok: true }));
api.use(apiRouter);
api.use(analyzeRouter);

// Ümumi xəta handler-i
api.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[api] error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

const honeypotServer = honeypot.listen(HONEYPOT_PORT, () => {
  console.log(`🍯 Honeypot (FAKE site):     http://localhost:${HONEYPOT_PORT}`);
});

const apiServer = api.listen(API_PORT, () => {
  console.log(`📊 Dashboard API (internal): http://localhost:${API_PORT}`);
  console.log(`   LLM provider: ${process.env.LLM_PROVIDER || 'ollama'}`);
});

// Təmiz bağlanma
async function shutdown(signal) {
  console.log(`\n${signal} — shutting down servers...`);
  await Promise.all([
    new Promise((resolve) => honeypotServer.close(resolve)),
    new Promise((resolve) => apiServer.close(resolve)),
  ]);
  await prisma.$disconnect();
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
