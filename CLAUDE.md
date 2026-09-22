# CLAUDE.md — Honeypod

Web honeypot + AI təhlili dashboard-u. Müdafiə/öyrənmə (kurs) layihəsidir.

## Əsas qaydalar

- **İKİ AYRI server var, onları qarışdırma:**
  - `HONEYPOT_PORT` (8080) — internetə açılan SAXTA sayt, yalnız catch-all loglama.
    Bura **heç vaxt** admin/dashboard endpointi əlavə etmə.
  - `API_PORT` (3000) — DAXİLİ dashboard API-si (+ prod-da build olunmuş UI).
    Default `127.0.0.1`-ə bind olunur, internetə açılmır.
- **Heç bir model TRAIN edilmir** — yalnız hazır (pre-trained) model çağırılır (`server/src/lib/llm.js`).
- Honeypot heç nə **icra etmir** (`exec`/`eval` yoxdur) və **real sirr saxlamır** —
  `/.env`, `/config.php`, `/.git/config` cavabları uydurma placeholder-lərdir.
- ES modules (`import/export`), `"type": "module"`.
- Prisma client **həmişə** `server/src/prisma.js`-dən import olunur, `new PrismaClient()` yazma.
- Gizli açarlar yalnız `.env`-də (`.gitignore`-dadır). `.env.example` yenilənməlidir.
- **Kod şərhləri və bütün istifadəçi mətnləri İNGİLİS dilindədir** (UI, API xətaları,
  konsol logları, README, AI hesabatı).

## Struktur

```
prisma/schema.prisma        HoneypotEvent, Report
server/src/index.js         iki Express app-i işə salır (+ prod-da client/dist, Basic auth)
server/src/prisma.js        PrismaClient tək nüsxə
server/src/routes/honeypot.js   SAXTA sayt + catch-all loglama
server/src/routes/api.js        /api/stats, /api/events, /api/reports
server/src/routes/analyze.js    POST /api/analyze — AI təsnifatı + hesabat
server/src/lib/llm.js           askLLM() — ollama | groq | gemini
server/src/lib/storefront.js    saxta e-commerce səhifələrinin HTML-i
client/src/components/Dashboard.vue   bütün UI
scripts/demo-traffic.mjs    demo hücum trafiki
Dockerfile, docker-compose.yml, .dockerignore   deploy
```

## Verilənlər modeli

- `HoneypotEvent` — ip, method, path, query, userAgent, headers(Json), body(≤2000 simvol),
  route (`storefront` | `product` | `cart` | `checkout` | `fake-payment` | `login-lure` |
  `admin-lure` | `sensitive-file-probe` | `catch-all`),
  attackType/severity/analyzed (AI doldurur).
- `Report` — model, eventCount, summary (ingilis dilində), breakdown `[{type, severity, count}]`.

## AI təsnifat dəyərləri

`attackType`: sql_injection, path_traversal, xss, command_injection, scanner_bot,
brute_force, sensitive_file_probe, unknown — `severity`: low | medium | high.
Model cavabı parse olunmasa → hamısı `unknown`/`low` (fallback).

## Deploy

- `SERVICE` env dəyişəni prosesin nəyi işlətdiyini seçir: `both` (default, iki port) |
  `honeypot` | `dashboard`. `both` olmayanda platformanın verdiyi `PORT` istifadə olunur.
- `NODE_ENV=production` → dashboard app `client/dist`-i verir (single origin, CORS yoxdur)
  və xəta detalları gizlədilir.
- `DASHBOARD_USER` + `DASHBOARD_PASSWORD` hər ikisi təyin olunsa, dashboard HTTP Basic
  auth tələb edir (`/health` açıq qalır). Prod-da dashboard public host-a bind olunub
  auth yoxdursa, proses **qəsdən start olmur** (məlumat sızmasın).
- Free deploy (Docker-siz): `render.yaml` — eyni repo-dan iki Render servisi
  (`SERVICE=honeypot` public, `SERVICE=dashboard` Basic auth ilə), DB Supabase, LLM Groq.
- Docker (opsional): `docker compose up -d --build` — 8080 public, 3000 yalnız
  `127.0.0.1`-ə map olunur.

## Əmrlər

```bash
npm run dev            # honeypot + api + client
npm run build          # client/dist
npm start              # production (NODE_ENV=production ilə)
npm run deploy:start   # migrate deploy + start
npm run demo           # honeypota nümunə hücum trafiki
npm run prisma:migrate # dev migration
npm run prisma:deploy  # prod migration
npm run prisma:studio
```
