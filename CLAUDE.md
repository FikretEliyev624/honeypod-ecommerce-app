# CLAUDE.md — Honeypod

Web honeypot + AI təhlili dashboard-u. Müdafiə/öyrənmə (kurs) layihəsidir.

## Əsas qaydalar

- **İKİ AYRI server var, onları qarışdırma:**
  - `HONEYPOT_PORT` (8080) — internetə açılan SAXTA sayt, yalnız catch-all loglama.
    Bura **heç vaxt** admin/dashboard endpointi əlavə etmə.
  - `API_PORT` (3000) — DAXİLİ dashboard API-si. İnternetə açılmır.
- **Heç bir model TRAIN edilmir** — yalnız hazır (pre-trained) model çağırılır (`server/src/lib/llm.js`).
- Honeypot heç nə **icra etmir** (`exec`/`eval` yoxdur) və **real sirr saxlamır** —
  `/.env`, `/config.php`, `/.git/config` cavabları uydurma placeholder-lərdir.
- ES modules (`import/export`), `"type": "module"`.
- Prisma client **həmişə** `server/src/prisma.js`-dən import olunur, `new PrismaClient()` yazma.
- Gizli açarlar yalnız `.env`-də (`.gitignore`-dadır). `.env.example` yenilənməlidir.
- **Şərhlər Azərbaycan dilində** yazılır.

## Struktur

```
prisma/schema.prisma        HoneypotEvent, Report
server/src/index.js         iki Express app-i işə salır
server/src/prisma.js        PrismaClient tək nüsxə
server/src/routes/honeypot.js   SAXTA sayt + catch-all loglama
server/src/routes/api.js        /api/stats, /api/events, /api/reports
server/src/routes/analyze.js    POST /api/analyze — AI təsnifatı + hesabat
server/src/lib/llm.js           askLLM() — ollama | groq | gemini
client/src/components/Dashboard.vue   bütün UI
scripts/demo-traffic.mjs    demo hücum trafiki
```

## Verilənlər modeli

- `HoneypotEvent` — ip, method, path, query, userAgent, headers(Json), body(≤2000 simvol),
  route (`login-lure` | `admin-lure` | `sensitive-file-probe` | `catch-all`),
  attackType/severity/analyzed (AI doldurur).
- `Report` — model, eventCount, summary (ingilis dilində), breakdown `[{type, severity, count}]`.

## AI təsnifat dəyərləri

`attackType`: sql_injection, path_traversal, xss, command_injection, scanner_bot,
brute_force, sensitive_file_probe, unknown — `severity`: low | medium | high.
Model cavabı parse olunmasa → hamısı `unknown`/`low` (fallback).

## Əmrlər

```bash
npm run dev            # honeypot + api + client
npm run demo           # honeypota nümunə hücum trafiki
npm run prisma:migrate
npm run prisma:studio
```
