# Honeypod — Web Honeypot + AI Dashboard

A fake web store (**honeypot**) attracts attackers and scanners and writes every HTTP
request to Postgres. A **Vue dashboard** displays those events, and a pre-trained LLM
classifies them and produces an English report.

> **No model is ever TRAINED** — only a pre-trained model is called.
> The project is strictly for defensive/educational (coursework) purposes.

## Tech stack

PEVN monorepo: **P**ostgres (Supabase) + **E**xpress + **V**ue 3 + **N**ode.js,
Prisma ORM, Vite, npm workspaces, ES modules.

## Architecture — TWO SEPARATE servers

| Server | Port (default) | Purpose |
|---|---|---|
| **Honeypot** | `8080` (`HONEYPOT_PORT`) | The FAKE site exposed to the internet. Catch-all logging only. It has **no** admin/dashboard endpoint. |
| **Dashboard API** | `3000` (`API_PORT`) | **INTERNAL**. Do not expose it to the internet. The Vue dashboard talks to this. |

Both run in a single Node process, but as separate Express `app` instances on separate
ports (`server/src/index.js`).

## Setup

```bash
npm install
cp .env.example .env         # fill in your Supabase details (Windows: copy .env.example .env)
npx prisma migrate dev --name init
npm run dev                  # honeypot + api + client together (concurrently)
# For the AI:  ollama pull llama3.1   (requires Ollama to be installed)
```

Available at:

- Dashboard → http://localhost:5173
- Honeypot (fake site) → http://localhost:8080
- API (internal) → http://localhost:3000

### Supabase connection

The `.env` file needs two URLs (Supabase → Project Settings → Database → Connection string):

- `DATABASE_URL` — **pooled**, port `6543`, ending with `?pgbouncer=true`
- `DIRECT_URL` — **direct**, port `5432` (used for migrations)

## npm scripts

| Script | What it does |
|---|---|
| `npm run dev` | server + client together |
| `npm run dev:server` | honeypot + API only |
| `npm run dev:client` | Vue dashboard only |
| `npm run build` | builds the dashboard into `client/dist` |
| `npm start` | production start (serves the API + the built dashboard) |
| `npm run deploy:start` | `prisma migrate deploy` + production start |
| `npm run demo` | sends sample attack traffic to the honeypot |
| `npm run prisma:migrate` | dev migration |
| `npm run prisma:deploy` | applies migrations in production |
| `npm run prisma:studio` | Prisma Studio |

## Test / demo

The simplest way:

```bash
npm run demo
```

To hit a deployed honeypot instead of the local one, pass its URL:

```bash
npm run demo -- https://your-honeypot.onrender.com
```

Or manually with `curl`:

```bash
# SQL injection
curl -A "sqlmap/1.7.2" "http://localhost:8080/products?id=1'%20OR%20'1'='1"

# Path traversal
curl "http://localhost:8080/download?file=../../../../etc/passwd"

# XSS
curl "http://localhost:8080/search?q=<script>alert(1)</script>"

# Command injection
curl "http://localhost:8080/ping?host=127.0.0.1;cat%20/etc/shadow"

# Brute force
curl -X POST -d "username=admin&password=123456" http://localhost:8080/admin
curl -X POST -d "username=admin&password=admin"  http://localhost:8080/admin

# Sensitive file probe
curl http://localhost:8080/.env
curl http://localhost:8080/.git/config
```

Then press **“Analyze”** in the dashboard → the AI writes `attackType`/`severity` onto the
events and creates a `Report`.

> The honeypot does **not** wait for the database write (the fake site must always answer
> instantly), so requests show up in the dashboard with a few seconds of delay.
> Before pressing “Analyze”, wait for the **“Pending analysis”** counter to settle —
> otherwise only the events already written are analyzed (the rest come in the next run).

## Honeypot traps

| Path | `route` | Response |
|---|---|---|
| `/`, `/shop`, `/products`, `/search` | `storefront` | fake store pages (home, catalogue, search) |
| `/product/:id` | `product` | fake product page (404 page for an unknown id) |
| `/cart` | `cart` | fake cart |
| `GET /checkout`, `/pay`, `/api/pay`, `/api/checkout`, `/payment` | `checkout` | fake payment form (no real processing) |
| `POST` to the same payment paths | `fake-payment` | always “declined” (402), the submitted card data is only logged |
| `/account/login`, `/login`, `/account/register` | `login-lure` | fake account login (POST → always 401) |
| `/admin`, `/administrator`, `/wp-login.php`, `/wp-admin`, `/phpmyadmin`, `/.env.bak` | `admin-lure` | fake admin login (POST → always 401) |
| `/.env`, `/config.php`, `/.git/config` | `sensitive-file-probe` | fake, WORTHLESS content (no real secrets) |
| everything else | `catch-all` | fake 404 store page |

## API (internal)

| Endpoint | Purpose |
|---|---|
| `GET /api/stats` | total requests, unique IPs, top IPs/paths, attackType and severity breakdown |
| `GET /api/events?limit=&offset=&attackType=&severity=&ip=` | recent events (paginated) |
| `GET /api/reports?limit=` | reports (newest first) |
| `POST /api/analyze` | classifies unanalyzed events (≤80) and creates a report |

## AI provider

Default: **Ollama** (local, free). Switch with the `LLM_PROVIDER` variable in `.env`:

```env
LLM_PROVIDER="ollama"   # OLLAMA_URL, OLLAMA_MODEL
LLM_PROVIDER="groq"     # GROQ_API_KEY (+ optional GROQ_MODEL)
LLM_PROVIDER="gemini"   # GEMINI_API_KEY (+ optional GEMINI_MODEL)
```

`attackType` values: `sql_injection`, `path_traversal`, `xss`, `command_injection`,
`scanner_bot`, `brute_force`, `sensitive_file_probe`, `unknown`.
`severity`: `low` | `medium` | `high`.

If the model response cannot be parsed as JSON, the events are marked `unknown`/`low` and
a note about it is added to the report.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Can't reach database server` | check `DATABASE_URL`/`DIRECT_URL` in `.env` and your Supabase password |
| `prepared statement ... already exists` | make sure `DATABASE_URL` ends with `?pgbouncer=true` |
| `Could not connect to the LLM` | is Ollama running: `ollama list`, is the model pulled: `ollama pull llama3.1` |
| Analysis takes too long | use a smaller model (`llama3.2`) or `LLM_PROVIDER="groq"` |
| `No new events to analyze.` | send some traffic to the honeypot first (`npm run demo`) |
| `vite: not found` / `prisma: not found` during a hosted build | the build ran with `NODE_ENV=production`, which skips devDependencies — use `npm ci --include=dev` |
| the dashboard service exits right after start | it would be public without credentials — set `DASHBOARD_USER` and `DASHBOARD_PASSWORD` |
| `LLM request failed … model_not_found` | the provider retired that model — set `GROQ_MODEL`/`GEMINI_MODEL` to one your key can list (`curl -s https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY"`) |

## Deployment

The two servers stay strictly separated in production as well:

- the **fake site** is the only thing that may face the internet;
- the **dashboard** (API + built Vue UI) is bound to `127.0.0.1` by default, and refuses to
  start on a public interface unless HTTP Basic auth is configured.

`SERVICE` decides what a process runs:

| `SERVICE` | Runs | Port |
|---|---|---|
| `both` (default) | honeypot + dashboard in one process | `HONEYPOT_PORT` and `API_PORT` |
| `honeypot` | the fake site only | `PORT` (platform) or `HONEYPOT_PORT` |
| `dashboard` | the dashboard only | `PORT` (platform) or `API_PORT` |

Hosting platforms give one port per service, so there you deploy the same repo twice.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `NODE_ENV` | `development` | `production` serves `client/dist` from the dashboard app and hides error details |
| `SERVICE` | `both` | `both` / `honeypot` / `dashboard` |
| `PORT` | — | injected by the hosting platform; used when `SERVICE` is not `both` |
| `HONEYPOT_PORT` / `HONEYPOT_HOST` | `8080` / `0.0.0.0` | the public fake site |
| `API_PORT` / `API_HOST` | `3000` / `127.0.0.1` | the dashboard; loopback-only unless overridden |
| `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | unset | when **both** are set, the dashboard requires HTTP Basic auth (`/health` stays open) |
| `DATABASE_URL` / `DIRECT_URL` | — | Supabase pooled / direct connection strings |
| `LLM_PROVIDER` + provider key | `ollama` | use `groq` or `gemini` when hosting (a local Ollama is not available there) |

### Option A — Render free tier (no Docker)

Free stack: **Render** (two web services) + **Supabase** (database) + **Groq** (LLM API).

1. Push the repo to GitHub.
2. Create the database on [supabase.com](https://supabase.com) and copy both connection
   strings (pooled `:6543` with `?pgbouncer=true`, and direct `:5432`).
3. Get a free API key from [console.groq.com](https://console.groq.com).
4. On [render.com](https://render.com) → **New → Blueprint**, pick the repo. `render.yaml`
   creates the two services; fill in the variables marked `sync: false`:

   | Service | Variables to set |
   |---|---|
   | `honeypod-honeypot` | `DATABASE_URL`, `DIRECT_URL` |
   | `honeypod-dashboard` | `DATABASE_URL`, `DIRECT_URL`, `DASHBOARD_USER`, `DASHBOARD_PASSWORD`, `GROQ_API_KEY` |

5. The dashboard service runs `prisma migrate deploy` during its build, so the schema is
   created on the first deploy.

You end up with two URLs: `honeypod-honeypot.onrender.com` (the bait — share this one) and
`honeypod-dashboard.onrender.com` (asks for the Basic auth user/password).

Free-tier caveats:

- services sleep after ~15 minutes of inactivity and need ~1 minute to wake up, so the
  first request after a quiet period is slow (an attacker still gets logged);
- Render's own health checks and internet background scans appear as events — that is
  real honeypot traffic, not a bug;
- the LLM must be a hosted API (`groq` or `gemini`); `ollama` only works where you run it.

Deploying without the blueprint is the same thing by hand: two **Web Services** from one
repo, runtime Node, build `npm ci --include=dev && npx prisma generate` (the dashboard also needs
`&& npm run build && npx prisma migrate deploy`), start `node server/src/index.js`, plus
`SERVICE=honeypot` / `SERVICE=dashboard` and `NODE_ENV=production`.

### Option B — Railway (no Docker)

Railway builds the repo with Nixpacks, so no Dockerfile is involved. It has no permanent
free tier (a trial credit, then a paid plan), but services do not sleep.

Create **one project with two services from the same repo** — Railway has no blueprint
file for multi-service repos, so set them up in the UI:

| Setting | `honeypot` service | `dashboard` service |
|---|---|---|
| Build command | `npm ci --include=dev && npx prisma generate` | `npm ci --include=dev && npx prisma generate && npm run build && npx prisma migrate deploy` |
| Start command | `node server/src/index.js` | `node server/src/index.js` |
| Variables | `NODE_ENV=production`, `SERVICE=honeypot`, `DATABASE_URL`, `DIRECT_URL` | `NODE_ENV=production`, `SERVICE=dashboard`, `DATABASE_URL`, `DIRECT_URL`, `DASHBOARD_USER`, `DASHBOARD_PASSWORD`, `LLM_PROVIDER=groq`, `GROQ_API_KEY` |
| Public domain | generate one — this is the bait URL | generate one — protected by Basic auth |

`PORT` is injected by Railway; the app picks it up automatically whenever `SERVICE` is not
`both`. Do not set `HONEYPOT_PORT`/`API_PORT` there.

### Option C — your own VPS (no Docker)

```bash
npm ci
npm run build                # builds client/dist
npx prisma generate
npx prisma migrate deploy    # applies migrations to the production database
NODE_ENV=production npm start   # SERVICE=both: 8080 public, 3000 on localhost
```

systemd unit (`/etc/systemd/system/honeypod.service`):

```ini
[Unit]
Description=Honeypod (honeypot + dashboard)
After=network.target

[Service]
WorkingDirectory=/opt/honeypod
EnvironmentFile=/opt/honeypod/.env
Environment=NODE_ENV=production
ExecStart=/usr/bin/node server/src/index.js
Restart=always
User=honeypod

[Install]
WantedBy=multi-user.target
```

Reaching the dashboard from your own machine (no public port needed):

```bash
ssh -L 3000:127.0.0.1:3000 user@server   # then open http://localhost:3000
```

If you prefer to publish it behind a reverse proxy, set `DASHBOARD_USER` and
`DASHBOARD_PASSWORD` first and terminate TLS at the proxy. Behind any proxy, pass the real
client IP through (`X-Forwarded-For`) — the app already trusts it:

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### Option D — Docker (optional)

`Dockerfile` and `docker-compose.yml` are included for whoever wants them:

```bash
docker compose up -d --build
```

The compose file publishes `8080` publicly and maps the dashboard to `127.0.0.1:3000`
only; migrations run on container start.

### Pre-deploy checklist

- [ ] `.env` is **not** committed (only `.env.example` is)
- [ ] `NODE_ENV=production`
- [ ] the dashboard is on localhost, or `DASHBOARD_USER`/`DASHBOARD_PASSWORD` are set
- [ ] `prisma migrate deploy` has run against the production database
- [ ] the LLM provider is reachable from the server (`groq`/`gemini` when hosted)
- [ ] the honeypot runs on a host of your own, isolated from production systems

## Ethical note

The honeypot runs only on your own server, executes nothing and stores no real secrets.
It is not meant for testing anyone else's systems.
