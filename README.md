# Honeypod — Web Honeypot + AI Dashboard

Saxta web sayt (**honeypot**) hücumçuları/skanerləri cəlb edir, hər HTTP sorğusunu
Postgres-ə yazır. **Vue dashboard** həmin hadisələri göstərir, hazır (pre-trained) LLM
isə onları təsnif edib Azərbaycan dilində hesabat çıxarır.

> **Heç bir model TRAIN edilmir** — yalnız hazır model çağırılır.
> Layihə tamamilə müdafiə/öyrənmə (kurs) məqsədlidir.

## Texnologiya

PEVN monorepo: **P**ostgres (Supabase) + **E**xpress + **V**ue 3 + **N**ode.js,
Prisma ORM, Vite, npm workspaces, ES modules.

## Memarlıq — İKİ AYRI server

| Server | Port (default) | Təyinat |
|---|---|---|
| **Honeypot** | `8080` (`HONEYPOT_PORT`) | İnternetə açılan SAXTA sayt. Yalnız catch-all loglama. Burada admin/dashboard endpointi **yoxdur**. |
| **Dashboard API** | `3000` (`API_PORT`) | **DAXİLİ**. İnternetə açma. Vue dashboard buna müraciət edir. |

Hər ikisi bir Node prosesində, amma ayrı Express `app` və ayrı portlarda işləyir
(`server/src/index.js`).

## Quraşdırma

```bash
npm install
cp .env.example .env         # Supabase məlumatlarını doldur (Windows: copy .env.example .env)
npx prisma migrate dev --name init
npm run dev                  # honeypot + api + client birlikdə (concurrently)
# AI üçün:  ollama pull llama3.1   (Ollama quraşdırılmış olsun)
```

Açılır:

- Dashboard → http://localhost:5173
- Honeypot (saxta sayt) → http://localhost:8080
- API (daxili) → http://localhost:3000

### Supabase bağlantısı

`.env` faylında iki URL lazımdır (Supabase → Project Settings → Database → Connection string):

- `DATABASE_URL` — **pooled**, port `6543`, sonunda `?pgbouncer=true`
- `DIRECT_URL` — **direct**, port `5432` (migration üçün)

## npm skriptləri

| Skript | Nə edir |
|---|---|
| `npm run dev` | server + client birlikdə |
| `npm run dev:server` | yalnız honeypot + API |
| `npm run dev:client` | yalnız Vue dashboard |
| `npm run demo` | honeypota nümunə hücum trafiki göndərir |
| `npm run prisma:migrate` | migration |
| `npm run prisma:studio` | Prisma Studio |

## Test / demo

Ən sadəsi:

```bash
npm run demo
```

Və ya əl ilə `curl` ilə:

```bash
# SQL injection
curl -A "sqlmap/1.7.2" "http://localhost:8080/products?id=1'%20OR%20'1'='1"

# Path traversal
curl "http://localhost:8080/download?file=../../../../etc/passwd"

# XSS
curl "http://localhost:8080/search?q=<script>alert(1)</script>"

# Command injection
curl "http://localhost:8080/ping?host=127.0.0.1;cat%20/etc/shadow"

# Brute-force
curl -X POST -d "username=admin&password=123456" http://localhost:8080/admin
curl -X POST -d "username=admin&password=admin"  http://localhost:8080/admin

# Həssas fayl yoxlaması
curl http://localhost:8080/.env
curl http://localhost:8080/.git/config
```

Sonra dashboard-da **“Təhlil et”** düyməsinə bas → AI hadisələrə `attackType`/`severity`
yazır və bir `Report` yaradır.

> Honeypot bazaya yazmanı **gözləmir** (saxta sayt həmişə dərhal cavab verməlidir),
> ona görə də sorğular dashboard-da bir neçə saniyə gecikmə ilə görünür.
> “Təhlil et”ə basmadan əvvəl **“Təhlil gözləyir”** sayının stabilləşməsini gözlə —
> əks halda yalnız artıq yazılmış hadisələr təhlil olunar (qalanları növbəti təhlildə).

## Honeypot tələləri

| Yol | `route` | Cavab |
|---|---|---|
| `/`, `/login` | `login-lure` | saxta login HTML |
| `/admin`, `/administrator`, `/wp-login.php`, `/wp-admin`, `/phpmyadmin` | `admin-lure` | saxta admin login (POST → həmişə 401) |
| `/.env`, `/config.php`, `/.git/config` | `sensitive-file-probe` | saxta, DƏYƏRSİZ məzmun (real sirr yoxdur) |
| qalan hər şey | `catch-all` | saxta Apache 404 |

## API (daxili)

| Endpoint | Təyinat |
|---|---|
| `GET /api/stats` | ümumi sorğu, unikal IP, top IP/yollar, attackType və severity bölgüsü |
| `GET /api/events?limit=&offset=&attackType=&severity=&ip=` | son hadisələr (səhifələmə ilə) |
| `GET /api/reports?limit=` | hesabatlar (ən yenidən köhnəyə) |
| `POST /api/analyze` | analiz edilməmiş hadisələri (≤80) təsnif edir və hesabat yaradır |

## AI provayderi

Default: **Ollama** (yerli, pulsuz). `.env`-də `LLM_PROVIDER` dəyişəni ilə keçid:

```env
LLM_PROVIDER="ollama"   # OLLAMA_URL, OLLAMA_MODEL
LLM_PROVIDER="groq"     # GROQ_API_KEY (+ istəyə görə GROQ_MODEL)
LLM_PROVIDER="gemini"   # GEMINI_API_KEY (+ istəyə görə GEMINI_MODEL)
```

`attackType` dəyərləri: `sql_injection`, `path_traversal`, `xss`, `command_injection`,
`scanner_bot`, `brute_force`, `sensitive_file_probe`, `unknown`.
`severity`: `low` | `medium` | `high`.

Model cavabı JSON kimi oxuna bilməsə, hadisələr `unknown`/`low` işarələnir və hesabatda
bu barədə qeyd yazılır.

## Problemlər

| Problem | Həll |
|---|---|
| `Can't reach database server` | `.env`-dəki `DATABASE_URL`/`DIRECT_URL` və Supabase parolu yoxla |
| `prepared statement ... already exists` | `DATABASE_URL` sonunda `?pgbouncer=true` olduğundan əmin ol |
| `LLM-ə qoşulmaq mümkün olmadı` | Ollama işləyirmi: `ollama list`, model yüklənibmi: `ollama pull llama3.1` |
| Təhlil çox uzun çəkir | daha kiçik model (`llama3.2`) və ya `LLM_PROVIDER="groq"` |
| `Təhlil üçün yeni hadisə yoxdur` | əvvəlcə honeypota sorğu göndər (`npm run demo`) |

## Etik qeyd

Honeypot yalnız öz serverində işlədilir, heç nə icra etmir, real sirr saxlamır.
Başqasının sistemini sınamaq üçün deyil.
