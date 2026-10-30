# Deployment

SENTINEL AI ships as one application: a FastAPI backend that also serves the compiled React
bundle. This keeps deployment to a single process, a single port and two writable volumes.
That is a deliberate trade-off in favour of a small attack surface and simple operations, not
a claim that one process suits every scale.

---

## 1. Development

Requirements: Python 3.11+ (3.13 tested), Node.js 20+ (24 tested).

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` and `/ws` to `127.0.0.1:8000`. Use
`localhost`, not `127.0.0.1`, for the browser: cookie and origin handling are simplest when
the host matches what the API allowlist expects.

On first start the API creates the database, seeds roles, workspaces, the demo corpus, demo
accounts and either trains or loads the four detection models. OpenAPI is at `/docs`.

To reset development state, stop the server and remove `backend/data/sentinel.db` plus
`backend/models/trained`. The next start recreates and re-seeds them. Do not delete
`backend/data/.secret_key` unless you intend to invalidate every session.

---

## 2. Production build

```bash
cd frontend
npm ci
npm run build        # type-checks, then emits frontend/dist
```

Start the backend without `--reload`:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --workers 1
```

When `frontend/dist` exists, the API serves `index.html` for application routes and static
assets from `dist/assets`. Unknown `/api`, `/ws`, `/docs` paths return a real 404 instead of
the SPA shell.

### Worker count

Run **one** Uvicorn worker per database file. The replay engine and event bus keep
in-process state (`_controls`, subscriber queues), and SQLite serialises writes. A second
worker would duplicate background scheduling and split WebSocket subscribers across
processes. If you need horizontal scale, move to PostgreSQL and an external queue first;
that work is not included in this release.

---

## 3. Docker

```bash
cp .env.example .env
# edit .env: set SENTINEL_SECRET_KEY, decide on demo seeding and external enrichment
docker compose up --build -d
docker compose logs -f sentinel
```

The image is multi-stage:

1. `node:22-alpine` runs `npm ci && npm run build` for the frontend.
2. `python:3.13-slim` installs `backend/requirements.txt`, copies the backend and the built
   bundle, creates an unprivileged user `sentinel` (uid 10001), and starts Uvicorn.

| Property | Value |
| --- | --- |
| Container port | 8000 |
| Data volume | `sentinel-data` → `/data` (SQLite, uploads, secret file) |
| Model volume | `sentinel-models` → `/models` (joblib artefacts) |
| Healthcheck | HTTP 200 from `/api/v1/health` every 30 s |
| Default allowed origin | `http://localhost:8000` (same-origin serving) |

The compose environment overrides `SENTINEL_DATA_DIR` and `SENTINEL_MODEL_DIR`. Leave those
alone unless you mount different paths.

### Behind a reverse proxy

Terminate TLS at the proxy and forward to port 8000. Set:

```dotenv
SENTINEL_COOKIE_SECURE=true
SENTINEL_ALLOWED_ORIGINS=https://sentinel.example.com
```

Pass `--proxy-headers` (already in the image command) so the client address used by rate
limiting reflects `X-Forwarded-For`. Restrict that header at the proxy; do not accept it from
arbitrary clients. WebSocket upgrade must be allowed on `/ws/events`.

Example Nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;   # keep the event stream alive
}
location /ws/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

---

## 4. Configuration reference

All settings are environment variables. `.env.example` is the authoritative template. At
startup the API loads `.env` from the repository root and then `backend/.env`; variables that
are already exported in the process environment take precedence over both files.

| Variable | Default | Notes |
| --- | --- | --- |
| `SENTINEL_SECRET_KEY` | dev file | **Required in production.** 48-byte URL-safe random string. Rotating it ends all sessions. |
| `SENTINEL_TOKEN_TTL_MINUTES` | `480` | Session lifetime |
| `SENTINEL_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `SENTINEL_COOKIE_SAMESITE` | `lax` | `strict` is viable for single-origin deployments |
| `SENTINEL_ALLOWED_ORIGINS` | localhost:5173 | Exact origins, comma-separated |
| `SENTINEL_DATABASE_URL` | SQLite in data dir | SQLite is the supported default; PostgreSQL needs a driver installed and is untested in this release |
| `SENTINEL_DATA_DIR` | `backend/data` | Database, uploads, persisted dev secret |
| `SENTINEL_MODEL_DIR` | `backend/models` | Joblib artefacts |
| `SENTINEL_MAX_UPLOAD_MB` | `50` | Upload ceiling |
| `SENTINEL_DEMO_ENABLED` | `true` | Seed demo workspace, corpus and demo sign-in |
| `SENTINEL_DEMO_PASSWORD` | `Sentinel!Demo2026` | Change before any shared deployment |
| `SENTINEL_ADMIN_EMAIL` / `SENTINEL_ADMIN_PASSWORD` | demo values | Initial administrator |
| `SENTINEL_SKIP_SEED` | unset | `true` starts with an empty database |
| `SENTINEL_ALLOW_EXTERNAL_ENRICHMENT` | `false` | Master switch for outbound lookups |
| `SENTINEL_LLM_ENABLED` | `false` | Reserved; insights are deterministic without it |
| `THREATFOX_AUTH_KEY` | empty | Server-side only |
| `URLHAUS_AUTH_KEY` | empty | Server-side only |
| `ABUSEIPDB_API_KEY` | empty | Server-side only |
| `GREYNOISE_API_KEY` | empty | Server-side only |
| `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` | empty | Server-side only |
| `MAXMIND_DB_PATH` | empty | Local GeoLite2 database path |
| `SENTINEL_TEST_INDICATOR` | `8.8.8.8` | Indicator used by the provider test button |

---

## 5. Production checklist

**Before first start**

- [ ] Generate and set `SENTINEL_SECRET_KEY`; keep it out of source control.
- [ ] Set `SENTINEL_COOKIE_SECURE=true` and serve exclusively over HTTPS.
- [ ] Set `SENTINEL_ALLOWED_ORIGINS` to the exact production origin. No wildcards.
- [ ] Change `SENTINEL_DEMO_PASSWORD` or set `SENTINEL_DEMO_ENABLED=false`.
- [ ] Decide whether `SENTINEL_ALLOW_EXTERNAL_ENRICHMENT` stays off. The recommended default
      for a first deployment is **off** until change approval exists.
- [ ] Confirm the data directory is on encrypted storage with backups.
- [ ] Decide an upload size ceiling appropriate to your capture sizes.
- [ ] Put the service behind a reverse proxy with request body limits.

**After first start**

- [ ] Sign in as administrator and replace the seeded password.
- [ ] Create real user accounts with the minimum role each person needs; disable demo
      accounts if demo mode is not required.
- [ ] Configure internal CIDRs for the live workspace. Direction-dependent detection
      (exfiltration) is unreliable until this reflects your network.
- [ ] Register collectors, deliver their keys over a secure channel, confirm `LIVE` status
      and heartbeat within five minutes.
- [ ] Upload a representative flow export and read the quality report. Check module coverage
      against the fields your collectors actually emit.
- [ ] Train the models once on your own labelled data before trusting model contributions;
      until then, treat stored synthetic benchmark numbers as a pipeline check only.
- [ ] Verify the audit log records sign-ins, uploads, exports and configuration changes.
- [ ] Confirm `/api/v1/health` and the container healthcheck are monitored.

---

## 6. Backups and recovery

| Asset | Backup method | Recovery notes |
| --- | --- | --- |
| SQLite database | Online backup or filesystem snapshot while stopped | WAL files must be consistent; stop the service or use SQLite backup tooling |
| Uploaded captures | Copy `data/uploads` | Referenced by job records; restoring the DB alone loses the files |
| Model artefacts | Copy `models/` | If lost, retrain; evaluations remain in the database |
| `.secret_key` (dev) | Only if sessions must survive | In production the key is the environment variable, not this file |

Back up the database and uploads together. Restoring one without the other produces jobs that
reference missing files — the application will report the mismatch rather than invent results.

---

## 7. Operations

| Concern | Behaviour |
| --- | --- |
| Logs | stdout via Uvicorn/FastAPI logging. Credential values are never logged; provider errors are redacted |
| Health | `GET /api/v1/health` — unauthenticated, database reachability |
| Readiness | The app starts even if seeding fails, logging a degraded state instead of exiting silently |
| Rate limits | 900 requests/min per client IP on the API; 8 sign-ins/300 s; 12 demo sign-ins/300 s; 120 feed requests/min per collector; 25 provider lookups/min per provider |
| Cache headers | API responses are `no-store` |
| Security headers | `nosniff`, `DENY`, referrer policy, permissions policy, COOP, CSP on non-asset responses |
| Session | HTTP-only signed cookie, SameSite configurable, CSRF token required on mutating requests |

The rate limiter is in-process. With one worker that is exact; with multiple processes it
would be per-process, which is another reason to keep a single worker in this release.

---

## 8. Upgrading

1. Back up the database, uploads and models.
2. Pull the new code and rebuild (`docker compose up --build -d` or rebuild the frontend and
   restart Uvicorn).
3. Start once and let seeding run. Role definitions are reconciled on every start, so
   permission changes apply without manual migration.
4. Review the audit log and the AI page. If the model version changed, verify the stored
   evaluation before enabling model-assisted scoring in production.

There is no migration framework. `init_db` creates missing tables, and seed logic upserts
reference data. A schema-altering upgrade requires an explicit migration step, which this
release does not provide.

---

## 9. Known deployment limits

- SQLite and a single process bound the write throughput and concurrent replay capacity.
- Upload parsing happens in a background task inside the API process; a very large capture
  competes with request handling for CPU.
- The PDF writer is built in and intentionally plain; no external rendering service is used.
- No built-in TLS termination, identity provider (SAML/OIDC) or SIEM forwarding. Those belong
  at the platform edge, and adding them here would widen scope beyond what is tested.
