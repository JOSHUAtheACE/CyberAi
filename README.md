# SENTINEL AI

**Passive network threat-intelligence and monitoring platform.**

SENTINEL AI normalises passively collected flow metadata, runs six behavioural detection
modules and one statistical/ML pipeline, and presents evidence-backed alerts, investigation
workflows and reports. It is read-only with respect to monitored infrastructure: it never
probes, blocks, isolates or reconfigures hosts, and it never decrypts TLS/QUIC payloads.

Every number in the interface is computed from stored telemetry. When a field is missing the
product says so instead of estimating. Demo and replay data are permanently labelled and are
never mixed with live collector data.

---

## Contents

- [Feature map](#feature-map)
- [Architecture](#architecture)
- [Quick start (development)](#quick-start-development)
- [Docker deployment](#docker-deployment)
- [Demo accounts](#demo-accounts)
- [Data-handling and security model](#data-handling-and-security-model)
- [Project layout](#project-layout)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Known limitations](#known-limitations)

---

## Feature map

| Area | What it does |
| --- | --- |
| **Landing page** | Product overview with an interactive WebGL globe; non-WebGL and reduced-motion fallbacks. |
| **Authentication** | Email/password sign-in with scrypt hashing, signed HTTP-only session cookie, CSRF token, per-IP rate limiting, audit logging. |
| **Overview** | Ten backend-derived KPIs with honest comparison windows, geographic arcs, traffic charts, severity distribution, grounded insights and recent alerts. |
| **Traffic & topology** | Paginated flow explorer with protocol/direction/search filters and alert linkage; Cytoscape topology derived from stored flows with no DNS probing. |
| **Data ingestion** | Server-side validation and preview for PCAP/PCAPNG, CSV/TSV, JSON/JSONL and Zeek logs, with a quality report, column mapping, module coverage and rejection reasons. One-way collector push contract. |
| **Replay lab** | Eleven labelled synthetic scenarios and completed uploads, replayed at 0.5×/1×/2×/5× into an isolated REPLAY workspace; ground truth stays attached for evaluation only. |
| **Alert centre** | Deduplicated queue with recurrence counters, severity/protocol/assignee filters, evidence-backed detail, note/status/assignee workflow, false-positive recording, evidence export. No remediation. |
| **Detection workspaces** | DDoS, beaconing, DGA/DNS, TLS/QUIC metadata, port scanning and exfiltration, each with category-specific charts, thresholds, telemetry coverage and score semantics. |
| **AI & models** | Real trained artefacts (Random Forest, Gradient Boosting, calibrated TF-IDF + Logistic Regression, Isolation Forest) with stored precision/recall/F1/ROC AUC, PR and ROC curves, confusion matrices, drift and split composition. Scores are labelled by semantics; confidence is never presented as accuracy. |
| **Threat intelligence** | ThreatFox, URLhaus, AbuseIPDB, GreyNoise and MaxMind, all disabled by default and off unless both the server switch and the provider toggle are enabled. Masked credential presence, rate limits, caching, enrichment audit log and an air-gapped offline snapshot provider. |
| **Reports** | Server-computed reports with a live detail view and PDF/CSV/JSON exports that carry the query, period and known limitations. |
| **Administration** | User management, five server-enforced roles, permission catalogue, searchable audit log, runtime settings and workspace environment separation. |

---

## Architecture

```
┌────────────────────────────┐        ┌─────────────────────────────────┐
│  React 19 + TypeScript     │  HTTPS │  FastAPI (api/v1)               │
│  Vite · Tailwind · ECharts │ ─────► │  SQLAlchemy 2 · SQLite WAL      │
│  globe.gl · Cytoscape      │  WS    │  scikit-learn · httpx           │
└────────────────────────────┘        └──────────────┬──────────────────┘
                                                     │
                                   ┌─────────────────┴──────────────────┐
                                   │ Passive telemetry only             │
                                   │ uploads · one-way collector push   │
                                   └────────────────────────────────────┘
```

- The **browser never captures packets** and is never treated as a sensor.
- Telemetry arrives by validated upload or by an enclave collector that pushes metadata one
  way to `POST /api/v1/feed/ingest`.
- Detection runs server-side. Alerts are persisted with feature-level evidence and the flow
  records they reference.
- External intelligence lookups originate server-side only, are disabled by default, and are
  limited to public indicators.

---

## Quick start (development)

Requirements: Python 3.11+ (3.13 tested), Node.js 20+ (24 tested).

**Backend**

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

On first start the API creates the SQLite database, seeds roles, the demo workspace, a
synthetic corpus and the demo accounts, then exposes OpenAPI at
`http://127.0.0.1:8000/docs`.

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` and `/ws` to the backend on port 8000.

**Production build**

```bash
cd frontend
npm run build     # type-checks then emits frontend/dist
```

When `frontend/dist` exists the FastAPI app serves the SPA itself, so a single process can
host the whole product. Run the backend without `--reload` and set `SENTINEL_SECRET_KEY`.

---

## Docker deployment

```bash
cp .env.example .env          # set SENTINEL_SECRET_KEY and review the rest
docker compose up --build
```

The compose file builds the frontend, copies the static bundle into the backend image and
serves everything from a single container on port 8000. SQLite data and model artefacts are
kept in named volumes.

---

## Demo accounts

Seeded only when `SENTINEL_DEMO_ENABLED=true` (the default for development). All demo
accounts are labelled **DEMO** in the interface.

| Account | Role |
| --- | --- |
| `admin@sentinela.ai` | Security Administrator |
| `analyst@sentinela.ai` | SOC Analyst |
| `engineer@sentinela.ai` | Network Security Engineer |
| `ml@sentinela.ai` | ML Engineer |
| `auditor@sentinela.ai` | Auditor / Management |

Default password: `Sentinel!Demo2026` (override with `SENTINEL_DEMO_PASSWORD`, and change it
before any shared deployment). The sign-in page also offers a one-click demo session.

---

## Data-handling and security model

- **Server-enforced RBAC.** Every endpoint declares the permission it requires; the browser
  only hides controls it knows will be refused.
- **scrypt password hashing** with per-user salts; signed HS256 session cookies (HTTP-only,
  SameSite=Lax, Secure behind HTTPS) and a CSRF token on mutating requests.
- **Rate limiting** on sign-in and demo sign-in, with audit records for refusals.
- **Security headers** on every response (nosniff, frame denial, referrer policy, permissions
  policy, cross-origin opener policy).
- **Uploads are validated server-side**, hashed with SHA-256 and size-limited; previews are
  discarded without persisting flows.
- **External enrichment is disabled by default.** It requires both
  `SENTINEL_ALLOW_EXTERNAL_ENRICHMENT=true` and a per-provider enable, after change approval.
  Only public IP addresses and bare hostnames are eligible; private, loopback, link-local and
  documentation ranges are rejected locally.
- **Credentials never reach the browser or logs.** Provider configuration surfaces only the
  environment-variable names and a present/missing indicator.
- **No payload decryption.** TLS/QUIC analysis uses observable handshake metadata only.
- **No active actions.** Investigation updates records inside the platform; nothing is
  blocked, isolated or reconfigured.
- **Utc everywhere.** All persisted timestamps and API responses are UTC.

---

## Project layout

```
backend/
  app/
    api/             HTTP routers (auth, dashboard, monitoring, ingestion, replay, alerts,
                     detections, ai, intelligence, reports, admin, meta)
    detectors.py     Six behavioural detection modules with evidence builders
    ml.py            Feature sets, training, calibration, evaluation, scoring
    parsing.py       PCAP/PCAPNG, CSV/TSV, JSON/JSONL and Zeek parsers + quality report
    pipeline.py      Ingestion -> features -> detection -> alert persistence
    intelligence*.py Threat-intel providers, policy guards and offline snapshots
    reports.py       Server-side report aggregation and exports
    pdf_report.py    Minimal PDF writer (no external rendering dependency)
    demo.py          Synthetic scenario generator
    replay_engine.py Isolated replay sessions
    models.py        25 SQLAlchemy entities
    security.py      scrypt, JWT sessions, CSRF, rate limiter, severity mapping
  data/              SQLite database, uploads, generated artefacts (git-ignored)
  models/            Trained model artefacts and evaluation records
frontend/
  src/pages/         Landing, Login, Overview, Monitoring, Ingestion, Replay, Alerts,
                     AlertDetail, Detections, DetectionWorkspace, AiCentre, Intelligence,
                     Reports, Admin
  src/components/    Design system, app shell, charts, globe, topology
  src/lib/           API client, types, formatting, event stream
docs/                Architecture, methodology and operations documentation
docker-compose.yml
.env.example
```

---

## Configuration

All settings are environment variables; see [`.env.example`](.env.example) for the full list.
Copy it to `.env` at the repository root for local runs — the API loads that file at startup,
and explicitly exported variables take precedence. The most important ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SENTINEL_SECRET_KEY` | dev-persisted | Session signing key. **Required in production.** |
| `SENTINEL_DATABASE_URL` | SQLite in `backend/data` | Database connection. |
| `SENTINEL_ALLOWED_ORIGINS` | `localhost:5173` | CORS allowlist. |
| `SENTINEL_DEMO_ENABLED` | `true` | Seed and expose demo data and demo sign-in. |
| `SENTINEL_ALLOW_EXTERNAL_ENRICHMENT` | `false` | Master switch for outbound intel lookups. |
| `SENTINEL_MAX_UPLOAD_MB` | `50` | Upload size ceiling. |
| `SENTINEL_DEMO_PASSWORD` | `Sentinel!Demo2026` | Seeded account password. |

---

## Documentation

- [Architecture](docs/architecture.md)
- [Detection methodology](docs/detection-methodology.md)
- [Feature engineering](docs/feature-engineering.md)
- [Data sources and ingestion](docs/data-sources.md)
- [API integrations](docs/api-integrations.md)
- [Deployment](docs/deployment.md)
- [Benchmark results](docs/benchmark-results.md)
- [Limitations](docs/limitations.md)

---

## Known limitations

- Model metrics are measured on the labelled synthetic corpus shipped with the platform and
  are engineering benchmarks, not production accuracy claims.
- Behavioural detectors require sufficient observation windows; the UI reports coverage gaps
  instead of estimating.
- IP geolocation approximates network registration, not physical device location.
- External enrichment is disabled by default and is not required for any core workflow.
- The PDF export uses a small built-in writer and is intentionally plain.

See [docs/limitations.md](docs/limitations.md) for the full list.
