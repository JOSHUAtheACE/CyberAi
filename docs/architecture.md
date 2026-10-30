# Architecture

SENTINEL AI is a single-deployable, full-stack application. One FastAPI process can serve the
JSON API, the WebSocket stream and the built React SPA; during development Vite serves the SPA
and proxies `/api` and `/ws` to the backend.

```
Browser (React 19)
  │  HTTPS  /api/v1/*        JSON over fetch, HTTP-only session cookie + CSRF header
  │  WSS    /ws/events       server-pushed events, per-environment subscription
  ▼
FastAPI application
  ├── platform middleware   security headers, CSRF, rate limiting, audit hooks
  ├── routers (api/v1)      auth, dashboard, monitoring, ingestion, replay, alerts,
  │                         detections, ai, intelligence, reports, admin, meta
  ├── services              parsing, pipeline, detectors, ml, intelligence, reports,
  │                         replay_engine, pdf_report, geo
  ├── event bus             fan-out to WebSocket subscribers (bounded queues)
  └── SQLAlchemy 2.x        SQLite (WAL) by default; PostgreSQL-compatible URL supported
```

## Request lifecycle

1. `platform_middleware` attaches security headers, validates the CSRF token on mutating
   requests (except the explicitly exempt sign-in and collector endpoints), and applies the
   per-IP rate limiter to sign-in paths.
2. Dependencies decode the signed session cookie, load the user, and check the permission the
   endpoint declares. The browser never decides authorisation; it only hides controls.
3. Routers resolve the workspace (`live-ops`, `demo`, `replay-lab`) and query **only** that
   workspace's environment, so demo, replay and live telemetry can never mix.
4. Responses are UTC ISO-8601 timestamps plus values computed at request time from stored
   records.

## Data model (25 entities)

| Group | Entities |
| --- | --- |
| Identity | `roles`, `users`, `audit_logs` |
| Tenancy | `workspaces`, `runtime_settings`, `system_events` |
| Ingest | `traffic_sources`, `ingestion_jobs`, `capture_files`, `flow_records` |
| Features & models | `feature_observations`, `detection_modules`, `model_versions`, `model_evaluations` |
| Alerts | `security_alerts`, `alert_evidence`, `alert_links` |
| Investigation | `investigation_cases`, `investigation_notes` |
| Intelligence | `threat_intel_indicators`, `enrichment_results`, `provider_configs` |
| Output | `generated_reports`, `replay_sessions`, `demo_datasets` |

`flow_records` is the analytical base. Each row stores endpoint addresses and ports, protocol,
byte and packet counters (directional where supplied), start/end timestamps, application
protocol, and optional DNS/TLS metadata. `security_alerts` references the flows it was derived
from; `alert_evidence` stores the exact feature values that triggered it.

## Ingestion pipeline

```
upload / collector push
  → format detection & parsing (parsing.py)          validates rows, reports quality
  → normalised FlowIn records
  → persistence with environment + workspace tag
  → feature extraction per detector (pipeline.py)
  → six detectors + optional model scoring
  → deduplication with recurrence counters
  → alert + evidence persistence
  → event bus publish (WebSocket) + audit records
```

Parsing is shared between preview and ingestion, so a successful preview is not a different
code path from the real job. Preview samples at most 20 000 rows/packets and never persists
flows.

## Real-time delivery

`EventBus` keeps a set of per-environment subscribers. Producers run in worker threads and
schedule delivery onto each subscriber's event loop with `call_soon_threadsafe`. Queues are
bounded; on overflow the oldest event is dropped rather than blocking ingestion. The browser
shows `stream live`, `connecting` or `stream offline` based on the socket state and falls back
to polling intervals on queries.

## Frontend structure

- React Router with a protected `/app/*` shell. Navigation items are filtered by permission.
- TanStack Query for all server state; ranges come from a shared workspace context.
- ECharts for charts, Cytoscape for topology, globe.gl/three for the landing and overview
  globes. Heavy libraries are split into separate chunks.
- A token-based design system (`components/ui`) for panels, badges, tabs, toggles, tables,
  empty/error states and info hints. Reduced-motion and non-WebGL fallbacks are provided.

## Deployment shape

- **Development:** Vite on 5173, uvicorn on 8000 with `--reload`.
- **Production:** `npm run build` then run uvicorn; FastAPI mounts `frontend/dist/assets` and
  serves `index.html` for non-API paths.
- **Container:** multi-stage Dockerfile builds the SPA, copies it into the Python image and
  runs as a non-root user with `/data` and `/models` volumes.

See [deployment.md](deployment.md) for the operational details.

## Design constraints encoded in the architecture

- No fabricated data: endpoints return stored values or explicit `null`/empty states.
- Demo and replay workspaces are separate rows scoped by environment.
- External enrichment is a server-side policy decision gated by configuration and per-provider
  toggles, not a client feature flag.
- Detector score semantics are stored with each detector and rendered next to every alert, so
  a heuristic score is never displayed as a probability.
- Investigation endpoints mutate platform records only; there is no network-control API.
