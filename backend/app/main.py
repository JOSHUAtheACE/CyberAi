from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import HTTPConnection

from . import __version__
from .config import settings
from .database import session_scope
from .deps import get_session_payload
from .models import User
from .security import decode_session_token, rate_limiter
from .seed import seed_database
from .streaming import bus

from .api import admin, ai, alerts, auth, dashboard, detections, ingestion, intelligence_api, meta, monitoring, replay, reports_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sentinel")

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_EXEMPT = {
    f"{settings.api_prefix}/auth/login",
    f"{settings.api_prefix}/auth/demo-login",
    f"{settings.api_prefix}/feed/ingest",
    f"{settings.api_prefix}/feed/heartbeat",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from .database import init_db

    init_db()
    if os.environ.get("SENTINEL_SKIP_SEED", "").strip().lower() not in {"1", "true", "yes"}:
        try:
            with session_scope() as db:
                summary = seed_database(db)
            logger.info("initial seed complete: %s", summary)
        except Exception:  # noqa: BLE001
            logger.exception("Database seed failed; API will start in degraded state")
    yield


app = FastAPI(
    title="SENTINEL AI",
    description=(
        "Passive network threat intelligence and monitoring platform. "
        "All detections are evidence-backed and confined to the monitored workspace."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-Collector-Id", "X-Collector-Key", "Authorization"],
    expose_headers=["Content-Disposition"],
    max_age=600,
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _is_docs(path: str) -> bool:
    return path in {"/docs", "/redoc", "/openapi.json"} or path.startswith(("/docs/", "/redoc/"))


@app.middleware("http")
async def platform_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(settings.api_prefix) and path not in {f"{settings.api_prefix}/health"}:
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(f"http:{client_ip}", limit=900, window_seconds=60):
            return JSONResponse(status_code=429, content={"detail": "Request rate limit exceeded"})

    if (
        request.method in MUTATING
        and path.startswith(settings.api_prefix)
        and path not in CSRF_EXEMPT
    ):
        token = request.cookies.get(settings.cookie_name)
        if token:
            try:
                payload = decode_session_token(token)
            except Exception:  # noqa: BLE001
                return JSONResponse(status_code=401, content={"detail": "Session expired or invalid"})
            from .security import require_csrf

            try:
                require_csrf(request, payload)
            except Exception as exc:  # noqa: BLE001
                detail = getattr(exc, "detail", "CSRF validation failed")
                return JSONResponse(status_code=403, content={"detail": detail})

    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    if not path.startswith("/assets"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self' ws: wss:; font-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
    if path.startswith(settings.api_prefix):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


for api_router in (
    auth.router,
    meta.router,
    dashboard.router,
    monitoring.router,
    ingestion.router,
    replay.router,
    alerts.router,
    detections.router,
    ai.router,
    reports_api.router,
    intelligence_api.router,
    admin.router,
):
    app.include_router(api_router, prefix=settings.api_prefix)


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    token = websocket.cookies.get(settings.cookie_name)
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = decode_session_token(token)
    except Exception:  # noqa: BLE001
        await websocket.close(code=4401)
        return
    from .database import SessionLocal

    db = SessionLocal()
    try:
        user = db.get(User, int(payload.get("sub", 0)))
        if not user or not user.is_active:
            await websocket.close(code=4403)
            return
    finally:
        db.close()

    environment = (websocket.query_params.get("environment") or "LIVE").upper()[:16]
    await websocket.accept()
    subscriber = bus.subscribe(environment)
    await websocket.send_json(
        {
            "type": "connected",
            "environment": environment,
            "user": payload.get("email"),
            "server_time": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }
    )
    try:
        while True:
            try:
                event = await asyncio.wait_for(subscriber.queue.get(), timeout=20)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat", "environment": environment})
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(environment, subscriber)


if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
async def spa(full_path: str):
    if full_path.startswith(("api/", "ws/", "docs", "redoc", "openapi.json")):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    index = FRONTEND_DIST / "index.html"
    if not index.exists():
        return JSONResponse(
            status_code=200,
            content={
                "service": "SENTINEL AI API",
                "status": "frontend build not found",
                "docs": "/docs",
                "hint": "Run `npm run build` in frontend/ or use the Vite dev server on http://localhost:5173",
            },
        )
    candidate = FRONTEND_DIST / full_path
    if full_path and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(index)
