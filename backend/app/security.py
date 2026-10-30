from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import Lock

from fastapi import HTTPException, Request, status

from .config import settings

# ---------------------------------------------------------------------------
# Password hashing (scrypt, memory-hard, stdlib only)
# ---------------------------------------------------------------------------

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Stateless signed sessions (JWT HS256)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_session_token(
    *, user_id: int, email: str, role: str, csrf_token: str, ttl_minutes: int | None = None
) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "csrf": csrf_token,
        "iat": now,
        "exp": now + (ttl_minutes or settings.access_token_ttl_minutes) * 60,
        "jti": secrets.token_urlsafe(12),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
    return ".".join(segments + [_b64url(signature)])


def decode_session_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            raise ValueError("signature mismatch")
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid"
        ) from exc


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def require_csrf(request: Request, payload: dict) -> None:
    supplied = request.headers.get("x-csrf-token", "")
    expected = payload.get("csrf", "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter (per process; use Redis in multi-node)
# ---------------------------------------------------------------------------


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


rate_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

PERMISSIONS: dict[str, str] = {
    "dashboard.view": "View operational dashboards",
    "monitoring.view": "View network monitoring and topology",
    "ingestion.view": "View ingestion jobs and sources",
    "ingestion.upload": "Upload captures and flow records",
    "sources.manage": "Configure approved traffic collectors",
    "replay.run": "Start and control traffic replays",
    "alerts.view": "View alerts",
    "alerts.investigate": "Acknowledge, annotate and triage alerts",
    "alerts.assign": "Assign alerts to analysts",
    "alerts.export": "Export alert evidence",
    "detections.view": "View threat detection workspaces",
    "ai.view": "View AI/ML model intelligence",
    "ai.evaluate": "Run authorised model evaluations",
    "ai.models.manage": "Manage model versions and thresholds",
    "reports.view": "View analytical reports",
    "reports.export": "Export reports",
    "intel.view": "View threat intelligence enrichment",
    "intel.manage": "Configure threat intelligence providers",
    "audit.view": "View audit logs",
    "settings.view": "View workspace settings",
    "users.manage": "Manage users and roles",
    "thresholds.manage": "Manage detection thresholds",
}

ROLE_DEFINITIONS: list[dict] = [
    {
        "code": "security_admin",
        "name": "Security Administrator",
        "description": "Full control of workspaces, users, integrations and detection policy.",
        "permissions": list(PERMISSIONS.keys()),
    },
    {
        "code": "soc_analyst",
        "name": "SOC Analyst",
        "description": "Investigates alerts, records findings and exports permitted reports.",
        "permissions": [
            "dashboard.view",
            "monitoring.view",
            "ingestion.view",
            "replay.run",
            "alerts.view",
            "alerts.investigate",
            "alerts.assign",
            "alerts.export",
            "detections.view",
            "reports.view",
            "reports.export",
            "intel.view",
            "ai.view",
            "settings.view",
        ],
    },
    {
        "code": "network_engineer",
        "name": "Network Security Engineer",
        "description": "Owns collectors, ingestion health and network traffic analytics.",
        "permissions": [
            "dashboard.view",
            "monitoring.view",
            "ingestion.view",
            "ingestion.upload",
            "sources.manage",
            "replay.run",
            "alerts.view",
            "detections.view",
            "reports.view",
            "intel.view",
            "settings.view",
        ],
    },
    {
        "code": "ml_engineer",
        "name": "ML Engineer",
        "description": "Inspects features, evaluates models and manages model versions.",
        "permissions": [
            "dashboard.view",
            "monitoring.view",
            "alerts.view",
            "detections.view",
            "ai.view",
            "ai.evaluate",
            "ai.models.manage",
            "reports.view",
            "settings.view",
        ],
    },
    {
        "code": "auditor",
        "name": "Auditor / Management",
        "description": "Reviews analytical summaries, audit records and approved reports.",
        "permissions": [
            "dashboard.view",
            "monitoring.view",
            "alerts.view",
            "detections.view",
            "ai.view",
            "reports.view",
            "audit.view",
            "settings.view",
        ],
    },
]

HIGH_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def severity_for_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.35:
        return "low"
    return "informational"


def api_key_fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str]:
    raw = "sk_collector_" + secrets.token_urlsafe(32)
    return raw, api_key_fingerprint(raw)
