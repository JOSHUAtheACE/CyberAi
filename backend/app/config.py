from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_ROOT.parent / ".env")
load_dotenv(BACKEND_ROOT / ".env")

DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", BACKEND_ROOT / "data")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = Path(os.environ.get("SENTINEL_MODEL_DIR", BACKEND_ROOT / "models")).resolve()
DEMO_DIR = DATA_DIR / "demo"

for _d in (DATA_DIR, UPLOAD_DIR, MODEL_DIR / "trained", MODEL_DIR / "evaluation", DEMO_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _persisted_secret() -> str:
    """Development convenience: persist a generated secret so sessions survive restarts.

    Production deployments must provide SENTINEL_SECRET_KEY explicitly.
    """
    env_secret = os.environ.get("SENTINEL_SECRET_KEY")
    if env_secret:
        return env_secret
    secret_file = DATA_DIR / ".secret_key"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    secret_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass
    return value


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "SENTINEL AI"
    api_prefix: str = "/api/v1"
    secret_key: str = field(default_factory=_persisted_secret)
    access_token_ttl_minutes: int = int(os.environ.get("SENTINEL_TOKEN_TTL_MINUTES", "480"))
    cookie_name: str = "sentinel_session"
    csrf_cookie: str = "sentinel_csrf"
    cookie_secure: bool = _bool("SENTINEL_COOKIE_SECURE", False)
    cookie_samesite: str = os.environ.get("SENTINEL_COOKIE_SAMESITE", "lax")
    database_url: str = os.environ.get(
        "SENTINEL_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'sentinel.db').as_posix()}"
    )
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.environ.get(
            "SENTINEL_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if origin.strip()
    )
    max_upload_bytes: int = int(os.environ.get("SENTINEL_MAX_UPLOAD_MB", "50")) * 1024 * 1024
    max_preview_records: int = 25
    demo_mode_enabled: bool = _bool("SENTINEL_DEMO_ENABLED", True)
    external_enrichment_default: bool = _bool("SENTINEL_ALLOW_EXTERNAL_ENRICHMENT", False)
    llm_enabled: bool = _bool("SENTINEL_LLM_ENABLED", False)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


settings = Settings()

# Seed / demo account passwords. Override in production; documented in README.
DEMO_PASSWORD = os.environ.get("SENTINEL_DEMO_PASSWORD", "Sentinel!Demo2026")
ADMIN_EMAIL = os.environ.get("SENTINEL_ADMIN_EMAIL", "admin@sentinela.ai")
ADMIN_PASSWORD = os.environ.get("SENTINEL_ADMIN_PASSWORD", DEMO_PASSWORD)

# MaxMind credentials are read server-side only.
MAXMIND_ACCOUNT_ID = os.environ.get("MAXMIND_ACCOUNT_ID", "")
MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")
MAXMIND_DB_PATH = os.environ.get("MAXMIND_DB_PATH", "")
