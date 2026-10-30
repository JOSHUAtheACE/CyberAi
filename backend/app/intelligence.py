from __future__ import annotations

import ipaddress
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from . import geo
from .config import settings
from .models import EnrichmentResult, ProviderConfig, RuntimeSetting, ThreatIntelIndicator, utcnow
from .security import rate_limiter
from .text import plural

CACHE_TTL = timedelta(hours=24)
REQUEST_TIMEOUT = httpx.Timeout(10.0, connect=6.0)
USER_AGENT = "SentinelAI/1.0 (passive network intelligence platform)"


class ProviderError(RuntimeError):
    pass


def external_enrichment_allowed(db: Session) -> bool:
    row = db.get(RuntimeSetting, "external_enrichment")
    if row is not None:
        return bool((row.value or {}).get("enabled", False))
    return settings.external_enrichment_default


def _env_values(names: list[str]) -> dict[str, str]:
    return {name: os.environ.get(name, "") for name in names}


def _masked_status(config: ProviderConfig, allowed: bool) -> dict:
    values = _env_values(config.credential_env or [])
    configured = (
        all(bool(v) for v in values.values())
        if values
        else config.provider == "offline_snapshot"
    )
    return {
        "provider": config.provider,
        "display_name": config.display_name,
        "category": config.category,
        "docs_url": config.docs_url,
        "credential_env": config.credential_env,
        "credentials_present": {name: bool(value) for name, value in values.items()},
        "configured": configured,
        "enabled": config.enabled,
        "status": "NOT_CONFIGURED" if not configured else config.status,
        "last_success_at": config.last_success_at.isoformat() + "Z" if config.last_success_at else None,
        "last_error": config.last_error,
        "rate_limit": config.rate_limit,
        "attribution": config.attribution,
        "notes": config.notes,
        "external_requests_allowed": config.provider == "offline_snapshot" or allowed,
        "credential_values_exposed": False,
    }


def list_providers(db: Session) -> list[dict]:
    allowed = external_enrichment_allowed(db)
    return [_masked_status(c, allowed) for c in db.query(ProviderConfig).order_by(ProviderConfig.id).all()]


def _ensure_public_indicator(indicator: str) -> str:
    value = indicator.strip()
    if not value or len(value) > 255:
        raise ProviderError("Invalid indicator")
    try:
        address = ipaddress.ip_address(value)
        if not geo.is_public_ip(value):
            raise ProviderError(
                "Refused: private, reserved or loopback addresses are never sent to external providers."
            )
        return str(address)
    except ValueError:
        pass
    if any(ch.isspace() for ch in value) or "/" in value:
        raise ProviderError("Only public IP addresses and bare hostnames/domains are supported.")
    lowered = value.lower().rstrip(".")
    if "." not in lowered:
        raise ProviderError("Invalid domain indicator")
    return lowered


def _client() -> httpx.Client:
    return httpx.Client(timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=False)


def _provider_call(provider: str, indicator: str) -> dict:
    """Perform a narrowly scoped, read-only lookup for one public indicator."""
    if not rate_limiter.check(f"provider:{provider}", limit=25, window_seconds=60):
        raise ProviderError("Local provider rate limit reached; try again shortly.")
    if provider == "threatfox":
        key = os.environ.get("THREATFOX_AUTH_KEY", "")
        with _client() as client:
            response = client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                headers={"Auth-Key": key},
                json={"query": "search_ioc", "search_term": indicator},
            )
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") not in {"ok", "no_result"}:
            raise ProviderError(f"ThreatFox query failed ({payload.get('query_status')})")
        entries = payload.get("data") or []
        if isinstance(entries, dict):
            entries = [entries]
        top = entries[:5] if entries else []
        return {
            "verdict": "listed" if top else "no_match",
            "confidence": max((int(e.get("confidence_level", 0) or 0) for e in top), default=0) or None,
            "first_seen": _safe_iso(top[0].get("first_seen")) if top else None,
            "last_seen": _safe_iso(top[0].get("last_seen")) if top else None,
            "source_url": "https://threatfox.abuse.ch/browse/",
            "summary": (
                f"{len(top)} public IOC {plural(len(top), 'record')} reference this indicator."
                if top
                else "No public IOC records matched this indicator at query time."
            ),
            "raw": {"query_status": payload.get("query_status"), "matches": top},
        }
    if provider == "urlhaus":
        key = os.environ.get("URLHAUS_AUTH_KEY", "")
        with _client() as client:
            response = client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers={"Auth-Key": key},
                data={"host": indicator},
            )
        response.raise_for_status()
        payload = response.json()
        status = payload.get("query_status")
        urls = payload.get("urls") or []
        return {
            "verdict": "listed" if status == "ok" else "no_match",
            "confidence": None,
            "first_seen": _safe_iso(payload.get("firstseen")) if status == "ok" else None,
            "last_seen": _safe_iso(payload.get("lastseen")) if status == "ok" else None,
            "source_url": "https://urlhaus.abuse.ch/",
            "summary": (
                f"URLhaus returned {len(urls)} associated malware {plural(len(urls), 'URL')}."
                if status == "ok"
                else "No URLhaus host record matched this indicator."
            ),
            "raw": {"query_status": status, "url_count": len(urls), "urls": urls[:5]},
        }
    if provider == "abuseipdb":
        key = os.environ.get("ABUSEIPDB_API_KEY", "")
        with _client() as client:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
            )
        response.raise_for_status()
        data = (response.json() or {}).get("data", {})
        score = data.get("abuseConfidenceScore")
        return {
            "verdict": "abusive" if (score or 0) >= 50 else "low_reporting",
            "confidence": score,
            "first_seen": None,
            "last_seen": _safe_iso(data.get("lastReportedAt")),
            "source_url": f"https://www.abuseipdb.com/check/{indicator}",
            "summary": (
                f"AbuseIPDB confidence {score if score is not None else 'n/a'}% across "
                f"{data.get('totalReports', 0)} {plural(int(data.get('totalReports', 0) or 0), 'report')} in 90 days."
            ),
            "raw": {
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "usageType": data.get("usageType"),
                "totalReports": data.get("totalReports"),
            },
        }
    if provider == "greynoise":
        key = os.environ.get("GREYNOISE_API_KEY", "")
        with _client() as client:
            response = client.get(
                f"https://api.greynoise.io/v3/community/{indicator}",
                headers={"key": key, "Accept": "application/json"},
            )
        if response.status_code == 404:
            return {
                "verdict": "no_match",
                "confidence": None,
                "source_url": "https://viz.greynoise.io/",
                "summary": "GreyNoise has no observation for this indicator.",
                "raw": {},
            }
        response.raise_for_status()
        data = response.json()
        return {
            "verdict": data.get("classification") or "unknown",
            "confidence": None,
            "last_seen": _safe_iso(data.get("last_seen")),
            "source_url": f"https://viz.greynoise.io/ip/{indicator}",
            "summary": (
                f"GreyNoise classification: {data.get('classification', 'unknown')}; "
                f"noise={data.get('noise')}, riot={data.get('riot')}."
            ),
            "raw": {"name": data.get("name"), "link": data.get("link")},
        }
    if provider == "maxmind":
        info = geo.geo_status()
        if not info["configured"]:
            raise ProviderError("MaxMind database is not available locally.")
        result = geo.lookup_geo(indicator)
        if not result:
            return {
                "verdict": "no_match",
                "confidence": None,
                "source_url": "https://www.maxmind.com/",
                "summary": "No geolocation record was found for this indicator.",
                "raw": {},
            }
        return {
            "verdict": "located",
            "confidence": None,
            "source_url": "https://www.maxmind.com/",
            "summary": (
                f"GeoLite2: {result.get('city') or 'unknown city'}, {result.get('country') or 'unknown country'}. "
                "Coordinates approximate network registration, not device location."
            ),
            "raw": result,
        }
    raise ProviderError("Unknown provider")


def _safe_iso(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def test_provider(db: Session, config: ProviderConfig) -> dict:
    if not config.configured:
        raise ProviderError("Provider is not configured. Supply credentials server-side first.")
    started = time.perf_counter()
    if config.provider == "offline_snapshot":
        count = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.provider == "offline_snapshot").count()
        config.last_success_at = utcnow()
        config.status = "READY"
        config.last_error = None
        db.commit()
        return {
            "ok": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "message": f"Offline snapshot contains {count} imported {plural(count, 'indicator')}.",
        }
    indicator = os.environ.get("SENTINEL_TEST_INDICATOR", "8.8.8.8")
    try:
        result = _provider_call(config.provider, indicator)
    except Exception as exc:  # noqa: BLE001
        message = _safe_error(exc)
        config.status = "ERROR"
        config.last_error = message
        db.commit()
        raise ProviderError(message) from exc
    config.last_success_at = utcnow()
    config.status = "READY"
    config.last_error = None
    db.add(
        EnrichmentResult(
            provider=config.provider,
            indicator=indicator,
            status="TEST_OK",
            payload=result,
        )
    )
    db.commit()
    return {
        "ok": True,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "message": "Connection succeeded with a narrowly scoped test lookup.",
        "result": {
            "verdict": result.get("verdict"),
            "summary": result.get("summary"),
            "attribution": config.attribution,
        },
    }


def _safe_error(exc: Exception) -> str:
    text = str(exc)
    for name in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY"):
        value = os.environ.get(name, "")
        if value:
            text = text.replace(value, "[redacted]")
    if len(text) > 300:
        text = text[:300] + "…"
    return text or exc.__class__.__name__


def lookup(db: Session, config: ProviderConfig, *, indicator: str, alert_id: int | None = None) -> dict:
    if not config.enabled:
        raise ProviderError(
            "External enrichment is disabled for this provider. An administrator must approve it in Settings."
        )
    if config.provider != "offline_snapshot" and not external_enrichment_allowed(db):
        raise ProviderError(
            "External enrichment is globally disabled. A Security Administrator must enable it in "
            "Settings after deployment approval, or use the offline snapshot provider."
        )
    value = indicator if config.provider == "offline_snapshot" else _ensure_public_indicator(indicator)
    if config.provider == "offline_snapshot":
        cached = (
            db.query(ThreatIntelIndicator)
            .filter(
                ThreatIntelIndicator.provider == "offline_snapshot",
                ThreatIntelIndicator.indicator == value,
            )
            .first()
        )
        if not cached:
            return {"cached": False, "found": False, "indicator": value, "provider": "offline_snapshot"}
        return {
            "cached": True,
            "found": True,
            "indicator": value,
            "provider": "offline_snapshot",
            "verdict": cached.verdict,
            "confidence": cached.confidence,
            "source_url": cached.source_url,
            "licence": cached.licence,
            "retrieved_at": cached.retrieved_at.isoformat() + "Z",
            "valid_until": cached.valid_until.isoformat() + "Z" if cached.valid_until else None,
        }

    cache = (
        db.query(EnrichmentResult)
        .filter(
            EnrichmentResult.provider == config.provider,
            EnrichmentResult.indicator == value,
            EnrichmentResult.status == "OK",
            EnrichmentResult.retrieved_at >= utcnow() - CACHE_TTL,
        )
        .order_by(EnrichmentResult.retrieved_at.desc())
        .first()
    )
    if cache:
        return {
            "cached": True,
            "found": True,
            "indicator": value,
            "provider": config.provider,
            "attribution": config.attribution,
            "retrieved_at": cache.retrieved_at.isoformat() + "Z",
            "valid_until": (cache.retrieved_at + CACHE_TTL).isoformat() + "Z",
            "result": cache.payload,
        }

    started = time.perf_counter()
    try:
        result = _provider_call(config.provider, value)
    except Exception as exc:  # noqa: BLE001
        message = _safe_error(exc)
        db.add(
            EnrichmentResult(
                provider=config.provider,
                indicator=value,
                alert_id=alert_id,
                status="ERROR",
                error=message,
            )
        )
        config.status = "ERROR"
        config.last_error = message
        db.commit()
        raise ProviderError(message) from exc

    retrieved = utcnow()
    db.add(
        EnrichmentResult(
            provider=config.provider,
            indicator=value,
            alert_id=alert_id,
            status="OK",
            payload=result,
        )
    )
    if result.get("verdict") not in (None, "no_match"):
        db.add(
            ThreatIntelIndicator(
                provider=config.provider,
                indicator=value,
                indicator_type="ip" if _looks_like_ip(value) else "domain",
                verdict=result.get("verdict"),
                confidence=result.get("confidence"),
                first_seen=_parse_dt(result.get("first_seen")),
                last_seen=_parse_dt(result.get("last_seen")),
                source_url=result.get("source_url"),
                licence=config.attribution,
                retrieved_at=retrieved,
                valid_until=retrieved + CACHE_TTL,
                raw=result.get("raw") or {},
            )
        )
    config.last_success_at = retrieved
    config.status = "READY"
    config.last_error = None
    db.commit()
    return {
        "cached": False,
        "found": True,
        "indicator": value,
        "provider": config.provider,
        "attribution": config.attribution,
        "confidence_type": "provider_reported",
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "retrieved_at": retrieved.isoformat() + "Z",
        "valid_until": (retrieved + CACHE_TTL).isoformat() + "Z",
        "result": result,
        "context_notice": (
            "External threat intelligence is contextual evidence, not conclusive proof of malicious behaviour."
        ),
    }


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def import_snapshot(db: Session, entries: list[dict], metadata: dict) -> dict:
    """Import locally vetted indicators for air-gapped deployments."""
    imported = 0
    rejected = 0
    for entry in entries:
        indicator = str(entry.get("indicator", "")).strip()
        if not indicator or len(indicator) > 255:
            rejected += 1
            continue
        valid_until = _parse_dt(entry.get("valid_until"))
        db.add(
            ThreatIntelIndicator(
                provider="offline_snapshot",
                indicator=indicator,
                indicator_type=str(entry.get("type", "ip"))[:24],
                verdict=str(entry.get("verdict", "listed"))[:64],
                confidence=int(entry["confidence"]) if entry.get("confidence") is not None else None,
                first_seen=_parse_dt(entry.get("first_seen")),
                last_seen=_parse_dt(entry.get("last_seen")),
                source_url=str(entry.get("source_url", ""))[:512] or None,
                licence=str(metadata.get("licence", ""))[:160] or None,
                retrieved_at=utcnow(),
                valid_until=valid_until,
                raw={"import_metadata": metadata, "entry": entry},
            )
        )
        imported += 1
    db.commit()
    return {
        "imported": imported,
        "rejected": rejected,
        "source": metadata.get("source"),
        "licence": metadata.get("licence"),
        "retrieved_at": utcnow().isoformat() + "Z",
    }
