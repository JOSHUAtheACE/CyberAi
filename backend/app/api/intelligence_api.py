from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .. import intelligence
from ..database import get_db
from ..deps import record_audit, require_permissions
from ..geo import is_public_ip
from ..models import (
    EnrichmentResult,
    ProviderConfig,
    SecurityAlert,
    ThreatIntelIndicator,
    User,
    utcnow,
)
from ..serializers import iso

router = APIRouter(prefix="/intel", tags=["Threat intelligence"])


def _provider(db: Session, provider: str) -> ProviderConfig:
    config = db.query(ProviderConfig).filter(ProviderConfig.provider == provider).first()
    if not config:
        raise HTTPException(status_code=404, detail="Unknown intelligence provider")
    return config


@router.get("/providers")
def providers(
    user: User = Depends(require_permissions("intel.view")),
    db: Session = Depends(get_db),
):
    allowed = intelligence.external_enrichment_allowed(db)
    indicator_count = db.query(func.count(ThreatIntelIndicator.id)).scalar() or 0
    enrichment_count = db.query(func.count(EnrichmentResult.id)).scalar() or 0
    return {
        "providers": intelligence.list_providers(db),
        "external_enrichment_allowed": allowed,
        "policy": {
            "headline": "External enrichment is disabled by default and requires explicit approval.",
            "rules": [
                "Only public IP addresses and bare hostnames are eligible for external lookup.",
                "Private, loopback, link-local and documentation addresses never leave the platform.",
                "Captures, flow records, internal hostnames and analyst notes are never sent externally.",
                "All requests are read-only lookups; no provider receives monitoring telemetry.",
                "Offline snapshot import supports air-gapped deployments without external requests.",
            ],
            "enable_via": "Set SENTINEL_ALLOW_EXTERNAL_ENRICHMENT=true in the server environment after change approval, then enable providers here.",
        },
        "cache": {
            "indicators": indicator_count,
            "enrichment_results": enrichment_count,
            "ttl_hours": 24,
        },
    }


class ProviderUpdate(BaseModel):
    enabled: bool


@router.patch("/providers/{provider}")
def update_provider(
    provider: str,
    payload: ProviderUpdate,
    user: User = Depends(require_permissions("intel.manage")),
    db: Session = Depends(get_db),
):
    config = _provider(db, provider)
    status = intelligence._masked_status(config, intelligence.external_enrichment_allowed(db))
    if payload.enabled and not status["configured"]:
        raise HTTPException(
            status_code=409,
            detail="Provider credentials are not present in the server environment.",
        )
    config.enabled = payload.enabled
    config.status = "READY" if payload.enabled else "DISABLED"
    if not payload.enabled:
        config.last_error = None
    record_audit(
        db,
        actor=user,
        action="intel.provider_updated",
        resource_type="provider_config",
        resource_id=config.provider,
        meta={"enabled": payload.enabled},
    )
    db.commit()
    return intelligence._masked_status(config, intelligence.external_enrichment_allowed(db))


@router.post("/providers/{provider}/test")
def test_provider(
    provider: str,
    user: User = Depends(require_permissions("intel.manage")),
    db: Session = Depends(get_db),
):
    config = _provider(db, provider)
    status = intelligence._masked_status(config, intelligence.external_enrichment_allowed(db))
    if not status["configured"]:
        raise HTTPException(status_code=409, detail="Provider is not configured on this server.")
    if not status["external_requests_allowed"]:
        raise HTTPException(
            status_code=409,
            detail="External enrichment is globally disabled by deployment policy.",
        )
    try:
        return intelligence.test_provider(db, config)
    except intelligence.ProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=255)
    provider: str | None = None
    alert_id: int | None = None


@router.post("/lookup")
def lookup_indicator(
    payload: LookupRequest,
    user: User = Depends(require_permissions("intel.view")),
    db: Session = Depends(get_db),
):
    if payload.alert_id and not db.get(SecurityAlert, payload.alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    configs = (
        [_provider(db, payload.provider)]
        if payload.provider
        else db.query(ProviderConfig)
        .filter(ProviderConfig.enabled.is_(True))
        .order_by(ProviderConfig.id)
        .all()
    )
    if not configs:
        raise HTTPException(status_code=409, detail="No intelligence provider is enabled.")
    results = []
    errors = []
    for config in configs:
        try:
            results.append(intelligence.lookup(db, config, indicator=payload.indicator, alert_id=payload.alert_id))
        except intelligence.ProviderError as exc:
            errors.append({"provider": config.provider, "error": str(exc)})
    if not results:
        raise HTTPException(status_code=422, detail=errors[0]["error"] if errors else "Lookup failed")
    record_audit(
        db,
        actor=user,
        action="intel.lookup",
        resource_type="indicator",
        resource_id=payload.indicator[:64],
        meta={"providers": [r.get("provider") for r in results], "alert_id": payload.alert_id},
    )
    db.commit()
    return {
        "indicator": payload.indicator,
        "results": results,
        "errors": errors,
        "context_notice": (
            "External intelligence is contextual evidence only. A listing does not confirm compromise "
            "or attribution for this environment."
        ),
    }


@router.post("/alerts/{alert_id}/enrich")
def enrich_alert(
    alert_id: int,
    user: User = Depends(require_permissions("intel.view")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    candidates = []
    for value in [alert.source_ip, alert.dest_ip]:
        if value and value not in candidates:
            candidates.append(value)
    public = [value for value in candidates if is_public_ip(value)]
    skipped = [
        {"indicator": value, "reason": "private, reserved or non-public address"}
        for value in candidates
        if value not in public
    ]
    configs = (
        db.query(ProviderConfig)
        .filter(ProviderConfig.enabled.is_(True), ProviderConfig.status != "NOT_CONFIGURED")
        .order_by(ProviderConfig.id)
        .all()
    )
    if not configs:
        return {
            "alert_id": alert.id,
            "results": [],
            "skipped": skipped,
            "errors": [
                {
                    "provider": None,
                    "error": "No approved intelligence provider is enabled for this deployment.",
                }
            ],
            "note": "No external request was made.",
        }
    results = []
    errors = []
    for config in configs:
        for indicator in public:
            try:
                payload = intelligence.lookup(db, config, indicator=indicator, alert_id=alert.id)
                results.append({"indicator": indicator, "provider": config.provider, **payload})
            except intelligence.ProviderError as exc:
                errors.append({"provider": config.provider, "indicator": indicator, "error": str(exc)})
    record_audit(
        db,
        actor=user,
        action="intel.alert_enriched",
        resource_type="security_alert",
        resource_id=alert.id,
        meta={"providers": [c.provider for c in configs], "indicators": public},
    )
    db.commit()
    return {
        "alert_id": alert.id,
        "results": results,
        "skipped": skipped,
        "errors": errors,
        "note": "Only public indicators were queried. Internal addresses never leave the platform.",
    }


@router.get("/indicators")
def indicators(
    q: str | None = Query(None, max_length=120),
    provider: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(require_permissions("intel.view")),
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIntelIndicator)
    if provider:
        query = query.filter(ThreatIntelIndicator.provider == provider)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                ThreatIntelIndicator.indicator.ilike(like),
                ThreatIntelIndicator.verdict.ilike(like),
            )
        )
    total = query.count()
    rows = (
        query.order_by(ThreatIntelIndicator.retrieved_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "provider": row.provider,
                "indicator": row.indicator,
                "type": row.indicator_type,
                "verdict": row.verdict,
                "confidence": row.confidence,
                "first_seen": iso(row.first_seen),
                "last_seen": iso(row.last_seen),
                "source_url": row.source_url,
                "licence": row.licence,
                "retrieved_at": iso(row.retrieved_at),
                "valid_until": iso(row.valid_until),
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/enrichment")
def enrichment_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permissions("intel.view")),
    db: Session = Depends(get_db),
):
    query = db.query(EnrichmentResult)
    total = query.count()
    rows = (
        query.order_by(EnrichmentResult.retrieved_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "provider": row.provider,
                "indicator": row.indicator,
                "status": row.status,
                "cached": row.cached,
                "alert_id": row.alert_id,
                "error": row.error,
                "retrieved_at": iso(row.retrieved_at),
                "summary": (row.payload or {}).get("summary"),
                "verdict": (row.payload or {}).get("verdict"),
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


class SnapshotRequest(BaseModel):
    metadata: dict = Field(default_factory=dict)
    entries: list[dict] = Field(min_length=1, max_length=10000)


@router.post("/snapshot")
def import_snapshot(
    payload: SnapshotRequest,
    user: User = Depends(require_permissions("intel.manage")),
    db: Session = Depends(get_db),
):
    if len(payload.entries) > 10000:
        raise HTTPException(status_code=413, detail="Snapshot exceeds the 10,000 indicator limit")
    result = intelligence.import_snapshot(db, payload.entries, payload.metadata)
    record_audit(
        db,
        actor=user,
        action="intel.snapshot_imported",
        resource_type="threat_intel_indicator",
        resource_id=payload.metadata.get("source", "offline")[:64],
        meta={"imported": result.get("imported"), "rejected": result.get("rejected")},
    )
    db.commit()
    return result
