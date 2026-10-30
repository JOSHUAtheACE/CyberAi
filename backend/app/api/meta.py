from __future__ import annotations

import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..geo import geo_status
from ..models import (
    DetectionModule,
    FlowRecord,
    GeneratedReport,
    IngestionJob,
    SecurityAlert,
    SystemEvent,
    User,
    Workspace,
    utcnow,
)
from ..serializers import iso

router = APIRouter(tags=["Platform"])


@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        database = "error"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": "sentinel-ai-api",
        "version": "1.0.0",
        "database": database,
        "time": iso(utcnow()),
        "demo_enabled": settings.demo_mode_enabled,
    }


@router.get("/workspaces")
def workspaces(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Workspace).order_by(Workspace.id).all()
    return [
        {
            "id": ws.id,
            "slug": ws.slug,
            "name": ws.name,
            "environment": ws.environment,
            "description": ws.description,
            "internal_cidrs": ws.internal_cidrs,
        }
        for ws in rows
    ]


@router.get("/system/events")
def system_events(
    limit: int = Query(20, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(SystemEvent).order_by(SystemEvent.ts.desc(), SystemEvent.id.desc()).limit(limit).all()
    return [
        {
            "id": row.id,
            "ts": iso(row.ts),
            "level": row.level,
            "category": row.category,
            "message": row.message,
            "meta": row.meta,
        }
        for row in rows
    ]


@router.get("/system/status")
def system_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    modules = db.query(DetectionModule).filter(DetectionModule.enabled.is_(True)).count()
    last_flow = db.query(FlowRecord).order_by(FlowRecord.ts.desc()).first()
    return {
        "active_detectors": modules,
        "last_flow_at": iso(last_flow.ts) if last_flow else None,
        "geo": geo_status(),
        "external_enrichment": bool(os.environ.get("SENTINEL_ALLOW_EXTERNAL_ENRICHMENT", "")),
        "llm_enabled": settings.llm_enabled,
        "retention_days": 90,
        "storage": {
            "upload_limit_mb": settings.max_upload_bytes // (1024 * 1024),
            "mode": "controlled local file storage",
        },
    }


@router.get("/search")
def global_search(
    q: str = Query(min_length=2, max_length=120),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    term = q.strip()
    like = f"%{term}%"
    results: list[dict] = []

    alerts = (
        db.query(SecurityAlert)
        .filter(or_(SecurityAlert.alert_code.ilike(like), SecurityAlert.source_ip.ilike(like),
                    SecurityAlert.dest_ip.ilike(like), SecurityAlert.threat_class.ilike(like)))
        .order_by(SecurityAlert.first_seen.desc())
        .limit(6)
        .all()
    )
    for alert in alerts:
        results.append({
            "type": "alert",
            "id": alert.id,
            "title": f"{alert.alert_code} · {alert.threat_class.replace('_', ' ')}",
            "subtitle": f"{alert.source_ip} → {alert.dest_ip} · {alert.severity}",
            "href": f"/app/alerts/{alert.id}",
        })

    flows = (
        db.query(FlowRecord)
        .filter(or_(FlowRecord.reference.ilike(like), FlowRecord.src_ip.ilike(like), FlowRecord.dst_ip.ilike(like),
                    FlowRecord.dns_query.ilike(like), FlowRecord.tls_sni.ilike(like)))
        .order_by(FlowRecord.ts.desc())
        .limit(4)
        .all()
    )
    for flow in flows:
        results.append({
            "type": "flow",
            "id": flow.id,
            "title": f"{flow.reference} · {flow.protocol} {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}",
            "subtitle": iso(flow.ts),
            "href": f"/app/monitoring?flow={flow.id}",
        })

    jobs = db.query(IngestionJob).filter(or_(IngestionJob.reference.ilike(like), IngestionJob.original_filename.ilike(like))).limit(3).all()
    for job in jobs:
        results.append({
            "type": "ingestion",
            "id": job.id,
            "title": f"{job.reference} · {job.original_filename or job.kind}",
            "subtitle": f"{job.status} · {job.records_valid:,} records",
            "href": "/app/sources",
        })

    modules = db.query(DetectionModule).filter(or_(DetectionModule.name.ilike(like), DetectionModule.code.ilike(like),
                                                  DetectionModule.threat_class.ilike(like))).limit(3).all()
    for module in modules:
        results.append({
            "type": "detector",
            "id": module.id,
            "title": module.name,
            "subtitle": module.technique,
            "href": "/app/ai",
        })

    reports = db.query(GeneratedReport).filter(GeneratedReport.title.ilike(like)).limit(3).all()
    for report in reports:
        results.append({
            "type": "report",
            "id": report.id,
            "title": report.title,
            "subtitle": report.reference,
            "href": "/app/reports",
        })
    return {"query": term, "results": results[:18]}


@router.get("/activity")
def activity(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    since = utcnow() - timedelta(hours=24)
    alerts = db.query(SecurityAlert).filter(SecurityAlert.first_seen >= since).count()
    flows = db.query(FlowRecord).filter(FlowRecord.ts >= since).count()
    critical = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.first_seen >= since, SecurityAlert.severity == "critical")
        .count()
    )
    return {
        "window": "24h",
        "alerts": alerts,
        "critical": critical,
        "flows": flows,
        "events": [
            {
                "ts": iso(row.ts),
                "level": row.level,
                "category": row.category,
                "message": row.message,
            }
            for row in db.query(SystemEvent).order_by(SystemEvent.ts.desc()).limit(8).all()
        ],
    }
