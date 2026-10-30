from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import record_audit, require_permissions
from ..models import (
    AlertEvidence,
    AlertLink,
    EnrichmentResult,
    FlowRecord,
    InvestigationCase,
    InvestigationNote,
    SecurityAlert,
    User,
    utcnow,
)
from ..serializers import alert_detail, alert_summary, case_payload, iso
from .dashboard import get_workspace_or_404, window

router = APIRouter(tags=["Alerts & investigations"])

STATUSES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"]
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def _split(values: list[str] | None) -> list[str]:
    if not values:
        return []
    output: list[str] = []
    for value in values:
        output.extend(part.strip() for part in value.split(",") if part.strip())
    return output


def _base_query(db: Session, ws, start, end):
    return db.query(SecurityAlert).filter(
        SecurityAlert.workspace_id == ws.id,
        SecurityAlert.environment == ws.environment,
        SecurityAlert.first_seen >= start,
        SecurityAlert.first_seen <= end,
    )


def _facet(query, limit: int = 12) -> list[dict]:
    from sqlalchemy import func

    rows = (
        query.with_entities(SecurityAlert.threat_class, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.threat_class)
        .order_by(func.count(SecurityAlert.id).desc())
        .limit(limit)
        .all()
    )
    return [{"value": value, "count": count} for value, count in rows]


@router.get("/alerts/meta")
def alert_meta(
    user: User = Depends(require_permissions("alerts.view")),
    db: Session = Depends(get_db),
):
    from ..models import DetectionModule

    detectors = db.query(DetectionModule).order_by(DetectionModule.name).all()
    users = db.query(User).filter(User.is_active.is_(True)).order_by(User.name).all()
    return {
        "statuses": STATUSES,
        "severities": SEVERITIES,
        "detectors": [
            {"code": item.code, "name": item.name, "threat_class": item.threat_class}
            for item in detectors
        ],
        "assignees": [
            {"id": item.id, "name": item.name, "email": item.email, "role": item.role.name}
            for item in users
        ],
        "confidence_types": [
            "calibrated_probability",
            "hybrid_score",
            "heuristic_score",
            "anomaly_score",
        ],
        "notes": [
            "Severity expresses potential impact; confidence expresses detector certainty or score strength.",
            "Investigation actions update records inside SENTINEL AI only. No blocking or isolation is performed.",
        ],
    }


@router.get("/alerts")
def list_alerts(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    q: str | None = Query(None, max_length=120),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    threat_class: list[str] | None = Query(None),
    detector: list[str] | None = Query(None),
    assignee: str | None = Query(None),
    sort: str = Query("first_seen"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: User = Depends(require_permissions("alerts.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    start_dt, end_dt, label = window(range, start, end)
    base = _base_query(db, ws, start_dt, end_dt)

    severities = _split(severity)
    statuses = _split(status)
    classes = _split(threat_class)
    detectors = _split(detector)

    query = base
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                SecurityAlert.alert_code.ilike(like),
                SecurityAlert.source_ip.ilike(like),
                SecurityAlert.dest_ip.ilike(like),
                SecurityAlert.threat_class.ilike(like),
                SecurityAlert.summary.ilike(like),
                SecurityAlert.dedup_key.ilike(like),
            )
        )
    if severities:
        query = query.filter(SecurityAlert.severity.in_(severities))
    if statuses:
        query = query.filter(SecurityAlert.status.in_(statuses))
    if classes:
        query = query.filter(SecurityAlert.threat_class.in_(classes))
    if detectors:
        query = query.filter(SecurityAlert.detector_code.in_(detectors))
    if assignee == "unassigned":
        query = query.filter(SecurityAlert.assignee_id.is_(None))
    elif assignee == "me":
        query = query.filter(SecurityAlert.assignee_id == user.id)
    elif assignee and assignee.isdigit():
        query = query.filter(SecurityAlert.assignee_id == int(assignee))

    sort_field = {
        "first_seen": SecurityAlert.first_seen,
        "last_seen": SecurityAlert.last_seen,
        "confidence": SecurityAlert.confidence,
        "severity": SecurityAlert.severity,
    }.get(sort, SecurityAlert.first_seen)
    query = query.order_by(sort_field.desc(), SecurityAlert.id.desc())

    total = query.count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    evidence_rows = (
        db.query(AlertEvidence)
        .filter(AlertEvidence.alert_id.in_([row.id for row in rows] or [-1]))
        .order_by(AlertEvidence.id)
        .all()
    )
    by_alert: dict[int, list[AlertEvidence]] = {}
    for item in evidence_rows:
        by_alert.setdefault(item.alert_id, []).append(item)

    from sqlalchemy import func

    status_counts = dict(
        base.with_entities(SecurityAlert.status, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.status)
        .all()
    )
    severity_counts = dict(
        base.with_entities(SecurityAlert.severity, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.severity)
        .all()
    )
    detector_counts = dict(
        base.with_entities(SecurityAlert.detector_code, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.detector_code)
        .all()
    )

    return {
        "items": [alert_summary(row, by_alert.get(row.id, [])[:3]) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "period": {"label": label, "start": iso(start_dt), "end": iso(end_dt)},
        "workspace": {"slug": ws.slug, "name": ws.name, "environment": ws.environment},
        "facets": {
            "statuses": [{"value": key, "count": value} for key, value in status_counts.items()],
            "severities": [{"value": key, "count": value} for key, value in severity_counts.items()],
            "detectors": [{"value": key, "count": value} for key, value in detector_counts.items()],
            "threat_classes": _facet(base),
        },
    }


def _case_for(db: Session, alert: SecurityAlert) -> InvestigationCase | None:
    return db.query(InvestigationCase).filter(InvestigationCase.alert_id == alert.id).first()


def _ensure_case(db: Session, alert: SecurityAlert, actor: User) -> InvestigationCase:
    case = _case_for(db, alert)
    if case:
        return case
    db.flush()
    case = InvestigationCase(
        case_code=f"CASE-{alert.id:05d}",
        alert_id=alert.id,
        title=f"{alert.threat_class.replace('_', ' ')} — {alert.source_ip} → {alert.dest_ip}",
        status="OPEN",
        owner_id=actor.id,
    )
    db.add(case)
    db.flush()
    return case


@router.get("/alerts/{alert_id}")
def alert_detail_view(
    alert_id: int,
    user: User = Depends(require_permissions("alerts.view")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    evidence = (
        db.query(AlertEvidence)
        .filter(AlertEvidence.alert_id == alert.id)
        .order_by(AlertEvidence.id)
        .all()
    )
    flows = (
        db.query(FlowRecord)
        .filter(FlowRecord.id.in_(alert.flow_ids or []))
        .order_by(FlowRecord.ts.asc())
        .limit(250)
        .all()
    )
    payload = alert_detail(alert, evidence, flows)
    payload["workspace_id"] = alert.workspace_id
    payload["created_at"] = iso(alert.created_at)
    payload["updated_at"] = iso(alert.updated_at)
    payload["detector"] = {
        "code": alert.detector_code,
        "confidence_type": alert.confidence_type,
        "model_version_id": alert.model_version_id,
    }

    links = db.query(AlertLink).filter(
        or_(AlertLink.alert_id == alert.id, AlertLink.related_alert_id == alert.id)
    ).all()
    related_ids = {
        link.related_alert_id if link.alert_id == alert.id else link.alert_id for link in links
    }
    related = (
        db.query(SecurityAlert).filter(SecurityAlert.id.in_(related_ids)).all()
        if related_ids
        else []
    )
    payload["related"] = [
        {**alert_summary(item), "relation": "linked investigation"} for item in related
    ]

    similar = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.id != alert.id,
            SecurityAlert.workspace_id == alert.workspace_id,
            SecurityAlert.environment == alert.environment,
            SecurityAlert.first_seen >= alert.first_seen - timedelta(days=7),
            or_(SecurityAlert.source_ip == alert.source_ip, SecurityAlert.dest_ip == alert.dest_ip),
        )
        .order_by(SecurityAlert.first_seen.desc())
        .limit(5)
        .all()
    )
    payload["similar"] = [
        {
            **alert_summary(item),
            "relation": (
                "same source"
                if item.source_ip == alert.source_ip
                else "same destination"
            ),
        }
        for item in similar
    ]

    case = _case_for(db, alert)
    if case:
        notes = (
            db.query(InvestigationNote)
            .filter(InvestigationNote.case_id == case.id)
            .order_by(InvestigationNote.created_at.asc())
            .all()
        )
        payload["case"] = case_payload(case, notes)
    else:
        payload["case"] = None

    payload["enrichment"] = [
        {
            "id": item.id,
            "provider": item.provider,
            "indicator": item.indicator,
            "status": item.status,
            "cached": item.cached,
            "payload": item.payload,
            "error": item.error,
            "retrieved_at": iso(item.retrieved_at),
        }
        for item in db.query(EnrichmentResult)
        .filter(EnrichmentResult.alert_id == alert.id)
        .order_by(EnrichmentResult.retrieved_at.desc())
        .limit(10)
        .all()
    ]

    payload["evidence_flow_coverage"] = {
        "referenced": len(alert.flow_ids or []),
        "loaded": len(flows),
        "truncated": len(flows) < len(alert.flow_ids or []),
        "note": "Flow rows are loaded up to 250 per alert; every evidence item retains its flow references.",
    }
    return payload


class AlertUpdate(BaseModel):
    status: str | None = None
    assignee_id: int | None = None


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    user: User = Depends(require_permissions("alerts.investigate")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes: dict = {}
    if payload.status is not None:
        status = payload.status.upper()
        if status not in STATUSES:
            raise HTTPException(status_code=400, detail="Unsupported investigation status")
        alert.status = status
        changes["status"] = status
        case = _ensure_case(db, alert, user)
        if status in {"CLOSED", "FALSE_POSITIVE"}:
            case.status = "CLOSED"
        elif status == "ACKNOWLEDGED":
            case.status = "IN_PROGRESS"
        elif status == "INVESTIGATING":
            case.status = "IN_PROGRESS"
        elif status == "OPEN":
            case.status = "OPEN"
        case.updated_at = utcnow()

    if payload.assignee_id is not None:
        if "alerts.assign" not in (user.role.permissions or []):
            raise HTTPException(status_code=403, detail="Missing permission: alerts.assign")
        if payload.assignee_id == 0:
            alert.assignee_id = None
            changes["assignee_id"] = None
        else:
            assignee = db.get(User, payload.assignee_id)
            if not assignee or not assignee.is_active:
                raise HTTPException(status_code=400, detail="Assignee not found or inactive")
            alert.assignee_id = assignee.id
            changes["assignee_id"] = assignee.id
            case = _ensure_case(db, alert, user)
            case.owner_id = assignee.id
            case.updated_at = utcnow()

    if not changes:
        raise HTTPException(status_code=400, detail="No supported changes supplied")
    record_audit(
        db,
        actor=user,
        action="alert.updated",
        resource_type="security_alert",
        resource_id=alert.id,
        meta=changes,
    )
    db.commit()
    db.refresh(alert)
    return alert_summary(alert)


class NoteCreate(BaseModel):
    body: str = Field(min_length=3, max_length=4000)


@router.post("/alerts/{alert_id}/notes", status_code=201)
def add_note(
    alert_id: int,
    payload: NoteCreate,
    user: User = Depends(require_permissions("alerts.investigate")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    case = _ensure_case(db, alert, user)
    note = InvestigationNote(case_id=case.id, author_id=user.id, body=payload.body.strip())
    db.add(note)
    case.status = "IN_PROGRESS" if case.status == "OPEN" else case.status
    case.updated_at = utcnow()
    if alert.status == "OPEN":
        alert.status = "INVESTIGATING"
    record_audit(
        db,
        actor=user,
        action="alert.note_added",
        resource_type="security_alert",
        resource_id=alert.id,
        meta={"case": case.case_code, "length": len(payload.body)},
    )
    db.commit()
    db.refresh(note)
    return {
        "id": note.id,
        "author": user.name,
        "body": note.body,
        "created_at": iso(note.created_at),
        "case_code": case.case_code,
    }


class LinkCreate(BaseModel):
    related_alert_id: int


@router.post("/alerts/{alert_id}/link", status_code=201)
def link_alert(
    alert_id: int,
    payload: LinkCreate,
    user: User = Depends(require_permissions("alerts.investigate")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    related = db.get(SecurityAlert, payload.related_alert_id)
    if not alert or not related:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.id == related.id:
        raise HTTPException(status_code=400, detail="An alert cannot be linked to itself")
    exists = (
        db.query(AlertLink)
        .filter(
            or_(
                (AlertLink.alert_id == alert.id) & (AlertLink.related_alert_id == related.id),
                (AlertLink.alert_id == related.id) & (AlertLink.related_alert_id == alert.id),
            )
        )
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Alerts are already linked")
    db.add(AlertLink(alert_id=alert.id, related_alert_id=related.id))
    record_audit(
        db,
        actor=user,
        action="alert.linked",
        resource_type="security_alert",
        resource_id=alert.id,
        meta={"related_alert_id": related.id},
    )
    db.commit()
    return {"ok": True, "related": alert_summary(related)}


class BulkAction(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=100)
    action: str = Field(pattern="^(acknowledge|assign|close)$")
    assignee_id: int | None = None


@router.post("/alerts/bulk")
def bulk_action(
    payload: BulkAction,
    user: User = Depends(require_permissions("alerts.investigate")),
    db: Session = Depends(get_db),
):
    if payload.action == "assign" and "alerts.assign" not in (user.role.permissions or []):
        raise HTTPException(status_code=403, detail="Missing permission: alerts.assign")
    alerts = db.query(SecurityAlert).filter(SecurityAlert.id.in_(payload.ids)).all()
    updated = 0
    for alert in alerts:
        case = _ensure_case(db, alert, user)
        if payload.action == "acknowledge":
            alert.status = "ACKNOWLEDGED"
            case.status = "IN_PROGRESS"
        elif payload.action == "close":
            alert.status = "CLOSED"
            case.status = "CLOSED"
        else:
            if not payload.assignee_id:
                raise HTTPException(status_code=400, detail="assignee_id is required to assign")
            assignee = db.get(User, payload.assignee_id)
            if not assignee or not assignee.is_active:
                raise HTTPException(status_code=400, detail="Assignee not found or inactive")
            alert.assignee_id = assignee.id
            case.owner_id = assignee.id
            case.status = "IN_PROGRESS"
        case.updated_at = utcnow()
        updated += 1
    record_audit(
        db,
        actor=user,
        action=f"alert.bulk_{payload.action}",
        resource_type="security_alert",
        resource_id=",".join(str(i) for i in payload.ids[:20]),
        meta={"requested": len(payload.ids), "updated": updated},
    )
    db.commit()
    return {"updated": updated, "requested": len(payload.ids)}


@router.get("/alerts/{alert_id}/export")
def export_alert(
    alert_id: int,
    user: User = Depends(require_permissions("alerts.export")),
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    evidence = db.query(AlertEvidence).filter(AlertEvidence.alert_id == alert.id).all()
    flows = (
        db.query(FlowRecord)
        .filter(FlowRecord.id.in_(alert.flow_ids or []))
        .order_by(FlowRecord.ts.asc())
        .limit(500)
        .all()
    )
    case = _case_for(db, alert)
    notes = (
        db.query(InvestigationNote)
        .filter(InvestigationNote.case_id == case.id)
        .order_by(InvestigationNote.created_at.asc())
        .all()
        if case
        else []
    )
    document = {
        "export": {
            "product": "SENTINEL AI",
            "type": "alert_evidence",
            "generated_at": iso(utcnow()),
            "generated_by": user.email,
            "environment": alert.environment,
            "data_source": alert.data_source,
            "notice": (
                "Evidence export for internal investigation. Severity and confidence are analytical "
                "assessments; they do not confirm compromise or attribution."
            ),
        },
        "alert": alert_detail(alert, evidence, flows),
        "investigation": case_payload(case, notes) if case else None,
    }
    record_audit(
        db,
        actor=user,
        action="alert.exported",
        resource_type="security_alert",
        resource_id=alert.id,
    )
    db.commit()
    body = json.dumps(document, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{alert.alert_code}-evidence.json"'
        },
    )


@router.get("/investigations")
def list_investigations(
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permissions("alerts.view")),
    db: Session = Depends(get_db),
):
    query = db.query(InvestigationCase).join(SecurityAlert, InvestigationCase.alert_id == SecurityAlert.id)
    if status:
        query = query.filter(InvestigationCase.status == status.upper())
    total = query.count()
    rows = (
        query.order_by(InvestigationCase.updated_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    payload = []
    for case in rows:
        notes = (
            db.query(InvestigationNote)
            .filter(InvestigationNote.case_id == case.id)
            .order_by(InvestigationNote.created_at.asc())
            .all()
        )
        alert = db.get(SecurityAlert, case.alert_id)
        item = case_payload(case, notes, alert)
        item["environment"] = alert.environment if alert else None
        item["severity"] = alert.severity if alert else None
        payload.append(item)
    return {"items": payload, "total": total, "page": page, "page_size": page_size}
