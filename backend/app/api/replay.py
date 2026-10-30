from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import record_audit, require_permissions
from ..models import (
    DemoDataset,
    FlowRecord,
    IngestionJob,
    ReplaySession,
    SecurityAlert,
    User,
    Workspace,
    utcnow,
)
from ..replay_engine import (
    ALLOWED_SPEEDS,
    CATEGORY_TO_DETECTOR,
    is_running,
    pause,
    resume,
    start,
    stop,
)
from ..serializers import alert_summary, iso

router = APIRouter(prefix="/replay", tags=["Replay"])


def _workspace(db: Session) -> Workspace:
    ws = db.query(Workspace).filter(Workspace.slug == "replay-lab").first()
    if not ws:
        ws = db.query(Workspace).filter(Workspace.environment == "REPLAY").first()
    if not ws:
        raise HTTPException(status_code=503, detail="Replay workspace is not provisioned")
    return ws


def _dataset_counts(db: Session) -> dict[str, int]:
    rows = (
        db.query(FlowRecord.scenario_id, func.count(FlowRecord.id))
        .filter(FlowRecord.environment == "DEMO", FlowRecord.scenario_id.isnot(None))
        .group_by(FlowRecord.scenario_id)
        .all()
    )
    return {scenario: count for scenario, count in rows}


def _session_payload(session: ReplaySession, *, running: bool) -> dict:
    total = session.total_records or 0
    processed = session.records_processed or 0
    return {
        "id": session.id,
        "reference": session.reference,
        "dataset_id": session.dataset_id,
        "job_id": session.job_id,
        "dataset_label": session.dataset_label,
        "environment": session.environment,
        "demo": bool(session.dataset_id) or session.environment == "DEMO",
        "status": session.status,
        "running": running,
        "speed": session.speed,
        "cursor": session.cursor,
        "total_records": total,
        "records_processed": processed,
        "remaining_records": max(0, total - processed),
        "progress": round(processed / total * 100, 1) if total else 0,
        "alerts_generated": session.alerts_generated,
        "current_rate": session.current_rate,
        "processing_latency_ms": session.processing_latency_ms,
        "categories": session.categories or [],
        "started_at": iso(session.started_at),
        "finished_at": iso(session.finished_at),
        "created_at": iso(session.created_at),
    }


@router.get("/datasets")
def replay_datasets(
    user: User = Depends(require_permissions("replay.run")),
    db: Session = Depends(get_db),
):
    datasets = db.query(DemoDataset).order_by(DemoDataset.id).all()
    counts = _dataset_counts(db)
    jobs = (
        db.query(IngestionJob)
        .filter(
            IngestionJob.kind.in_(["pcap", "flows", "zeek"]),
            IngestionJob.status == "COMPLETE",
            IngestionJob.records_valid > 0,
        )
        .order_by(IngestionJob.created_at.desc())
        .limit(40)
        .all()
    )
    return {
        "demo_datasets": [
            {
                "id": item.id,
                "scenario_id": item.scenario_id,
                "name": item.name,
                "threat_class": item.threat_class,
                "description": item.description,
                "expected_features": item.expected_features,
                "ground_truth": item.ground_truth,
                "timespan": item.timespan,
                "flow_count": counts.get(item.scenario_id, item.flow_count),
            }
            for item in datasets
        ],
        "uploaded_datasets": [
            {
                "id": job.id,
                "reference": job.reference,
                "filename": job.original_filename,
                "kind": job.kind,
                "records": job.records_valid,
                "environment": job.environment,
                "finished_at": iso(job.finished_at),
            }
            for job in jobs
        ],
        "speeds": list(ALLOWED_SPEEDS),
        "categories": [
            {"slug": slug, "detector": detector}
            for slug, detector in CATEGORY_TO_DETECTOR.items()
        ],
        "notes": [
            "Synthetic datasets are replayed into the REPLAY workspace and always carry a DEMO label.",
            "Replay timelines are compressed for interactive use; the API reports the processed record count.",
            "Starting a session resets previous REPLAY-workspace results so charts reflect the current run.",
        ],
    }


class ReplayCreate(BaseModel):
    dataset: str = Field(pattern=r"^(demo|job):[0-9]+$")
    speed: float = 1.0
    categories: list[str] = Field(default_factory=list)


@router.post("/sessions", status_code=202)
def create_session(
    payload: ReplayCreate,
    user: User = Depends(require_permissions("replay.run")),
    db: Session = Depends(get_db),
):
    if payload.speed not in ALLOWED_SPEEDS:
        raise HTTPException(status_code=400, detail="Unsupported replay speed")
    invalid = [slug for slug in payload.categories if slug not in CATEGORY_TO_DETECTOR]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown detection category: {invalid[0]}")
    ws = _workspace(db)
    kind, raw_id = payload.dataset.split(":", 1)
    dataset_id = job_id = None
    label = ""
    demo = kind == "demo"

    if kind == "demo":
        dataset = db.get(DemoDataset, int(raw_id))
        if not dataset:
            raise HTTPException(status_code=404, detail="Demo dataset not found")
        dataset_id = dataset.id
        label = dataset.name
        total = (
            db.query(func.count(FlowRecord.id))
            .filter(
                FlowRecord.environment == "DEMO",
                FlowRecord.scenario_id == dataset.scenario_id,
            )
            .scalar()
            or 0
        )
        environment = "DEMO"
    else:
        job = db.get(IngestionJob, int(raw_id))
        if not job or job.status != "COMPLETE":
            raise HTTPException(status_code=404, detail="Completed ingestion job not found")
        job_id = job.id
        label = f"{job.reference} · {job.original_filename}"
        total = (
            db.query(func.count(FlowRecord.id)).filter(FlowRecord.job_id == job.id).scalar() or 0
        )
        environment = job.environment
        demo = job.environment == "DEMO"

    if not total:
        raise HTTPException(status_code=422, detail="Dataset contains no flow records to replay")

    session = ReplaySession(
        reference=f"RPL-{utcnow():%Y%m%d%H%M%S}-{total:05d}",
        workspace_id=ws.id,
        dataset_id=dataset_id,
        job_id=job_id,
        dataset_label=label,
        environment="DEMO" if demo else "REPLAY",
        status="READY",
        speed=payload.speed,
        total_records=total,
        categories=payload.categories,
        created_by=user.id,
        current_rate=0,
        processing_latency_ms=0,
    )
    db.add(session)
    db.flush()
    session.reference = f"RPL-{utcnow():%Y%m%d}-{session.id:04d}"
    record_audit(
        db,
        actor=user,
        action="replay.started",
        resource_type="replay_session",
        resource_id=session.id,
        meta={"dataset": label, "speed": payload.speed, "categories": payload.categories},
    )
    db.commit()
    db.refresh(session)
    start(session.id)
    return _session_payload(session, running=True)


@router.get("/sessions")
def list_sessions(
    user: User = Depends(require_permissions("replay.run")),
    db: Session = Depends(get_db),
):
    sessions = (
        db.query(ReplaySession).order_by(ReplaySession.created_at.desc()).limit(30).all()
    )
    return {"items": [_session_payload(item, running=is_running(item.id)) for item in sessions]}


@router.get("/sessions/{session_id}")
def session_status(
    session_id: int,
    user: User = Depends(require_permissions("replay.run")),
    db: Session = Depends(get_db),
):
    session = db.get(ReplaySession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Replay session not found")
    running = is_running(session.id)
    if session.status == "RUNNING" and not running:
        session.status = "STOPPED"
        db.commit()
    payload = _session_payload(session, running=running)
    if session.workspace_id:
        recent = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.workspace_id == session.workspace_id,
                SecurityAlert.environment == "REPLAY",
                SecurityAlert.first_seen >= session.started_at if session.started_at else True,
            )
            .order_by(SecurityAlert.first_seen.desc())
            .limit(6)
            .all()
        )
        payload["recent_alerts"] = [alert_summary(alert) for alert in recent]
    return payload


@router.post("/sessions/{session_id}/{action}")
def control_session(
    session_id: int,
    action: str,
    user: User = Depends(require_permissions("replay.run")),
    db: Session = Depends(get_db),
):
    if action not in {"pause", "resume", "stop"}:
        raise HTTPException(status_code=400, detail="Unsupported replay control")
    session = db.get(ReplaySession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Replay session not found")

    if action == "pause":
        if not pause(session_id):
            raise HTTPException(status_code=409, detail="Replay is not running")
        session.status = "PAUSED"
    elif action == "resume":
        if not resume(session_id):
            raise HTTPException(status_code=409, detail="Replay is not running")
        session.status = "RUNNING"
    else:
        stop(session_id)
        if session.status == "READY":
            session.status = "STOPPED"
            session.finished_at = utcnow()
    record_audit(
        db,
        actor=user,
        action=f"replay.{action}",
        resource_type="replay_session",
        resource_id=session.id,
    )
    db.commit()
    return _session_payload(session, running=is_running(session_id))
