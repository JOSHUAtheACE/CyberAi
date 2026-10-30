from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    UploadFile,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..config import UPLOAD_DIR, settings
from ..database import SessionLocal, get_db
from ..deps import record_audit, require_permissions
from ..models import (
    CaptureFile,
    IngestionJob,
    SystemEvent,
    TrafficSource,
    User,
    Workspace,
    utcnow,
)
from ..parsing import PcapError, normalize_row, parse_flow_records, parse_pcap
from ..pipeline import finalize_ingestion_job, insert_flows, run_detection
from ..security import api_key_fingerprint, generate_api_key, rate_limiter
from ..serializers import iso, job_payload, source_payload

router = APIRouter(tags=["Ingestion & sources"])

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")
FLOW_EXTENSIONS = (".csv", ".json", ".jsonl", ".ndjson", ".tsv", ".log", ".txt")
MAX_PCAP_PACKETS = 500_000
MAX_FLOW_RECORDS = 200_000
COLLECTOR_KINDS = [
    {
        "kind": "netflow",
        "label": "NetFlow v5 / v9",
        "transport": "Collector template export, one-way push",
        "record_contract": "Collector converts datagrams to the SENTINEL flow JSON contract before forwarding.",
    },
    {
        "kind": "ipfix",
        "label": "IPFIX (RFC 7011)",
        "transport": "Collector template export, one-way push",
        "record_contract": "IPFIX fields map 1:1 to the documented flow JSON contract.",
    },
    {
        "kind": "sflow",
        "label": "sFlow v5",
        "transport": "Agent datagram export, one-way push",
        "record_contract": "sFlow samples are expanded by the enclave collector into flow records.",
    },
    {
        "kind": "zeek",
        "label": "Zeek JSON streams",
        "transport": "Zeek logs tailed inside the monitoring enclave",
        "record_contract": "Native conn.log / dns.log / ssl.log JSON is accepted without transformation.",
    },
    {
        "kind": "pcap",
        "label": "PCAP sensor",
        "transport": "Span / TAP copy captured by an enclave sensor",
        "record_contract": "Sensor performs local metadata extraction and forwards the flow contract.",
    },
]


def _get_workspace(db: Session, slug: str | None) -> Workspace:
    ws = (
        db.query(Workspace).filter(Workspace.slug == slug).first()
        if slug
        else db.query(Workspace).filter(Workspace.environment == "LIVE").first()
    )
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


def _next_job_reference(db: Session) -> str:
    count = db.query(func.count(IngestionJob.id)).scalar() or 0
    return f"JOB-{utcnow():%Y%m%d}-{count + 1:04d}"


def _ext(name: str) -> str:
    lowered = name.lower()
    for ext in PCAP_EXTENSIONS:
        if lowered.endswith(ext):
            return "pcap"
    for ext in FLOW_EXTENSIONS:
        if lowered.endswith(ext):
            return "zeek" if lowered.endswith((".log", ".tsv")) else "flows"
    return "flows"


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


@router.get("/sources")
def list_sources(
    workspace: str | None = Query(None),
    user: User = Depends(require_permissions("ingestion.view")),
    db: Session = Depends(get_db),
):
    ws = _get_workspace(db, workspace)
    sources = (
        db.query(TrafficSource)
        .filter(TrafficSource.workspace_id == ws.id)
        .order_by(TrafficSource.id)
        .all()
    )
    now = utcnow()
    payloads = []
    for source in sources:
        item = source_payload(source)
        stale = bool(source.last_seen_at and now - source.last_seen_at > timedelta(minutes=5))
        item["stale"] = stale
        item["connection_state"] = (
            "LIVE"
            if source.status == "CONNECTED" and not stale
            else "STALE"
            if source.status == "CONNECTED" and stale
            else source.status
        )
        payloads.append(item)
    return {
        "workspace": {"slug": ws.slug, "name": ws.name, "environment": ws.environment},
        "sources": payloads,
        "collector_kinds": COLLECTOR_KINDS,
        "ingest_endpoint": f"{settings.api_prefix}/feed/ingest",
        "contract": {
            "method": "POST",
            "auth_headers": ["X-Collector-Id", "X-Collector-Key"],
            "body": {
                "format": "zeek_json | flow_json | netflow | ipfix | sflow",
                "sent_at": "ISO-8601 UTC (optional)",
                "records": "array of flow records; each requires a timestamp, source and destination",
            },
            "notes": [
                "The collector runs inside the monitoring enclave and pushes a one-way copy of metadata.",
                "The browser never captures packets and the platform never connects back to monitored hosts.",
                "Ingest accepts a maximum of 5,000 records per request.",
            ],
        },
    }


class SourceCreate(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    kind: str = Field(pattern="^(netflow|ipfix|sflow|zeek|pcap)$")
    workspace: str = "live-ops"
    description: str = Field(default="", max_length=400)


@router.post("/sources")
def create_source(
    payload: SourceCreate,
    user: User = Depends(require_permissions("sources.manage")),
    db: Session = Depends(get_db),
):
    ws = _get_workspace(db, payload.workspace)
    identifier = f"{payload.kind}-{payload.name.lower().replace(' ', '-')[:32]}-{int(time.time()) % 100000}"
    source = TrafficSource(
        workspace_id=ws.id,
        name=payload.name,
        kind=payload.kind,
        identifier=identifier,
        status="DISCONNECTED",
        config={
            "transport": "Collector push over approved one-way monitoring path",
            "note": payload.description,
        },
    )
    db.add(source)
    db.flush()
    raw_key, fingerprint = generate_api_key()
    source.api_key_hash = fingerprint
    record_audit(
        db,
        actor=user,
        action="source.created",
        resource_type="traffic_source",
        resource_id=source.id,
        meta={"kind": source.kind, "identifier": source.identifier},
    )
    db.commit()
    return {
        **source_payload(source),
        "collector_id": source.identifier,
        "collector_key": raw_key,
        "key_notice": "The collector key is displayed once. Store it in the enclave secret manager.",
    }


@router.post("/sources/{source_id}/rotate-key")
def rotate_source_key(
    source_id: int,
    user: User = Depends(require_permissions("sources.manage")),
    db: Session = Depends(get_db),
):
    source = db.get(TrafficSource, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Collector not found")
    raw_key, fingerprint = generate_api_key()
    source.api_key_hash = fingerprint
    source.status = "DISCONNECTED"
    record_audit(
        db,
        actor=user,
        action="source.key_rotated",
        resource_type="traffic_source",
        resource_id=source.id,
    )
    db.commit()
    return {
        "collector_id": source.identifier,
        "collector_key": raw_key,
        "key_notice": "Previous key invalidated immediately. Update the enclave collector secret.",
    }


# ---------------------------------------------------------------------------
# Upload preview and processing
# ---------------------------------------------------------------------------


async def _read_upload(file: UploadFile, *, limit: int) -> bytes:
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {limit // (1024 * 1024)} MB upload limit.",
        )
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    return content


@router.post("/ingestion/preview")
async def preview_upload(
    file: UploadFile = File(...),
    user: User = Depends(require_permissions("ingestion.upload")),
):
    """Validate a capture or flow export without storing it."""
    name = file.filename or "upload"
    content = await _read_upload(file, limit=min(settings.max_upload_bytes, 8 * 1024 * 1024))
    kind = _ext(name)
    if kind == "pcap":
        try:
            result = parse_pcap(content, max_packets=20_000)
        except PcapError as exc:
            return {
                "kind": "pcap",
                "valid": False,
                "filename": name,
                "size_bytes": len(content),
                "errors": [str(exc)],
                "notes": ["No flows would be ingested from this file."],
            }
        return {
            "kind": "pcap",
            "valid": True,
            "filename": name,
            "size_bytes": len(content),
            "packet_count": result.packet_count,
            "flow_count": len(result.flows),
            "capture_start": iso(result.capture_start),
            "capture_end": iso(result.capture_end),
            "link_types": result.link_types,
            "notes": result.notes
            + ["Preview is limited to the first 20,000 packets; the full capture is processed on upload."],
            "sample_flows": [
                {
                    "src": f"{flow.src_ip}:{flow.src_port}",
                    "dst": f"{flow.dst_ip}:{flow.dst_port}",
                    "protocol": flow.protocol,
                    "packets": flow.packets,
                    "bytes": flow.bytes_total,
                    "dns_query": flow.dns_query,
                    "tls_ja3": flow.tls_ja3,
                }
                for flow in result.flows[:12]
            ],
        }

    parsed = parse_flow_records(name, content, preview_limit=20, max_records=20_000)
    quality = parsed["quality"]
    return {
        "kind": "flows",
        "format": parsed["format"],
        "valid": parsed["record_count"] > 0,
        "filename": name,
        "size_bytes": len(content),
        "record_count": parsed["record_count"],
        "timestamp_range": parsed["timestamp_range"],
        "quality": quality,
        "preview": parsed["preview"],
        "notes": quality["notes"]
        + ["Preview is capped at 20,000 records; the complete file is processed on upload."],
    }


def _process_upload(job_id: int, storage_path: str, *, demo: bool) -> None:
    db = SessionLocal()
    started = time.perf_counter()
    try:
        job = db.get(IngestionJob, job_id)
        if not job:
            return
        workspace = db.get(Workspace, job.workspace_id)
        job.status = "PARSING"
        job.started_at = utcnow()
        job.progress = 8
        db.commit()

        content = Path(storage_path).read_bytes()
        parse_started = time.perf_counter()
        capture: CaptureFile | None = None
        stats: dict = {"storage_path": storage_path, "bytes": len(content)}

        if job.kind == "pcap":
            result = parse_pcap(content, max_packets=MAX_PCAP_PACKETS)
            flows = result.flows
            stats.update(
                {
                    "packet_count": result.packet_count,
                    "link_types": result.link_types,
                    "truncated": result.truncated,
                    "parse_notes": result.notes,
                }
            )
            capture = CaptureFile(
                job_id=job.id,
                filename=job.original_filename,
                sha256=job.sha256,
                bytes=len(content),
                storage_path=storage_path,
                packet_count=result.packet_count,
                capture_start=result.capture_start,
                capture_end=result.capture_end,
                validation={
                    "valid": True,
                    "link_types": result.link_types,
                    "notes": result.notes,
                    "truncated": result.truncated,
                },
            )
            db.add(capture)
            rejected = 0
        else:
            parsed = parse_flow_records(
                job.original_filename, content, max_records=MAX_FLOW_RECORDS
            )
            flows = parsed["flows"]
            rejected = parsed["quality"]["rejected_records"]
            stats.update(
                {
                    "format": parsed["format"],
                    "quality": parsed["quality"],
                    "timestamp_range": parsed["timestamp_range"],
                }
            )

        parse_ms = round((time.perf_counter() - parse_started) * 1000, 1)
        job.progress = 42
        db.commit()

        inserted: list = []
        for index in range(0, len(flows), 800):
            inserted.extend(
                insert_flows(
                    db,
                    workspace=workspace,
                    environment=job.environment,
                    flows=flows[index : index + 800],
                    job_id=job.id,
                    source_id=job.source_id,
                    demo=demo,
                )
            )
            job.progress = 42 + int(38 * min(1.0, (index + 800) / max(1, len(flows))))
            db.commit()

        detection_started = time.perf_counter()
        detection = run_detection(
            db,
            workspace=workspace,
            environment=job.environment,
            flows=inserted,
            data_source=f"uploaded_{job.kind}",
            broadcast=True,
        )
        detection_ms = round((time.perf_counter() - detection_started) * 1000, 1)
        stats.update(
            {
                "parse_ms": parse_ms,
                "detection_ms": detection_ms,
                "total_ms": round((time.perf_counter() - started) * 1000, 1),
                "detection": detection,
            }
        )
        finalize_ingestion_job(
            db,
            job,
            valid=len(inserted),
            rejected=rejected,
            alerts=detection["alerts_created"],
            stats=stats,
        )
        db.commit()
    except PcapError as exc:
        _fail_job(db, job_id, f"Capture could not be parsed: {exc}")
    except Exception as exc:  # noqa: BLE001
        _fail_job(db, job_id, f"Processing failed: {exc.__class__.__name__}: {str(exc)[:400]}")
    finally:
        db.close()


def _fail_job(db: Session, job_id: int, message: str) -> None:
    db.rollback()
    job = db.get(IngestionJob, job_id)
    if job:
        job.status = "FAILED"
        job.error = message
        job.finished_at = utcnow()
        job.progress = 100
        db.add(
            SystemEvent(
                level="ERROR",
                category="ingestion",
                message=f"Ingestion {job.reference} failed.",
                meta={"error": message},
            )
        )
        db.commit()


@router.post("/ingestion/upload", status_code=202)
async def upload_capture(
    background: BackgroundTasks,
    file: UploadFile = File(...),
    workspace: str = Form("live-ops"),
    kind: str | None = Form(None),
    source_id: int | None = Form(None),
    user: User = Depends(require_permissions("ingestion.upload")),
    db: Session = Depends(get_db),
):
    ws = _get_workspace(db, workspace)
    original = Path(file.filename or "upload").name
    detected_kind = kind if kind in {"pcap", "flows", "zeek"} else _ext(original)
    content = await _read_upload(file, limit=settings.max_upload_bytes)
    digest = hashlib.sha256(content).hexdigest()

    source = None
    if source_id:
        source = db.get(TrafficSource, source_id)
        if not source or source.workspace_id != ws.id:
            raise HTTPException(status_code=400, detail="Collector does not belong to this workspace")

    job = IngestionJob(
        reference=_next_job_reference(db),
        workspace_id=ws.id,
        source_id=source.id if source else None,
        kind=detected_kind,
        environment=ws.environment,
        status="QUEUED",
        original_filename=original,
        size_bytes=len(content),
        sha256=digest,
    )
    db.add(job)
    db.flush()
    job.reference = f"JOB-{utcnow():%Y%m%d}-{job.id:04d}"

    storage = UPLOAD_DIR / f"{job.id}-{digest[:12]}-{original}"
    storage.write_bytes(content)

    previous = (
        db.query(IngestionJob)
        .filter(IngestionJob.sha256 == digest, IngestionJob.id != job.id)
        .order_by(IngestionJob.id.desc())
        .first()
    )
    if previous:
        job.stats = {"duplicate_of": previous.reference}

    record_audit(
        db,
        actor=user,
        action="ingestion.uploaded",
        resource_type="ingestion_job",
        resource_id=job.id,
        meta={"filename": original, "kind": detected_kind, "bytes": len(content), "sha256": digest},
    )
    db.commit()
    db.refresh(job)

    demo = ws.environment == "DEMO"
    background.add_task(_process_upload, job.id, str(storage), demo=demo)
    return job_payload(job)


@router.get("/ingestion/jobs")
def list_jobs(
    workspace: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(12, ge=1, le=50),
    user: User = Depends(require_permissions("ingestion.view")),
    db: Session = Depends(get_db),
):
    ws = _get_workspace(db, workspace)
    query = db.query(IngestionJob).filter(IngestionJob.workspace_id == ws.id)
    if status:
        query = query.filter(IngestionJob.status == status.upper())
    total = query.count()
    rows = (
        query.order_by(IngestionJob.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    counts = dict(
        db.query(IngestionJob.status, func.count(IngestionJob.id))
        .filter(IngestionJob.workspace_id == ws.id)
        .group_by(IngestionJob.status)
        .all()
    )
    captures = {
        c.job_id: c
        for c in db.query(CaptureFile)
        .filter(CaptureFile.job_id.in_([r.id for r in rows] or [-1]))
        .all()
    }
    return {
        "items": [job_payload(row, captures.get(row.id)) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "status_counts": counts,
    }


@router.get("/ingestion/jobs/{job_id}")
def job_detail(
    job_id: int,
    user: User = Depends(require_permissions("ingestion.view")),
    db: Session = Depends(get_db),
):
    job = db.get(IngestionJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Ingestion job not found")
    capture = db.query(CaptureFile).filter(CaptureFile.job_id == job.id).first()
    return job_payload(job, capture)


# ---------------------------------------------------------------------------
# Continuous collector feed (one-way push)
# ---------------------------------------------------------------------------


class FeedPayload(BaseModel):
    format: str = "flow_json"
    sent_at: str | None = None
    records: list[dict] = Field(min_length=1, max_length=5000)


def _authenticate_collector(
    db: Session,
    collector_id: str | None,
    collector_key: str | None,
) -> TrafficSource:
    if not collector_id or not collector_key:
        raise HTTPException(status_code=401, detail="Collector credentials required")
    source = db.query(TrafficSource).filter(TrafficSource.identifier == collector_id).first()
    if not source or not source.api_key_hash:
        raise HTTPException(status_code=401, detail="Unknown collector")
    if not api_key_fingerprint(collector_key) == source.api_key_hash:
        raise HTTPException(status_code=401, detail="Invalid collector key")
    if not rate_limiter.check(f"feed:{source.id}", limit=120, window_seconds=60):
        raise HTTPException(status_code=429, detail="Collector rate limit exceeded")
    return source


@router.post("/feed/ingest")
def collector_ingest(
    payload: FeedPayload,
    x_collector_id: str | None = Header(None, alias="X-Collector-Id"),
    x_collector_key: str | None = Header(None, alias="X-Collector-Key"),
    db: Session = Depends(get_db),
):
    source = _authenticate_collector(db, x_collector_id, x_collector_key)
    workspace = db.get(Workspace, source.workspace_id)
    received = utcnow()

    flows = []
    rejected = 0
    reasons: dict[str, int] = {}
    for record in payload.records:
        flow, error = normalize_row(record, default_direction=None)
        if flow is None:
            rejected += 1
            reasons[error or "unknown"] = reasons.get(error or "unknown", 0) + 1
        else:
            flows.append(flow)

    inserted = []
    for index in range(0, len(flows), 800):
        inserted.extend(
            insert_flows(
                db,
                workspace=workspace,
                environment=workspace.environment,
                flows=flows[index : index + 800],
                source_id=source.id,
            )
        )

    detection = run_detection(
        db,
        workspace=workspace,
        environment=workspace.environment,
        flows=inserted,
        data_source=f"collector_{source.kind}",
        broadcast=True,
    )

    now = utcnow()
    previous = source.last_record_at
    if previous:
        elapsed = max(0.2, (now - previous).total_seconds())
        source.records_per_second = round(len(inserted) / elapsed, 2)
    source.last_seen_at = now
    source.last_record_at = now
    source.status = "CONNECTED"
    source.records_total = (source.records_total or 0) + len(inserted)
    source.records_invalid = (source.records_invalid or 0) + rejected
    if payload.sent_at:
        try:
            sent = datetime.fromisoformat(payload.sent_at.replace("Z", "+00:00")).replace(tzinfo=None)
            source.avg_latency_ms = round((now - sent).total_seconds() * 1000, 1)
        except ValueError:
            pass
    db.commit()

    return {
        "accepted": len(inserted),
        "rejected": rejected,
        "rejection_reasons": reasons,
        "alerts_created": detection["alerts_created"],
        "alerts_updated": detection["alerts_updated"],
        "detectors": detection["per_detector"],
        "coverage": detection["coverage"],
        "environment": workspace.environment,
        "received_at": iso(received),
    }


@router.get("/feed/heartbeat")
def collector_heartbeat(
    x_collector_id: str | None = Header(None, alias="X-Collector-Id"),
    x_collector_key: str | None = Header(None, alias="X-Collector-Key"),
    db: Session = Depends(get_db),
):
    source = _authenticate_collector(db, x_collector_id, x_collector_key)
    source.last_seen_at = utcnow()
    source.status = "CONNECTED"
    db.commit()
    return {
        "ok": True,
        "collector": source.identifier,
        "server_time": iso(utcnow()),
        "next_expected_within_seconds": 300,
        "contract_version": "1.0",
    }
