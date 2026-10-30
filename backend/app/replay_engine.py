"""Traffic replay engine.

Replays stored flow records into the REPLAY workspace at a controlled pace.
Synthetic demo datasets are replayed only into the demo-labelled REPLAY
workspace and are never mixed with LIVE telemetry. Timeline gaps are
compressed so long recordings remain interactive; the compression factor is
reported to the client.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from threading import Event, Lock, Thread

from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import (
    AlertEvidence,
    AlertLink,
    DemoDataset,
    EnrichmentResult,
    FeatureObservation,
    FlowRecord,
    IngestionJob,
    InvestigationCase,
    InvestigationNote,
    ReplaySession,
    SecurityAlert,
    SystemEvent,
    Workspace,
    utcnow,
)
from .parsing import FlowIn
from .pipeline import insert_flows, run_detection
from .streaming import bus
from .text import plural

CATEGORY_TO_DETECTOR = {
    "ddos": "ddos_detector",
    "beaconing": "beaconing_detector",
    "dns": "dns_detector",
    "encrypted": "encrypted_metadata_detector",
    "scanning": "port_scan_detector",
    "exfiltration": "exfiltration_detector",
}
ALLOWED_SPEEDS = (0.5, 1.0, 2.0, 5.0)
TARGET_SECONDS = 120.0
MAX_REPLAY_FLOWS = 50_000


class ReplayControl:
    def __init__(self, session_id: int) -> None:
        self.session_id = session_id
        self.resume = Event()
        self.resume.set()
        self.stop = Event()
        self.thread = Thread(target=_run, args=(session_id, self), daemon=True, name=f"replay-{session_id}")


_lock = Lock()
_controls: dict[int, ReplayControl] = {}


def start(session_id: int) -> None:
    with _lock:
        control = _controls.get(session_id)
        if control and control.thread.is_alive():
            return
        control = ReplayControl(session_id)
        _controls[session_id] = control
        control.thread.start()


def is_running(session_id: int) -> bool:
    control = _controls.get(session_id)
    return bool(control and control.thread.is_alive())


def pause(session_id: int) -> bool:
    control = _controls.get(session_id)
    if not control or not control.thread.is_alive():
        return False
    control.resume.clear()
    return True


def resume(session_id: int) -> bool:
    control = _controls.get(session_id)
    if not control or not control.thread.is_alive():
        return False
    control.resume.set()
    return True


def stop(session_id: int) -> bool:
    control = _controls.get(session_id)
    if not control:
        return False
    control.stop.set()
    control.resume.set()
    return True


def _reset_replay_workspace(db: Session, workspace: Workspace) -> None:
    alerts = (
        db.query(SecurityAlert.id)
        .filter(
            SecurityAlert.workspace_id == workspace.id,
            SecurityAlert.environment == "REPLAY",
        )
        .all()
    )
    alert_ids = [row[0] for row in alerts]
    if alert_ids:
        cases = (
            db.query(InvestigationCase.id)
            .filter(InvestigationCase.alert_id.in_(alert_ids))
            .all()
        )
        case_ids = [row[0] for row in cases]
        if case_ids:
            db.query(InvestigationNote).filter(
                InvestigationNote.case_id.in_(case_ids)
            ).delete(synchronize_session=False)
        db.query(InvestigationCase).filter(
            InvestigationCase.alert_id.in_(alert_ids)
        ).delete(synchronize_session=False)
        db.query(AlertLink).filter(
            AlertLink.alert_id.in_(alert_ids)
        ).delete(synchronize_session=False)
        db.query(AlertLink).filter(
            AlertLink.related_alert_id.in_(alert_ids)
        ).delete(synchronize_session=False)
        db.query(AlertEvidence).filter(
            AlertEvidence.alert_id.in_(alert_ids)
        ).delete(synchronize_session=False)
        db.query(EnrichmentResult).filter(
            EnrichmentResult.alert_id.in_(alert_ids)
        ).delete(synchronize_session=False)
        db.query(SecurityAlert).filter(SecurityAlert.id.in_(alert_ids)).delete(
            synchronize_session=False
        )
    db.query(FeatureObservation).filter(
        FeatureObservation.environment == "REPLAY"
    ).delete(synchronize_session=False)
    db.query(FlowRecord).filter(
        FlowRecord.workspace_id == workspace.id,
        FlowRecord.environment == "REPLAY",
    ).delete(synchronize_session=False)
    db.commit()


def _snapshot_flows(db: Session, session: ReplaySession) -> tuple[list[dict], str, bool, str]:
    if session.dataset_id:
        dataset = db.get(DemoDataset, session.dataset_id)
        if not dataset:
            raise ValueError("Demo dataset no longer exists")
        rows = (
            db.query(FlowRecord)
            .filter(
                FlowRecord.environment == "DEMO",
                FlowRecord.scenario_id == dataset.scenario_id,
            )
            .order_by(FlowRecord.ts.asc())
            .limit(MAX_REPLAY_FLOWS)
            .all()
        )
        label = dataset.name
        demo = True
        description = dataset.description
    else:
        job = db.get(IngestionJob, session.job_id)
        if not job:
            raise ValueError("Ingestion job no longer exists")
        rows = (
            db.query(FlowRecord)
            .filter(FlowRecord.job_id == job.id)
            .order_by(FlowRecord.ts.asc())
            .limit(MAX_REPLAY_FLOWS)
            .all()
        )
        label = f"{job.reference} · {job.original_filename}"
        demo = job.environment == "DEMO"
        description = f"Uploaded {job.kind} capture processed at {job.created_at.isoformat()}Z"

    snapshot = [
        {
            "ts": row.ts,
            "src_ip": row.src_ip,
            "src_port": row.src_port,
            "dst_ip": row.dst_ip,
            "dst_port": row.dst_port,
            "protocol": row.protocol,
            "app_proto": row.app_proto,
            "bytes_total": row.bytes_total,
            "bytes_out": row.bytes_out,
            "bytes_in": row.bytes_in,
            "packets": row.packets,
            "duration_ms": row.duration_ms,
            "tcp_flags": row.tcp_flags,
            "dns_query": row.dns_query,
            "dns_qtype": row.dns_qtype,
            "dns_rcode": row.dns_rcode,
            "tls_sni": row.tls_sni,
            "tls_ja3": row.tls_ja3,
            "tls_version": row.tls_version,
            "tls_cipher": row.tls_cipher,
            "quic": row.quic,
            "scenario_id": row.scenario_id,
            "label": row.label,
            "meta": {**(row.meta or {}), "origin": "replay", "demo": demo},
        }
        for row in rows
    ]
    return snapshot, label, demo, description


def _run(session_id: int, control: ReplayControl) -> None:
    db = SessionLocal()
    session = db.get(ReplaySession, session_id)
    workspace = db.get(Workspace, session.workspace_id) if session else None
    if not session or not workspace:
        db.close()
        return

    try:
        snapshot, label, demo, description = _snapshot_flows(db, session)
        if not snapshot:
            session.status = "FAILED"
            session.finished_at = utcnow()
            db.commit()
            return

        _reset_replay_workspace(db, workspace)
        session.dataset_label = label
        session.total_records = len(snapshot)
        session.records_processed = 0
        session.cursor = 0
        session.alerts_generated = 0
        session.status = "RUNNING"
        session.started_at = utcnow()
        session.finished_at = None
        db.commit()

        detector_codes = {
            CATEGORY_TO_DETECTOR[slug]
            for slug in (session.categories or [])
            if slug in CATEGORY_TO_DETECTOR
        } or None

        demo = demo or (workspace.environment == "DEMO")
        first_ts: datetime = snapshot[0]["ts"]
        last_ts: datetime = snapshot[-1]["ts"]
        span = max(1.0, (last_ts - first_ts).total_seconds())
        compression = max(1.0, span / TARGET_SECONDS)
        effective = compression * max(0.5, session.speed or 1.0)
        anchor = utcnow() - timedelta(seconds=span / effective)
        wall_start = time.monotonic()
        processed = 0
        alerts_total = 0
        index = 0
        latency_ms = 0.0

        while index < len(snapshot):
            if control.stop.is_set():
                session.status = "STOPPED"
                session.finished_at = utcnow()
                db.commit()
                bus.publish("REPLAY", {"type": "replay.stopped", "session_id": session.id})
                return
            while not control.resume.wait(0.2):
                if control.stop.is_set():
                    break
            if control.stop.is_set():
                continue

            chunk = snapshot[index : index + 24]
            index += len(chunk)
            chunk_start = (chunk[0]["ts"] - first_ts).total_seconds() / effective
            chunk_end = (chunk[-1]["ts"] - first_ts).total_seconds() / effective
            wall_offset = time.monotonic() - wall_start
            if chunk_start > wall_offset:
                control.stop.wait(min(0.4, chunk_start - wall_offset))

            flows_in = [
                FlowIn(
                    ts=anchor
                    + timedelta(seconds=(item["ts"] - first_ts).total_seconds() / effective),
                    src_ip=item["src_ip"],
                    src_port=item["src_port"],
                    dst_ip=item["dst_ip"],
                    dst_port=item["dst_port"],
                    protocol=item["protocol"],
                    app_proto=item["app_proto"],
                    bytes_total=item["bytes_total"],
                    bytes_out=item["bytes_out"],
                    bytes_in=item["bytes_in"],
                    packets=item["packets"],
                    duration_ms=item["duration_ms"],
                    tcp_flags=item["tcp_flags"],
                    dns_query=item["dns_query"],
                    dns_qtype=item["dns_qtype"],
                    dns_rcode=item["dns_rcode"],
                    tls_sni=item["tls_sni"],
                    tls_ja3=item["tls_ja3"],
                    tls_version=item["tls_version"],
                    tls_cipher=item["tls_cipher"],
                    quic=item["quic"],
                    scenario_id=item["scenario_id"],
                    label=item["label"],
                    meta=item["meta"],
                )
                for item in chunk
            ]
            inserted = insert_flows(
                db,
                workspace=workspace,
                environment="REPLAY",
                flows=flows_in,
                demo=demo,
            )
            detection_started = time.perf_counter()
            result = run_detection(
                db,
                workspace=workspace,
                environment="REPLAY",
                flows=inserted,
                data_source="synthetic_demo_replay" if demo else "uploaded_replay",
                detector_codes=detector_codes,
                broadcast=True,
            )
            latency_ms = round((time.perf_counter() - detection_started) * 1000, 1)
            alerts_total += result["alerts_created"]
            processed += len(inserted)

            session.cursor = index
            session.records_processed = processed
            session.alerts_generated = alerts_total
            session.processing_latency_ms = latency_ms
            elapsed = max(0.1, time.monotonic() - wall_start)
            session.current_rate = round(processed / elapsed, 2)
            db.commit()
            bus.publish(
                "REPLAY",
                {
                    "type": "replay.progress",
                    "session_id": session.id,
                    "processed": processed,
                    "total": len(snapshot),
                    "alerts": alerts_total,
                    "rate": session.current_rate,
                    "demo": demo,
                    "at": utcnow().isoformat() + "Z",
                },
            )
            remaining = chunk_end - (time.monotonic() - wall_start)
            if remaining > 0:
                control.stop.wait(min(0.4, remaining))

        session.status = "COMPLETE"
        session.finished_at = utcnow()
        session.current_rate = 0.0
        db.add(
            SystemEvent(
                category="replay",
                message=(
                    f"Replay {session.reference} completed: {processed:,} {plural(processed, 'record')}, "
                    f"{alerts_total} {plural(alerts_total, 'alert')} generated."
                ),
                meta={
                    "session": session.reference,
                    "dataset": label,
                    "demo": demo,
                    "compression": round(compression, 2),
                    "description": description,
                },
            )
        )
        db.commit()
        bus.publish(
            "REPLAY",
            {
                "type": "replay.completed",
                "session_id": session.id,
                "processed": processed,
                "alerts": alerts_total,
                "demo": demo,
            },
        )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        session = db.get(ReplaySession, session_id)
        if session:
            session.status = "FAILED"
            session.finished_at = utcnow()
            db.add(
                SystemEvent(
                    level="ERROR",
                    category="replay",
                    message=f"Replay {session.reference} failed: {exc.__class__.__name__}",
                    meta={"error": str(exc)[:300]},
                )
            )
            db.commit()
    finally:
        db.close()
        with _lock:
            _controls.pop(session_id, None)
