from __future__ import annotations

from collections import Counter
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import detectors
from .geo import classify_direction, lookup_geo
from .models import (
    AlertEvidence,
    DetectionModule,
    FeatureObservation,
    FlowRecord,
    IngestionJob,
    SecurityAlert,
    SystemEvent,
    User,
    Workspace,
    utcnow,
)
from .parsing import FlowIn
from .streaming import bus
from .text import plural


def insert_flows(
    db: Session,
    *,
    workspace: Workspace,
    environment: str,
    flows: list[FlowIn],
    job_id: int | None = None,
    source_id: int | None = None,
    demo: bool = False,
    batch_size: int = 2000,
) -> list[FlowRecord]:
    records: list[FlowRecord] = []
    for flow in flows:
        direction = classify_direction(flow.src_ip, flow.dst_ip, workspace.internal_cidrs or [])
        declared = (flow.meta or {}).get("declared_direction")
        if declared in {"inbound", "outbound", "internal", "transit"}:
            direction = declared
        src_geo = lookup_geo(flow.src_ip, demo=demo) if demo else {}
        dst_geo = lookup_geo(flow.dst_ip, demo=demo) if demo else {}
        record = FlowRecord(
            reference="",
            workspace_id=workspace.id,
            environment=environment,
            job_id=job_id,
            source_id=source_id,
            ts=flow.ts,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            app_proto=flow.app_proto,
            bytes_total=flow.bytes_total,
            bytes_out=flow.bytes_out,
            bytes_in=flow.bytes_in,
            packets=flow.packets,
            duration_ms=flow.duration_ms,
            tcp_flags=flow.tcp_flags,
            direction=direction,
            dns_query=flow.dns_query,
            dns_qtype=flow.dns_qtype,
            dns_rcode=flow.dns_rcode,
            tls_sni=flow.tls_sni,
            tls_ja3=flow.tls_ja3,
            tls_version=flow.tls_version,
            tls_cipher=flow.tls_cipher,
            quic=flow.quic,
            src_country=src_geo.get("country"),
            src_city=src_geo.get("city"),
            src_lat=src_geo.get("lat"),
            src_lon=src_geo.get("lon"),
            dst_country=dst_geo.get("country"),
            dst_city=dst_geo.get("city"),
            dst_lat=dst_geo.get("lat"),
            dst_lon=dst_geo.get("lon"),
            geo_source=src_geo.get("geo_source") or dst_geo.get("geo_source"),
            scenario_id=flow.scenario_id,
            label=flow.label,
            meta=flow.meta,
        )
        db.add(record)
        records.append(record)
    db.flush()
    for record in records:
        record.reference = f"FLOW-{record.id:07d}"
    db.flush()
    return records


def _next_alert_code(db: Session) -> str:
    max_id = db.query(func.max(SecurityAlert.id)).scalar() or 0
    return f"ALT-{max_id + 1:06d}"


def _persist_detection(
    db: Session,
    *,
    workspace: Workspace,
    environment: str,
    detection: detectors.Detection,
    data_source: str,
) -> tuple[SecurityAlert, bool]:
    if detection.dedup_key:
        existing = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.workspace_id == workspace.id,
                SecurityAlert.environment == environment,
                SecurityAlert.detector_code == detection.detector_code,
                SecurityAlert.dedup_key == detection.dedup_key,
                SecurityAlert.status.notin_(["CLOSED", "FALSE_POSITIVE"]),
            )
            .order_by(SecurityAlert.id.desc())
            .first()
        )
        if existing:
            existing.last_seen = max(existing.last_seen, detection.last_seen)
            existing.recurrence += 1
            existing.evidence = detection.__dict__["evidence"] and {
                "items": [e.__dict__ for e in detection.evidence],
                "detection_reason": detection.summary,
            } or existing.evidence
            return existing, False

    alert = SecurityAlert(
        alert_code=_next_alert_code(db),
        workspace_id=workspace.id,
        environment=environment,
        first_seen=detection.first_seen,
        last_seen=detection.last_seen,
        threat_class=detection.threat_class,
        severity=detection.severity,
        confidence=detection.confidence,
        confidence_type=detection.confidence_type,
        detector_code=detection.detector_code,
        model_version_id=detection.model_version_id,
        source_ip=detection.source_ip,
        source_port=detection.source_port,
        dest_ip=detection.dest_ip,
        dest_port=detection.dest_port,
        protocol=detection.protocol,
        status="OPEN",
        data_source=data_source,
        scenario_id=detection.scenario_id,
        summary=detection.summary,
        evidence={
            "items": [e.__dict__ for e in detection.evidence],
            "detection_reason": detection.summary,
        },
        flow_ids=detection.flow_ids,
        baseline=detection.baseline,
        dedup_key=detection.dedup_key,
    )
    db.add(alert)
    db.flush()
    alert.alert_code = f"ALT-{alert.id:06d}"
    for item in detection.evidence:
        db.add(
            AlertEvidence(
                alert_id=alert.id,
                kind="feature",
                feature=item.feature,
                observed_value=item.observed,
                baseline_value=item.baseline,
                unit=item.unit,
                description=item.description,
                flow_ids=item.flow_ids,
            )
        )
    db.add(
        FeatureObservation(
            environment=environment,
            detector_code=detection.detector_code,
            entity=f"{detection.source_ip}->{detection.dest_ip}",
            window_start=detection.first_seen,
            window_end=detection.last_seen,
            features={e.feature: e.observed for e in detection.evidence},
        )
    )
    return alert, True


def run_detection(
    db: Session,
    *,
    workspace: Workspace,
    environment: str,
    flows: list[FlowRecord],
    data_source: str,
    detector_codes: set[str] | None = None,
    actor: User | None = None,
    broadcast: bool = True,
) -> dict:
    modules = {
        m.code: m
        for m in db.query(DetectionModule).filter(DetectionModule.enabled.is_(True)).all()
    }
    if detector_codes:
        modules = {code: m for code, m in modules.items() if code in detector_codes}

    created_alerts: list[SecurityAlert] = []
    updated = 0
    per_detector: dict[str, int] = {}
    coverage: dict = {}

    for code, module in modules.items():
        thresholds = module.thresholds or {}
        if code == "exfiltration_detector":
            detections, exfil_coverage = detectors.detect_exfiltration(flows, thresholds)
            coverage["exfiltration_detector"] = exfil_coverage
        else:
            fn = detectors.DETECTOR_FUNCTIONS.get(code)
            if not fn:
                continue
            detections = fn(flows, thresholds)
        per_detector[code] = len(detections)
        module.last_run_at = utcnow()
        for detection in detections:
            alert, is_new = _persist_detection(
                db,
                workspace=workspace,
                environment=environment,
                detection=detection,
                data_source=data_source,
            )
            if is_new:
                created_alerts.append(alert)
                module.detections_total = (module.detections_total or 0) + 1
            else:
                updated += 1

    db.flush()

    if not coverage.get("exfiltration_detector"):
        directional = sum(1 for f in flows if f.direction == "outbound")
        coverage["exfiltration_detector"] = {
            "directional_flows": directional,
            "flows_total": len(flows),
            "direction_available": directional > 0,
        }

    if broadcast:
        for alert in created_alerts:
            bus.publish(
                environment,
                {
                    "type": "alert.created",
                    "alert_id": alert.id,
                    "alert_code": alert.alert_code,
                    "severity": alert.severity,
                    "threat_class": alert.threat_class,
                    "source_ip": alert.source_ip,
                    "dest_ip": alert.dest_ip,
                    "confidence": alert.confidence,
                    "first_seen": alert.first_seen.isoformat() + "Z",
                },
            )
        bus.publish(
            environment,
            {
                "type": "detection.completed",
                "flows_processed": len(flows),
                "alerts_created": len(created_alerts),
                "alerts_updated": updated,
                "detectors": per_detector,
                "at": utcnow().isoformat() + "Z",
            },
        )

    if created_alerts:
        severity_counts = Counter(a.severity for a in created_alerts)
        db.add(
            SystemEvent(
                level="WARN" if severity_counts.get("high") or severity_counts.get("critical") else "INFO",
                category="detection",
                message=(
                    f"{len(created_alerts)} new security {plural(len(created_alerts), 'alert')} generated across "
                    f"{len([c for c, n in per_detector.items() if n])} "
                    f"{plural(len([c for c, n in per_detector.items() if n]), 'detector')}."
                ),
                meta={"severity": dict(severity_counts), "detectors": per_detector},
            )
        )
    return {
        "alerts_created": len(created_alerts),
        "alerts_updated": updated,
        "per_detector": per_detector,
        "coverage": coverage,
        "alert_ids": [a.id for a in created_alerts],
    }


def finalize_ingestion_job(
    db: Session,
    job: IngestionJob,
    *,
    valid: int,
    rejected: int,
    alerts: int,
    stats: dict,
) -> None:
    job.status = "COMPLETE"
    job.progress = 100
    job.records_total = valid + rejected
    job.records_valid = valid
    job.records_rejected = rejected
    job.alerts_generated = alerts
    job.finished_at = utcnow()
    job.stats = stats
    db.add(
        SystemEvent(
            category="ingestion",
            message=f"Ingestion {job.reference} completed with {valid:,} valid {plural(valid, 'record')}.",
            meta={"job": job.reference, "rejected": rejected, "alerts": alerts},
        )
    )
