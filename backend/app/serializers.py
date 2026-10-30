from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    AlertEvidence,
    CaptureFile,
    DetectionModule,
    FlowRecord,
    IngestionJob,
    InvestigationCase,
    InvestigationNote,
    SecurityAlert,
    TrafficSource,
    User,
)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": {
            "code": user.role.code,
            "name": user.role.name,
            "permissions": user.role.permissions or [],
        },
        "is_demo": user.is_demo,
        "is_active": user.is_active,
        "last_login_at": iso(user.last_login_at),
    }


def alert_summary(alert: SecurityAlert, evidence: list[AlertEvidence] | None = None) -> dict:
    items = evidence or []
    return {
        "id": alert.id,
        "alert_code": alert.alert_code,
        "first_seen": iso(alert.first_seen),
        "last_seen": iso(alert.last_seen),
        "threat_class": alert.threat_class,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "confidence_type": alert.confidence_type,
        "detector_code": alert.detector_code,
        "source_ip": alert.source_ip,
        "source_port": alert.source_port,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "status": alert.status,
        "assignee": alert.assignee.name if alert.assignee else None,
        "assignee_id": alert.assignee_id,
        "data_source": alert.data_source,
        "environment": alert.environment,
        "scenario_id": alert.scenario_id,
        "summary": alert.summary,
        "recurrence": alert.recurrence,
        "flow_count": len(alert.flow_ids or []),
        "evidence_preview": [
            {"feature": item.feature, "observed": item.observed_value, "unit": item.unit}
            for item in items[:2]
        ],
    }


def alert_detail(alert: SecurityAlert, evidence: list[AlertEvidence], flows: list[FlowRecord]) -> dict:
    return {
        **alert_summary(alert, evidence),
        "evidence": [
            {
                "id": item.id,
                "kind": item.kind,
                "feature": item.feature,
                "observed_value": item.observed_value,
                "baseline_value": item.baseline_value,
                "unit": item.unit,
                "description": item.description,
                "flow_ids": item.flow_ids,
            }
            for item in evidence
        ],
        "baseline": alert.baseline,
        "flow_ids": alert.flow_ids,
        "flows": [flow_payload(flow) for flow in flows],
        "detection_reason": (alert.evidence or {}).get("detection_reason") or alert.summary,
    }


def flow_payload(flow: FlowRecord) -> dict:
    return {
        "id": flow.id,
        "reference": flow.reference,
        "ts": iso(flow.ts),
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "app_proto": flow.app_proto,
        "bytes_total": flow.bytes_total,
        "bytes_out": flow.bytes_out,
        "bytes_in": flow.bytes_in,
        "packets": flow.packets,
        "duration_ms": flow.duration_ms,
        "tcp_flags": flow.tcp_flags,
        "direction": flow.direction,
        "dns_query": flow.dns_query,
        "dns_qtype": flow.dns_qtype,
        "dns_rcode": flow.dns_rcode,
        "tls_sni": flow.tls_sni,
        "tls_ja3": flow.tls_ja3,
        "tls_version": flow.tls_version,
        "tls_cipher": flow.tls_cipher,
        "src_city": flow.src_city,
        "src_country": flow.src_country,
        "dst_city": flow.dst_city,
        "dst_country": flow.dst_country,
        "geo_source": flow.geo_source,
        "scenario_id": flow.scenario_id,
    }


def job_payload(job: IngestionJob, capture: CaptureFile | None = None) -> dict:
    return {
        "id": job.id,
        "reference": job.reference,
        "kind": job.kind,
        "environment": job.environment,
        "status": job.status,
        "progress": job.progress,
        "filename": job.original_filename,
        "size_bytes": job.size_bytes,
        "sha256": job.sha256,
        "records_total": job.records_total,
        "records_valid": job.records_valid,
        "records_rejected": job.records_rejected,
        "alerts_generated": job.alerts_generated,
        "error": job.error,
        "created_at": iso(job.created_at),
        "started_at": iso(job.started_at),
        "finished_at": iso(job.finished_at),
        "stats": job.stats or {},
        "capture": {
            "packet_count": capture.packet_count,
            "capture_start": iso(capture.capture_start),
            "capture_end": iso(capture.capture_end),
            "validation": capture.validation,
        }
        if capture
        else None,
    }


def source_payload(source: TrafficSource) -> dict:
    return {
        "id": source.id,
        "name": source.name,
        "kind": source.kind,
        "identifier": source.identifier,
        "status": source.status,
        "workspace_id": source.workspace_id,
        "last_seen_at": iso(source.last_seen_at),
        "last_record_at": iso(source.last_record_at),
        "records_total": source.records_total,
        "records_invalid": source.records_invalid,
        "records_dropped": source.records_dropped,
        "records_per_second": source.records_per_second,
        "avg_latency_ms": source.avg_latency_ms,
        "has_key": bool(source.api_key_hash),
        "config": source.config or {},
    }


def module_payload(module: DetectionModule) -> dict:
    return {
        "code": module.code,
        "name": module.name,
        "threat_class": module.threat_class,
        "technique": module.technique,
        "description": module.description,
        "status": module.status if module.enabled else "DISABLED",
        "enabled": module.enabled,
        "model_name": module.model_name,
        "version": module.version,
        "supported_inputs": module.supported_inputs,
        "feature_count": module.feature_count,
        "thresholds": module.thresholds,
        "last_run_at": iso(module.last_run_at),
        "detections_total": module.detections_total,
    }


def case_payload(case: InvestigationCase, notes: list[InvestigationNote], alert: SecurityAlert | None = None) -> dict:
    return {
        "id": case.id,
        "case_code": case.case_code,
        "alert_id": case.alert_id,
        "title": case.title,
        "status": case.status,
        "owner": case.owner.name if case.owner else None,
        "owner_id": case.owner_id,
        "created_at": iso(case.created_at),
        "updated_at": iso(case.updated_at),
        "notes": [
            {
                "id": note.id,
                "author": note.author.name if note.author else "Unknown",
                "body": note.body,
                "created_at": iso(note.created_at),
            }
            for note in notes
        ],
        "alert": alert_summary(alert) if alert else None,
    }
