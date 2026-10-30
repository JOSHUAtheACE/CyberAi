from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import (
    DetectionModule,
    FlowRecord,
    GeneratedReport,
    IngestionJob,
    SecurityAlert,
    Workspace,
    utcnow,
)

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
REPORT_KINDS = {
    "security_summary": "Network threat & traffic summary",
    "executive": "Executive security posture",
    "detector_performance": "Detector effectiveness review",
}


def resolve_period(period: str, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime, str]:
    now = utcnow()
    if period == "24h":
        return now - timedelta(hours=24), now, "Last 24 hours"
    if period == "7d":
        return now - timedelta(days=7), now, "Last 7 days"
    if period == "30d":
        return now - timedelta(days=30), now, "Last 30 days"
    if period == "custom" and start and end and start < end:
        return start, end, "Custom period"
    return now - timedelta(hours=24), now, "Last 24 hours"


def _bucket_key(ts: datetime, days: float) -> str:
    if days <= 2:
        return ts.strftime("%Y-%m-%dT%H:00")
    return ts.strftime("%Y-%m-%d")


def build_report(
    db: Session,
    *,
    workspace: Workspace,
    environment: str,
    kind: str,
    start: datetime,
    end: datetime,
    period_label: str,
) -> dict:
    flow_query = db.query(
        FlowRecord.ts, FlowRecord.direction, FlowRecord.protocol, FlowRecord.src_ip,
        FlowRecord.dst_ip, FlowRecord.bytes_total, FlowRecord.bytes_out, FlowRecord.bytes_in,
        FlowRecord.packets, FlowRecord.dst_port,
    ).filter(
        FlowRecord.workspace_id == workspace.id,
        FlowRecord.ts >= start,
        FlowRecord.ts <= end,
    )
    if environment != "*":
        flow_query = flow_query.filter(FlowRecord.environment == environment)
    flows = flow_query.limit(300_000).all()

    alerts_query = db.query(SecurityAlert).filter(
        SecurityAlert.workspace_id == workspace.id,
        SecurityAlert.first_seen >= start,
        SecurityAlert.first_seen <= end,
    )
    if environment != "*":
        alerts_query = alerts_query.filter(SecurityAlert.environment == environment)
    alerts = alerts_query.all()

    days = max(0.1, (end - start).total_seconds() / 86400)
    timeline: dict[str, dict] = defaultdict(lambda: {"bytes_in": 0, "bytes_out": 0, "flows": 0, "packets": 0})
    protocols: Counter = Counter()
    directions: Counter = Counter()
    top_sources: Counter = Counter()
    top_destinations: Counter = Counter()
    for flow in flows:
        key = _bucket_key(flow.ts, days)
        bucket = timeline[key]
        bucket["flows"] += 1
        bucket["packets"] += flow.packets or 0
        bucket["bytes_out"] += flow.bytes_out or 0
        bucket["bytes_in"] += flow.bytes_in or 0
        protocols[flow.protocol] += 1
        directions[flow.direction] += 1
        top_sources[flow.src_ip] += (flow.bytes_in or 0) + (flow.bytes_out or 0)
        top_destinations[flow.dst_ip] += (flow.bytes_in or 0) + (flow.bytes_out or 0)

    severity_counts = Counter(a.severity for a in alerts)
    category_counts = Counter(a.threat_class for a in alerts)
    detector_counts = Counter(a.detector_code for a in alerts)
    status_counts = Counter(a.status for a in alerts)
    alert_timeline: dict[str, dict] = defaultdict(lambda: {"total": 0, **{s: 0 for s in SEVERITIES}})
    for alert in alerts:
        key = _bucket_key(alert.first_seen, days)
        alert_timeline[key]["total"] += 1
        alert_timeline[key][alert.severity] = alert_timeline[key].get(alert.severity, 0) + 1

    modules = {m.code: m for m in db.query(DetectionModule).all()}
    fp_count = sum(1 for a in alerts if a.status == "FALSE_POSITIVE")
    reviewed = sum(1 for a in alerts if a.status in {"CLOSED", "FALSE_POSITIVE"})
    avg_confidence = (
        round(sum(a.confidence for a in alerts) / len(alerts), 4) if alerts else None
    )

    jobs = (
        db.query(IngestionJob)
        .filter(
            IngestionJob.workspace_id == workspace.id,
            IngestionJob.created_at >= start,
            IngestionJob.created_at <= end,
            IngestionJob.status == "COMPLETE",
        )
        .all()
    )
    records_processed = sum(j.records_valid for j in jobs)
    detection_ms = [j.stats.get("detection_ms") for j in jobs if j.stats.get("detection_ms")]
    processing_ms = [j.stats.get("processing_ms") for j in jobs if j.stats.get("processing_ms")]
    duration_s = max(1.0, (end - start).total_seconds())

    traffic_series = [
        {
            "bucket": key,
            **{
                "bytes_in": round(value["bytes_in"] / 1_048_576, 2),
                "bytes_out": round(value["bytes_out"] / 1_048_576, 2),
                "flows": value["flows"],
                "packets": value["packets"],
            },
        }
        for key, value in sorted(timeline.items())
    ]

    summary = {
        "generated_at": utcnow().isoformat() + "Z",
        "workspace": {"name": workspace.name, "slug": workspace.slug, "environment": workspace.environment},
        "environment": environment,
        "period": {"label": period_label, "start": start.isoformat() + "Z", "end": end.isoformat() + "Z"},
        "query": {
            "description": (
                "flow_records and security_alerts filtered by workspace, environment and first-seen "
                "timestamp; aggregates computed server-side at generation time."
            ),
            "record_limit": 300_000,
            "data_source": "passive telemetry stored in the monitoring platform",
        },
        "totals": {
            "flows": len(flows),
            "bytes_total": sum((f.bytes_in or 0) + (f.bytes_out or 0) for f in flows),
            "packets": sum(f.packets or 0 for f in flows),
            "unique_sources": len({f.src_ip for f in flows}),
            "unique_destinations": len({f.dst_ip for f in flows}),
            "alerts": len(alerts),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "false_positives": fp_count,
            "avg_confidence": avg_confidence,
            "flows_per_second": round(len(flows) / duration_s, 3),
        },
        "traffic_timeline": traffic_series,
        "protocol_distribution": [{"protocol": k, "count": v} for k, v in protocols.most_common()],
        "direction_distribution": [{"direction": k, "count": v} for k, v in directions.most_common()],
        "severity_distribution": [{"severity": s, "count": severity_counts.get(s, 0)} for s in SEVERITIES],
        "category_distribution": [{"category": k, "count": v} for k, v in category_counts.most_common()],
        "alert_timeline": [
            {"bucket": k, **v} for k, v in sorted(alert_timeline.items())
        ],
        "top_sources": [{"ip": k, "bytes": v} for k, v in top_sources.most_common(8)],
        "top_destinations": [{"ip": k, "bytes": v} for k, v in top_destinations.most_common(8)],
        "detector_performance": [
            {
                "detector_code": code,
                "name": modules[code].name if code in modules else code,
                "alerts": detector_counts.get(code, 0),
                "avg_confidence": round(
                    sum(a.confidence for a in alerts if a.detector_code == code)
                    / max(1, detector_counts.get(code, 0)),
                    3,
                )
                if detector_counts.get(code)
                else None,
                "false_positives": sum(
                    1 for a in alerts if a.detector_code == code and a.status == "FALSE_POSITIVE"
                ),
                "confidence_type": next(
                    (a.confidence_type for a in alerts if a.detector_code == code), None
                ),
                "technique": modules[code].technique if code in modules else None,
            }
            for code in sorted(detector_counts)
        ],
        "review": {
            "status_counts": [{"status": k, "count": v} for k, v in status_counts.most_common()],
            "reviewed": reviewed,
            "false_positive_rate_on_reviewed": round(fp_count / reviewed, 4) if reviewed else None,
        },
        "processing": {
            "completed_jobs": len(jobs),
            "records_processed": records_processed,
            "avg_processing_ms": round(sum(processing_ms) / len(processing_ms), 2) if processing_ms else None,
            "avg_detection_ms": round(sum(detection_ms) / len(detection_ms), 2) if detection_ms else None,
            "note": (
                "Processing figures come from completed ingestion jobs in the selected period. "
                "Behavioural detections may additionally require longer observation windows."
            ),
        },
        "limitations": [
            "IP geolocation approximates network registration, not physical device location.",
            "External enrichment is disabled unless explicitly configured and approved.",
            "Behavioural detections depend on the fields present in the ingested telemetry.",
        ],
    }
    return summary


def create_report(
    db: Session,
    *,
    workspace: Workspace,
    environment: str,
    kind: str,
    period: str,
    start: datetime | None,
    end: datetime | None,
    created_by: int | None,
) -> GeneratedReport:
    period_start, period_end, label = resolve_period(period, start, end)
    summary = build_report(
        db,
        workspace=workspace,
        environment=environment,
        kind=kind,
        start=period_start,
        end=period_end,
        period_label=label,
    )
    reference = f"RPT-{utcnow().strftime('%Y%m%d')}-{(db.query(func.max(GeneratedReport.id)).scalar() or 0) + 1:04d}"
    report = GeneratedReport(
        reference=reference,
        workspace_id=workspace.id,
        environment=environment,
        kind=kind,
        title=f"{REPORT_KINDS.get(kind, REPORT_KINDS['security_summary'])} — {label}",
        period_start=period_start,
        period_end=period_end,
        params={"period": period, "kind": kind},
        status="READY",
        summary=summary,
        created_by=created_by,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def report_csv(summary: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["SENTINEL AI — generated report"])
    writer.writerow(["Generated at", summary["generated_at"]])
    writer.writerow(["Workspace", summary["workspace"]["name"]])
    writer.writerow(["Environment", summary["environment"]])
    writer.writerow(["Period", summary["period"]["label"], summary["period"]["start"], summary["period"]["end"]])
    writer.writerow([])
    writer.writerow(["Totals"])
    for key, value in summary["totals"].items():
        writer.writerow([key, value])
    writer.writerow([])
    writer.writerow(["Traffic timeline (MiB)"])
    writer.writerow(["bucket", "bytes_in_mib", "bytes_out_mib", "flows", "packets"])
    for row in summary["traffic_timeline"]:
        writer.writerow([row["bucket"], row["bytes_in"], row["bytes_out"], row["flows"], row["packets"]])
    writer.writerow([])
    writer.writerow(["Protocol distribution"])
    writer.writerow(["protocol", "count"])
    for row in summary["protocol_distribution"]:
        writer.writerow([row["protocol"], row["count"]])
    writer.writerow([])
    writer.writerow(["Severity distribution"])
    writer.writerow(["severity", "count"])
    for row in summary["severity_distribution"]:
        writer.writerow([row["severity"], row["count"]])
    writer.writerow([])
    writer.writerow(["Threat categories"])
    writer.writerow(["category", "count"])
    for row in summary["category_distribution"]:
        writer.writerow([row["category"], row["count"]])
    writer.writerow([])
    writer.writerow(["Detector performance"])
    writer.writerow(["detector", "alerts", "avg_confidence", "false_positives", "confidence_type"])
    for row in summary["detector_performance"]:
        writer.writerow([
            row["name"], row["alerts"], row["avg_confidence"], row["false_positives"], row["confidence_type"],
        ])
    return buffer.getvalue()
