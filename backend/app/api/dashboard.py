from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_permissions
from ..geo import classify_direction, geo_status, is_internal, is_public_ip
from ..models import (
    AlertEvidence,
    DetectionModule,
    FlowRecord,
    IngestionJob,
    SecurityAlert,
    TrafficSource,
    User,
    Workspace,
    utcnow,
)
from ..serializers import alert_summary, iso

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

RANGE_OPTIONS = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def get_workspace_or_404(db: Session, slug: str | None) -> Workspace:
    if slug:
        ws = db.query(Workspace).filter(Workspace.slug == slug).first()
    else:
        ws = db.query(Workspace).order_by(Workspace.id).first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


def window(range_key: str, start: str | None, end: str | None) -> tuple[datetime, datetime, str]:
    now = utcnow()
    if range_key == "custom" and start and end:
        try:
            s = datetime.fromisoformat(start.replace("Z", "+00:00")).replace(tzinfo=None)
            e = datetime.fromisoformat(end.replace("Z", "+00:00")).replace(tzinfo=None)
            if s < e:
                return s, e, "Custom period"
        except ValueError:
            pass
    delta = RANGE_OPTIONS.get(range_key, timedelta(hours=24))
    label = {"1h": "Last 60 minutes", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days"}.get(range_key, "Last 24 hours")
    return now - delta, now, label


def _bucket_size(start: datetime, end: datetime) -> tuple[int, str]:
    span = (end - start).total_seconds()
    if span <= 6 * 3600:
        return 300, "5-minute"
    if span <= 48 * 3600:
        return 3600, "hourly"
    if span <= 10 * 86400:
        return 6 * 3600, "6-hour"
    return 86400, "daily"


def _floor(dt: datetime, seconds: int) -> datetime:
    ts = int(dt.timestamp())
    return datetime.fromtimestamp(ts - ts % seconds)


def _bucket_label(dt: datetime, seconds: int) -> str:
    return dt.strftime("%Y-%m-%dT%H:%MZ") if seconds < 86400 else dt.strftime("%Y-%m-%d")


def _bucket_series(start: datetime, end: datetime, seconds: int) -> list[str]:
    labels = []
    cursor = _floor(start, seconds)
    while cursor <= end:
        labels.append(_bucket_label(cursor, seconds))
        cursor += timedelta(seconds=seconds)
    return labels


def _alert_query(db: Session, ws: Workspace, start: datetime, end: datetime):
    return db.query(SecurityAlert).filter(
        SecurityAlert.workspace_id == ws.id,
        SecurityAlert.environment == ws.environment,
        SecurityAlert.first_seen >= start,
        SecurityAlert.first_seen <= end,
    )


def _metrics(db: Session, ws: Workspace, start: datetime, end: datetime) -> dict:
    flow_row = (
        db.query(
            func.count(FlowRecord.id),
            func.coalesce(func.sum(FlowRecord.bytes_in), 0),
            func.coalesce(func.sum(FlowRecord.bytes_out), 0),
            func.coalesce(func.sum(FlowRecord.packets), 0),
            func.count(func.distinct(FlowRecord.src_ip)),
            func.coalesce(func.avg(FlowRecord.duration_ms), 0),
        )
        .filter(
            FlowRecord.workspace_id == ws.id,
            FlowRecord.environment == ws.environment,
            FlowRecord.ts >= start,
            FlowRecord.ts <= end,
        )
        .one()
    )
    alerts = _alert_query(db, ws, start, end)
    alert_count = alerts.count()
    critical = alerts.filter(SecurityAlert.severity == "critical").count()
    high = alerts.filter(SecurityAlert.severity == "high").count()
    duration = max(1.0, (end - start).total_seconds())
    return {
        "flows": int(flow_row[0] or 0),
        "bytes_in": int(flow_row[1] or 0),
        "bytes_out": int(flow_row[2] or 0),
        "packets": int(flow_row[3] or 0),
        "unique_sources": int(flow_row[4] or 0),
        "avg_duration_ms": round(float(flow_row[5] or 0), 1),
        "alerts": alert_count,
        "critical": critical,
        "high": high,
        "duration": duration,
    }


def _delta(current: float, previous: float | None) -> dict | None:
    if previous is None or previous == 0:
        return None
    change = (current - previous) / previous * 100
    return {"value": round(change, 1), "direction": "up" if change > 0 else "down" if change < 0 else "flat"}


def _kpi(key, label, value, unit, help_text, comparison=None, updated=None, note=None):
    return {
        "key": key,
        "label": label,
        "value": value,
        "unit": unit,
        "help": help_text,
        "comparison": comparison,
        "updated_at": updated,
        "note": note,
    }


@router.get("/overview")
def overview(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    span = w_end - w_start
    current = _metrics(db, ws, w_start, w_end)
    previous = _metrics(db, ws, w_start - span, w_start)
    earliest_flow = (
        db.query(func.min(FlowRecord.ts))
        .filter(FlowRecord.workspace_id == ws.id, FlowRecord.environment == ws.environment)
        .scalar()
    )
    comparable_previous = bool(earliest_flow and earliest_flow <= w_start - span)
    now = utcnow()

    last_flow = (
        db.query(FlowRecord.ts)
        .filter(FlowRecord.workspace_id == ws.id, FlowRecord.environment == ws.environment)
        .order_by(FlowRecord.ts.desc())
        .first()
    )
    modules = db.query(DetectionModule).filter(DetectionModule.enabled.is_(True)).count()
    sources = db.query(TrafficSource).filter(TrafficSource.workspace_id == ws.id).all()
    dropped = sum(s.records_dropped for s in sources)

    jobs = (
        db.query(IngestionJob)
        .filter(IngestionJob.workspace_id == ws.id, IngestionJob.status == "COMPLETE")
        .order_by(IngestionJob.finished_at.desc())
        .limit(10)
        .all()
    )
    job_latency = [j.stats.get("detection_ms") for j in jobs if j.stats.get("detection_ms")]
    latency_value = round(statistics.median(job_latency), 1) if job_latency else None

    bps_in = current["bytes_in"] * 8 / current["duration"] / 1_000_000
    bps_out = current["bytes_out"] * 8 / current["duration"] / 1_000_000
    prev_bps_in = previous["bytes_in"] * 8 / previous["duration"] / 1_000_000
    prev_bps_out = previous["bytes_out"] * 8 / previous["duration"] / 1_000_000
    throughput = current["flows"] / current["duration"]
    prev_throughput = previous["flows"] / previous["duration"]

    kpis = [
        _kpi("flows", "Flows processed", current["flows"], "flows",
             "Count of normalised flow records observed in the selected period.",
             _delta(current["flows"], previous["flows"] if comparable_previous else None), iso(last_flow[0]) if last_flow else None),
        _kpi("bandwidth_in", "Incoming bandwidth", round(bps_in, 2), "Mbps",
             "Captured inbound bytes × 8 ÷ observation seconds. Directional fields come from the collector.",
             _delta(bps_in, prev_bps_in if comparable_previous and previous["bytes_in"] else None), iso(now)),
        _kpi("bandwidth_out", "Outgoing bandwidth", round(bps_out, 2), "Mbps",
             "Captured outbound bytes × 8 ÷ observation seconds.",
             _delta(bps_out, prev_bps_out if comparable_previous and previous["bytes_out"] else None), iso(now)),
        _kpi("pps", "Packets per second", round(current["packets"] / current["duration"], 2), "pps",
             "Total captured packets ÷ observation seconds.", _delta(current["packets"], previous["packets"] if comparable_previous else None), iso(now)),
        _kpi("alerts", "Security alerts", current["alerts"], "alerts",
             "Alerts whose first-seen timestamp falls inside the selected period.",
             _delta(current["alerts"], previous["alerts"] if comparable_previous else None), iso(now)),
        _kpi("critical", "Critical alerts", current["critical"], "alerts",
             "Alerts with severity “critical” in the selected period. Severity is independent of confidence.",
             _delta(current["critical"], previous["critical"] if comparable_previous else None), iso(now)),
        _kpi("modules", "Active detection modules", modules, "modules",
             "Detectors enabled for this workspace. Disabled modules do not process telemetry.", None, iso(now)),
        _kpi("throughput", "Processing throughput", round(throughput, 3), "flows/s",
             "Records normalised per second of the observation window (pipeline throughput, not a benchmark).",
             _delta(throughput, prev_throughput if comparable_previous and previous["flows"] else None), iso(now)),
        _kpi("dropped", "Capture loss / dropped", dropped, "records",
             "Records reported dropped by configured collectors. Zero when no collector has reported drops.",
             None, iso(now)),
        _kpi("latency", "Processing latency (p50)", latency_value, "ms",
             "Median detection-stage duration reported by completed ingestion jobs. Shown only when measured.",
             None, iso(now), note="Requires completed ingestion jobs with detection timings in this workspace."),
    ]

    recent_alerts = _alert_query(db, ws, w_start, w_end).order_by(SecurityAlert.first_seen.desc()).limit(6).all()
    alert_items = []
    for alert in recent_alerts:
        evidence = db.query(AlertEvidence).filter(AlertEvidence.alert_id == alert.id).limit(2).all()
        alert_items.append(alert_summary(alert, evidence))

    insight_payload = _build_insights(db, ws, w_start, w_end)

    return {
        "workspace": {"id": ws.id, "slug": ws.slug, "name": ws.name, "environment": ws.environment},
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end)},
        "has_data": current["flows"] > 0 or current["alerts"] > 0,
        "kpis": kpis,
        "totals": current,
        "previous": previous,
        "recent_alerts": alert_items,
        "insights": insight_payload["insights"][:3],
        "sources": {
            "total": len(sources),
            "connected": sum(1 for s in sources if s.status == "CONNECTED"),
            "disconnected": sum(1 for s in sources if s.status != "CONNECTED"),
        },
        "generated_at": iso(utcnow()),
        "known_limitations": [
            "Metrics are computed only from stored telemetry; no values are synthesised.",
            "Percent changes are omitted unless the preceding comparison period is fully covered by stored telemetry.",
        ],
    }


@router.get("/traffic")
def traffic(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    bucket_seconds, bucket_label = _bucket_size(w_start, w_end)
    rows = (
        db.query(
            FlowRecord.ts, FlowRecord.protocol, FlowRecord.src_ip, FlowRecord.dst_ip,
            FlowRecord.dst_port, FlowRecord.bytes_in, FlowRecord.bytes_out,
            FlowRecord.packets, FlowRecord.duration_ms, FlowRecord.direction,
        )
        .filter(
            FlowRecord.workspace_id == ws.id,
            FlowRecord.environment == ws.environment,
            FlowRecord.ts >= w_start,
            FlowRecord.ts <= w_end,
        )
        .order_by(FlowRecord.ts.asc())
        .limit(200_000)
        .all()
    )

    series = {
        label: {"bytes_in": 0, "bytes_out": 0, "packets": 0, "flows": 0}
        for label in _bucket_series(w_start, w_end, bucket_seconds)
    }
    protocols: Counter = Counter()
    ports: Counter = Counter()
    sources: Counter = Counter()
    destinations: Counter = Counter()
    durations = {"< 1s": 0, "1–10s": 0, "10–60s": 0, "1–5m": 0, "5–30m": 0, "> 30m": 0}
    directions: Counter = Counter()
    for row in rows:
        key = _bucket_label(_floor(row.ts, bucket_seconds), bucket_seconds)
        bucket = series.setdefault(key, {"bytes_in": 0, "bytes_out": 0, "packets": 0, "flows": 0})
        bucket["bytes_in"] += row.bytes_in or 0
        bucket["bytes_out"] += row.bytes_out or 0
        bucket["packets"] += row.packets or 0
        bucket["flows"] += 1
        protocols[row.protocol] += 1
        directions[row.direction] += 1
        if row.dst_port:
            ports[str(row.dst_port)] += 1
        sources[row.src_ip] += (row.bytes_in or 0) + (row.bytes_out or 0)
        destinations[row.dst_ip] += (row.bytes_in or 0) + (row.bytes_out or 0)
        seconds = (row.duration_ms or 0) / 1000
        if seconds < 1:
            durations["< 1s"] += 1
        elif seconds < 10:
            durations["1–10s"] += 1
        elif seconds < 60:
            durations["10–60s"] += 1
        elif seconds < 300:
            durations["1–5m"] += 1
        elif seconds < 1800:
            durations["5–30m"] += 1
        else:
            durations["> 30m"] += 1

    timeline = [
        {
            "bucket": key,
            "bytes_in_mib": round(value["bytes_in"] / 1_048_576, 3),
            "bytes_out_mib": round(value["bytes_out"] / 1_048_576, 3),
            "packets": value["packets"],
            "flows": value["flows"],
            "pps": round(value["packets"] / bucket_seconds, 2),
        }
        for key, value in series.items()
    ]

    total_bytes = sum((r.bytes_in or 0) + (r.bytes_out or 0) for r in rows)
    return {
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end), "bucket": bucket_label},
        "has_data": bool(rows),
        "timeline": timeline,
        "protocols": [{"protocol": k, "count": v, "share": round(v / max(1, len(rows)), 4)} for k, v in protocols.most_common()],
        "directions": [{"direction": k, "count": v} for k, v in directions.most_common()],
        "top_sources": [{"ip": k, "bytes": v} for k, v in sources.most_common(8)],
        "top_destinations": [{"ip": k, "bytes": v} for k, v in destinations.most_common(8)],
        "top_ports": [{"port": k, "count": v} for k, v in ports.most_common(10)],
        "duration_distribution": [{"bucket": k, "count": v} for k, v in durations.items()],
        "summary": {
            "flows": len(rows),
            "bytes_total": total_bytes,
            "packets": sum(r.packets or 0 for r in rows),
            "avg_flow_bytes": round(total_bytes / max(1, len(rows)), 1),
        },
        "truncated": len(rows) >= 200_000,
    }


@router.get("/threats")
def threats(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    bucket_seconds, _ = _bucket_size(w_start, w_end)
    alerts = _alert_query(db, ws, w_start, w_end).order_by(SecurityAlert.first_seen.asc()).all()
    severity_counts = Counter(a.severity for a in alerts)
    category_counts = Counter(a.threat_class for a in alerts)
    detector_counts = Counter(a.detector_code for a in alerts)
    sources = Counter(a.source_ip for a in alerts)
    destinations = Counter(a.dest_ip for a in alerts)
    pairs = Counter((a.source_ip, a.dest_ip) for a in alerts)
    pair_severity: dict[tuple[str, str], str] = {}
    for alert in alerts:
        key = (alert.source_ip, alert.dest_ip)
        if SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(pair_severity.get(key, "informational"), 0):
            pair_severity[key] = alert.severity

    labels = _bucket_series(w_start, w_end, bucket_seconds)
    trend = {label_: {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0} for label_ in labels}
    for alert in alerts:
        key = _bucket_label(_floor(alert.first_seen, bucket_seconds), bucket_seconds)
        bucket = trend.setdefault(key, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0})
        bucket["total"] += 1
        bucket[alert.severity] = bucket.get(alert.severity, 0) + 1

    critical_alerts = [
        {
            "id": a.id,
            "alert_code": a.alert_code,
            "first_seen": iso(a.first_seen),
            "threat_class": a.threat_class,
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip,
            "status": a.status,
        }
        for a in sorted(alerts, key=lambda a: a.first_seen, reverse=True)
        if a.severity in {"critical", "high"}
    ][:12]

    insight_payload = _build_insights(db, ws, w_start, w_end)
    return {
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end)},
        "has_data": bool(alerts),
        "total_alerts": len(alerts),
        "severity_distribution": [
            {"severity": s, "count": severity_counts.get(s, 0)}
            for s in ["critical", "high", "medium", "low", "informational"]
        ],
        "category_distribution": [{"category": k, "count": v} for k, v in category_counts.most_common()],
        "detector_distribution": [{"detector": k, "count": v} for k, v in detector_counts.most_common()],
        "trend": [{"bucket": k, **v} for k, v in trend.items()],
        "critical_timeline": critical_alerts,
        "top_sources": [{"ip": k, "alerts": v} for k, v in sources.most_common(6)],
        "top_destinations": [{"ip": k, "alerts": v} for k, v in destinations.most_common(6)],
        "relationships": [
            {"source": k[0], "destination": k[1], "alerts": v, "severity": pair_severity.get(k, "informational")}
            for k, v in pairs.most_common(20)
        ],
        "insights": insight_payload["insights"],
        "note": "Severity reflects potential operational impact; confidence describes evidence strength.",
    }


def _build_insights(db: Session, ws: Workspace, start: datetime, end: datetime) -> dict:
    alerts = (
        _alert_query(db, ws, start, end)
        .order_by(SecurityAlert.first_seen.desc())
        .limit(40)
        .all()
    )
    insights = []
    for alert in alerts[:6]:
        evidence = db.query(AlertEvidence).filter(AlertEvidence.alert_id == alert.id).limit(5).all()
        evidence_text = "; ".join(
            f"{item.feature.replace('_', ' ')}: {item.observed_value}"
            + (f" (baseline {item.baseline_value})" if item.baseline_value else "")
            for item in evidence[:3]
        )
        insights.append(
            {
                "id": f"insight-{alert.id}",
                "title": alert.threat_class.replace("_", " "),
                "body": (
                    f"{alert.summary} Observed features — {evidence_text}. "
                    f"Generated by {alert.detector_code} from {alert.data_source}."
                ),
                "severity": alert.severity,
                "confidence": alert.confidence,
                "confidence_type": alert.confidence_type,
                "alert_ids": [alert.alert_code],
                "alert_id": alert.id,
                "flow_ids": (alert.flow_ids or [])[:8],
                "detector": alert.detector_code,
                "window": {"start": iso(alert.first_seen), "end": iso(alert.last_seen)},
                "data_source": alert.data_source,
                "grounded": True,
            }
        )
    if not insights:
        insight = {
            "id": "insight-empty",
            "title": "No detections in the selected window",
            "body": (
                "No alerts were generated for this workspace and period. This may reflect an absence "
                "of matching behaviour, missing telemetry fields, or disconnected collectors. "
                "No synthetic findings are substituted."
            ),
            "severity": "informational",
            "alert_ids": [],
            "flow_ids": [],
            "detector": None,
            "window": {"start": iso(start), "end": iso(end)},
            "data_source": "workspace_telemetry",
            "grounded": False,
        }
        insights = [insight]
    return {
        "insights": insights,
        "notice": (
            "Summaries are deterministic and traceable to stored evidence. The platform does not infer "
            "attribution, motive, malware identity or confirmed compromise."
        ),
    }


@router.get("/geo")
def geo_map(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    protocol: str | None = None,
    threat_only: bool = False,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    query = db.query(FlowRecord).filter(
        FlowRecord.workspace_id == ws.id,
        FlowRecord.environment == ws.environment,
        FlowRecord.ts >= w_start,
        FlowRecord.ts <= w_end,
    )
    if protocol and protocol.upper() in {"TCP", "UDP", "ICMP"}:
        query = query.filter(FlowRecord.protocol == protocol.upper())
    rows = query.order_by(FlowRecord.ts.desc()).limit(60_000).all()
    alerts = _alert_query(db, ws, w_start, w_end).all()
    alert_pairs: dict[tuple[str, str], str] = {}
    for alert in alerts:
        key = (alert.source_ip, alert.dest_ip)
        if SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(alert_pairs.get(key, "informational"), 0):
            alert_pairs[key] = alert.severity

    arcs: dict[tuple, dict] = {}
    nodes: dict[tuple, dict] = {}
    unknown_src = 0
    unknown_dst = 0
    for flow in rows:
        sev = alert_pairs.get((flow.src_ip, flow.dst_ip))
        if threat_only and not sev:
            continue
        if flow.src_lat is None or flow.dst_lat is None:
            if flow.src_lat is None:
                unknown_src += 1
            if flow.dst_lat is None:
                unknown_dst += 1
            continue
        key = (
            round(flow.src_lat, 3), round(flow.src_lon, 3), flow.src_city or "unknown",
            round(flow.dst_lat, 3), round(flow.dst_lon, 3), flow.dst_city or "unknown",
        )
        arc = arcs.setdefault(
            key,
            {
                "startLat": flow.src_lat,
                "startLng": flow.src_lon,
                "endLat": flow.dst_lat,
                "endLng": flow.dst_lon,
                "srcCity": flow.src_city,
                "srcCountry": flow.src_country,
                "dstCity": flow.dst_city,
                "dstCountry": flow.dst_country,
                "count": 0,
                "bytes": 0,
                "severity": None,
                "flow_ids": [],
                "geo_source": flow.geo_source,
            },
        )
        arc["count"] += 1
        arc["bytes"] += (flow.bytes_in or 0) + (flow.bytes_out or 0)
        if len(arc["flow_ids"]) < 8:
            arc["flow_ids"].append(flow.id)
        if sev and SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(arc["severity"] or "informational", 0):
            arc["severity"] = sev
        for city, country, lat, lon, bytes_ in (
            (flow.src_city, flow.src_country, flow.src_lat, flow.src_lon, flow.bytes_out or 0),
            (flow.dst_city, flow.dst_country, flow.dst_lat, flow.dst_lon, flow.bytes_in or 0),
        ):
            node_key = (round(lat, 3), round(lon, 3), city)
            node = nodes.setdefault(
                node_key,
                {"name": city or "Unknown", "country": country, "lat": lat, "lng": lon, "volume": 0, "connections": 0, "severity": None},
            )
            node["volume"] += bytes_
            node["connections"] += 1
            if sev and SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(node["severity"] or "informational", 0):
                node["severity"] = sev

    arc_list = sorted(arcs.values(), key=lambda a: a["count"], reverse=True)[:180]
    status = "ready"
    message = None
    if not rows:
        status = "awaiting_telemetry"
        message = "Awaiting network telemetry. The globe rotates without rendering traffic paths until data arrives."
    elif not arc_list:
        status = "geo_unavailable"
        message = (
            "Flows are present but no geolocation is available. Private addresses are never assigned "
            "invented coordinates. Configure MaxMind GeoLite2 to enable geographic visualisation."
        )
    return {
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end)},
        "status": status,
        "message": message,
        "arcs": arc_list,
        "nodes": sorted(nodes.values(), key=lambda n: n["volume"], reverse=True)[:120],
        "unknown_locations": {
            "source_without_location": unknown_src,
            "destination_without_location": unknown_dst,
            "flows_total": len(rows),
        },
        "geo": geo_status(),
        "demo_geo": any(flow.geo_source in {"demo_synthetic", "demo_configured_asset"} for flow in rows[:200]),
        "notice": (
            "IP geolocation approximates network registration, not the physical location of a device. "
            "Coordinates in the demo workspace are explicitly labelled synthetic demo metadata."
        ),
    }


@router.get("/topology")
def topology(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    protocol: str | None = None,
    threat_class: str | None = None,
    direction: str | None = None,
    limit: int = Query(70, ge=10, le=200),
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    query = db.query(FlowRecord).filter(
        FlowRecord.workspace_id == ws.id,
        FlowRecord.environment == ws.environment,
        FlowRecord.ts >= w_start,
        FlowRecord.ts <= w_end,
    )
    if protocol and protocol.upper() in {"TCP", "UDP", "ICMP"}:
        query = query.filter(FlowRecord.protocol == protocol.upper())
    if direction in {"inbound", "outbound", "internal", "transit"}:
        query = query.filter(FlowRecord.direction == direction)
    rows = query.limit(80_000).all()

    alerts = _alert_query(db, ws, w_start, w_end)
    if threat_class:
        alerts = alerts.filter(SecurityAlert.threat_class == threat_class)
    alerts = alerts.limit(500).all()
    threat_nodes: dict[str, dict] = {}
    for alert in alerts:
        for ip in (alert.source_ip, alert.dest_ip):
            entry = threat_nodes.setdefault(ip, {"alerts": 0, "severity": "informational", "classes": Counter()})
            entry["alerts"] += 1
            entry["classes"][alert.threat_class] += 1
            if SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(entry["severity"], 0):
                entry["severity"] = alert.severity

    edge_map: dict[tuple[str, str, str], dict] = {}
    node_meta: dict[str, dict] = {}
    for flow in rows:
        key = (flow.src_ip, flow.dst_ip, flow.protocol)
        edge = edge_map.setdefault(
            key,
            {"packets": 0, "bytes": 0, "flows": 0, "ports": Counter(), "first": flow.ts, "last": flow.ts, "direction": flow.direction},
        )
        edge["packets"] += flow.packets or 0
        edge["bytes"] += (flow.bytes_in or 0) + (flow.bytes_out or 0)
        edge["flows"] += 1
        edge["first"] = min(edge["first"], flow.ts)
        edge["last"] = max(edge["last"], flow.ts)
        if flow.dst_port:
            edge["ports"][flow.dst_port] += 1
        for ip in (flow.src_ip, flow.dst_ip):
            node = node_meta.setdefault(
                ip,
                {"bytes": 0, "flows": 0, "protocols": Counter(), "internal": is_internal(ip, ws.internal_cidrs or [])},
            )
            node["bytes"] += (flow.bytes_in or 0) + (flow.bytes_out or 0)
            node["flows"] += 1
            node["protocols"][flow.protocol] += 1

    top_nodes = sorted(node_meta.items(), key=lambda item: item[1]["bytes"], reverse=True)[:limit]
    included = {ip for ip, _ in top_nodes}
    edges = [
        (key, value)
        for key, value in sorted(edge_map.items(), key=lambda item: item[1]["bytes"], reverse=True)
        if key[0] in included and key[1] in included
    ][: int(limit * 2.4)]

    nodes_payload = []
    for ip, meta in top_nodes:
        threat = threat_nodes.get(ip)
        nodes_payload.append(
            {
                "id": ip,
                "label": ip,
                "internal": meta["internal"],
                "bytes": meta["bytes"],
                "flows": meta["flows"],
                "protocols": [p for p, _ in meta["protocols"].most_common(3)],
                "threat": bool(threat),
                "severity": threat["severity"] if threat else None,
                "alerts": threat["alerts"] if threat else 0,
                "threat_classes": [c for c, _ in threat["classes"].most_common(2)] if threat else [],
            }
        )
    edges_payload = []
    for (src, dst, proto), meta in edges:
        edges_payload.append(
            {
                "id": f"{src}->{dst}:{proto}",
                "source": src,
                "target": dst,
                "protocol": proto,
                "bytes": meta["bytes"],
                "packets": meta["packets"],
                "flows": meta["flows"],
                "port": meta["ports"].most_common(1)[0][0] if meta["ports"] else None,
                "first_seen": iso(meta["first"]),
                "last_seen": iso(meta["last"]),
                "direction": meta["direction"],
                "suspicious": bool(threat_nodes.get(src) or threat_nodes.get(dst)),
            }
        )
    return {
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end)},
        "has_data": bool(rows),
        "nodes": nodes_payload,
        "edges": edges_payload,
        "meta": {
            "nodes_total": len(node_meta),
            "edges_total": len(edge_map),
            "displayed_nodes": len(nodes_payload),
            "displayed_edges": len(edges_payload),
            "truncated": len(node_meta) > len(nodes_payload) or len(edge_map) > len(edges_payload),
            "derived_from": f"{len(rows):,} flow records",
        },
    }


@router.get("/insights")
def insights(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, label = window(range, start, end)
    payload = _build_insights(db, ws, w_start, w_end)
    return {
        "range": {"key": range, "label": label, "start": iso(w_start), "end": iso(w_end)},
        **payload,
        "llm": {"enabled": False, "note": "Deterministic summaries only; no external AI service is configured."},
    }


@router.get("/coverage")
def coverage(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("dashboard.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    w_start, w_end, _ = window(range, start, end)
    rows = (
        db.query(FlowRecord)
        .filter(
            FlowRecord.workspace_id == ws.id,
            FlowRecord.environment == ws.environment,
            FlowRecord.ts >= w_start,
            FlowRecord.ts <= w_end,
        )
        .limit(5000)
        .all()
    )
    modules = db.query(DetectionModule).all()
    checks = {
        "ddos_detector": any(f.packets for f in rows) and any(f.protocol for f in rows),
        "port_scan_detector": any(f.dst_port for f in rows),
        "beaconing_detector": any(f.dst_port for f in rows),
        "dns_detector": any(f.dns_query for f in rows),
        "encrypted_metadata_detector": any(f.tls_ja3 or f.tls_sni or f.quic for f in rows),
        "exfiltration_detector": any(f.direction == "outbound" and f.bytes_out > 0 for f in rows),
    }
    return {
        "flows_sampled": len(rows),
        "modules": [
            {
                "code": m.code,
                "name": m.name,
                "supported": bool(checks.get(m.code)),
                "reason": None
                if checks.get(m.code)
                else _coverage_reason(m.code),
            }
            for m in modules
        ],
    }


def _coverage_reason(code: str) -> str:
    return {
        "ddos_detector": "No packet counts and protocol fields were present in the sampled telemetry.",
        "port_scan_detector": "Destination ports were not captured in the sampled telemetry.",
        "beaconing_detector": "Destination endpoints were not present in the sampled telemetry.",
        "dns_detector": "DNS query names were not captured; DNS analysis has insufficient visibility.",
        "encrypted_metadata_detector": "No TLS/QUIC handshake metadata was captured; encrypted-session analysis is unavailable.",
        "exfiltration_detector": "Traffic direction could not be determined from configured zones and captured fields.",
    }.get(code, "Required fields were not available in the sampled telemetry.")
