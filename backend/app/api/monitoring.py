from __future__ import annotations

from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_permissions
from ..geo import is_internal
from ..models import FlowRecord, SecurityAlert, User
from ..serializers import alert_summary, flow_payload, iso
from .dashboard import _bucket_label, _bucket_series, _floor, get_workspace_or_404, window

router = APIRouter(prefix="/monitoring", tags=["Network monitoring"])


@router.get("/flows")
def flow_table(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    q: str | None = Query(None, max_length=120),
    protocol: str | None = Query(None),
    direction: str | None = Query(None),
    suspicious: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permissions("monitoring.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    start_dt, end_dt, label = window(range, start, end)
    query = db.query(FlowRecord).filter(
        FlowRecord.workspace_id == ws.id,
        FlowRecord.environment == ws.environment,
        FlowRecord.ts >= start_dt,
        FlowRecord.ts <= end_dt,
    )
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            or_(
                FlowRecord.reference.ilike(like),
                FlowRecord.src_ip.ilike(like),
                FlowRecord.dst_ip.ilike(like),
                FlowRecord.dns_query.ilike(like),
                FlowRecord.tls_sni.ilike(like),
            )
        )
    if protocol:
        query = query.filter(FlowRecord.protocol == protocol.upper())
    if direction:
        query = query.filter(FlowRecord.direction == direction)

    alert_ips: set[str] = set()
    if suspicious:
        alerts = (
            db.query(SecurityAlert.source_ip, SecurityAlert.dest_ip)
            .filter(
                SecurityAlert.workspace_id == ws.id,
                SecurityAlert.environment == ws.environment,
                SecurityAlert.first_seen >= start_dt,
                SecurityAlert.first_seen <= end_dt,
            )
            .all()
        )
        alert_ips = {ip for pair in alerts for ip in pair}
        if alert_ips:
            query = query.filter(
                or_(FlowRecord.src_ip.in_(alert_ips), FlowRecord.dst_ip.in_(alert_ips))
            )
        else:
            query = query.filter(FlowRecord.id == -1)

    total = query.count()
    rows = (
        query.order_by(FlowRecord.ts.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [
            {**flow_payload(row), "suspicious": bool(alert_ips and (row.src_ip in alert_ips or row.dst_ip in alert_ips))}
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "period": {"label": label, "start": iso(start_dt), "end": iso(end_dt)},
        "workspace": {"slug": ws.slug, "environment": ws.environment},
        "classification_note": (
            "Private addresses are classified against the workspace internal CIDR configuration. "
            "Geolocation, where present, approximates network registration rather than device location."
        ),
    }


@router.get("/hosts/{ip}")
def host_profile(
    ip: str,
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("monitoring.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    start_dt, end_dt, label = window(range, start, end)
    base = db.query(FlowRecord).filter(
        FlowRecord.workspace_id == ws.id,
        FlowRecord.environment == ws.environment,
        FlowRecord.ts >= start_dt,
        FlowRecord.ts <= end_dt,
        or_(FlowRecord.src_ip == ip, FlowRecord.dst_ip == ip),
    )
    rows = base.order_by(FlowRecord.ts.asc()).limit(20_000).all()
    if not rows and not db.query(FlowRecord.id).filter(FlowRecord.src_ip == ip).first():
        raise HTTPException(status_code=404, detail="No observations for this address in the workspace")

    outgoing = [r for r in rows if r.src_ip == ip]
    incoming = [r for r in rows if r.dst_ip == ip]
    peers: Counter = Counter()
    for row in rows:
        peers[row.dst_ip if row.src_ip == ip else row.src_ip] += 1
    ports = Counter(row.dst_port for row in outgoing if row.dst_port)
    protocols = Counter(row.protocol for row in rows)
    total_bytes = sum((r.bytes_in or 0) + (r.bytes_out or 0) for r in rows)

    bucket_seconds, _ = (300, "5-minute") if (end_dt - start_dt) <= timedelta(hours=12) else (3600, "hourly")
    buckets = _bucket_series(start_dt, end_dt, bucket_seconds)
    series = {b: {"sent": 0, "received": 0, "flows": 0} for b in buckets}
    for row in rows:
        key = _bucket_label(_floor(row.ts, bucket_seconds), bucket_seconds)
        bucket = series.setdefault(key, {"sent": 0, "received": 0, "flows": 0})
        bucket["flows"] += 1
        if row.src_ip == ip:
            bucket["sent"] += row.bytes_out or row.bytes_total or 0
        else:
            bucket["received"] += row.bytes_in or 0

    alerts = (
        db.query(SecurityAlert)
        .filter(
            SecurityAlert.workspace_id == ws.id,
            SecurityAlert.environment == ws.environment,
            SecurityAlert.first_seen >= start_dt,
            SecurityAlert.first_seen <= end_dt,
            or_(SecurityAlert.source_ip == ip, SecurityAlert.dest_ip == ip),
        )
        .order_by(SecurityAlert.first_seen.desc())
        .limit(10)
        .all()
    )
    sample = rows[0]
    return {
        "ip": ip,
        "workspace": {"slug": ws.slug, "environment": ws.environment},
        "period": {"label": label, "start": iso(start_dt), "end": iso(end_dt)},
        "geo": {
            "city": sample.src_city if sample.src_ip == ip else sample.dst_city,
            "country": sample.src_country if sample.src_ip == ip else sample.dst_country,
            "source": sample.geo_source,
        },
        "role": (
            "internal asset"
            if is_internal(ip, ws.internal_cidrs or [])
            else "external endpoint"
        ),
        "totals": {
            "observations": len(rows),
            "outbound_flows": len(outgoing),
            "inbound_flows": len(incoming),
            "bytes": total_bytes,
        },
        "timeline": [
            {
                "bucket": key,
                "sent_mib": round(value["sent"] / 1_048_576, 3),
                "received_mib": round(value["received"] / 1_048_576, 3),
                "flows": value["flows"],
            }
            for key, value in series.items()
        ],
        "top_peers": [{"ip": peer, "flows": count} for peer, count in peers.most_common(10)],
        "top_destination_ports": [{"port": port, "flows": count} for port, count in ports.most_common(10)],
        "protocols": [{"protocol": proto, "flows": count} for proto, count in protocols.most_common()],
        "alerts": [alert_summary(item) for item in alerts],
        "notice": "Host profiles are built only from stored passive observations in this workspace.",
    }
