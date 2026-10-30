from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_permissions
from ..detectors import char_entropy, shannon_entropy
from ..models import AlertEvidence, DetectionModule, FlowRecord, SecurityAlert, User
from ..serializers import alert_summary, iso, module_payload
from .dashboard import _alert_query, _bucket_label, _bucket_series, _floor, get_workspace_or_404, window

router = APIRouter(prefix="/detections", tags=["Detection workspaces"])

MODULE_MAP = {
    "ddos": "ddos_detector",
    "beaconing": "beaconing_detector",
    "dns": "dns_detector",
    "encrypted": "encrypted_metadata_detector",
    "scanning": "port_scan_detector",
    "exfiltration": "exfiltration_detector",
}


def _histogram(values: list[float], edges: list[float], labels: list[str] | None = None) -> list[dict]:
    counts = [0] * (len(edges) + 1)
    for value in values:
        placed = False
        for index, edge in enumerate(edges):
            if value < edge:
                counts[index] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    if labels is None:
        labels = [f"< {edges[0]:g}"] + [f"{edges[i]:g}–{edges[i+1]:g}" for i in range(len(edges) - 1)] + [f"≥ {edges[-1]:g}"]
    return [{"bucket": label, "count": count} for label, count in zip(labels, counts)]


def _flow_rows(db, ws, start, end, extra=None):
    query = db.query(FlowRecord).filter(
        FlowRecord.workspace_id == ws.id,
        FlowRecord.environment == ws.environment,
        FlowRecord.ts >= start,
        FlowRecord.ts <= end,
    )
    if extra is not None:
        query = query.filter(extra)
    return query.order_by(FlowRecord.ts.asc()).limit(40_000).all()


def _confidence_badge(module: DetectionModule) -> str:
    return {
        "ddos_detector": "heuristic_score",
        "beaconing_detector": "heuristic_score",
        "encrypted_metadata_detector": "heuristic_score",
        "port_scan_detector": "hybrid_score",
        "dns_detector": "hybrid_score",
        "exfiltration_detector": "hybrid_score",
    }.get(module.code, "heuristic_score")


def _base(db, ws, code, start, end, slug: str) -> dict:
    module = db.query(DetectionModule).filter(DetectionModule.code == code).first()
    if not module:
        raise HTTPException(status_code=404, detail="Detection module not found")
    alerts = _alert_query(db, ws, start, end).filter(SecurityAlert.detector_code == code).order_by(SecurityAlert.first_seen.desc()).all()
    payloads = []
    for alert in alerts:
        evidence = db.query(AlertEvidence).filter(AlertEvidence.alert_id == alert.id).limit(3).all()
        payloads.append(alert_summary(alert, evidence))
    return {"module": module, "alerts": alerts, "alert_payloads": payloads}


def _kpis(alerts: list[SecurityAlert], flows: int, coverage_note: str | None) -> list[dict]:
    severities = Counter(a.severity for a in alerts)
    sources = {a.source_ip for a in alerts}
    avg_conf = round(statistics.fmean([a.confidence for a in alerts]), 3) if alerts else None
    return [
        {"key": "detections", "label": "Detections", "value": len(alerts), "unit": "alerts", "help": "Alerts from this module in the selected period."},
        {"key": "sources", "label": "Distinct sources", "value": len(sources), "unit": "endpoints", "help": "Distinct source addresses associated with these alerts."},
        {"key": "critical_high", "label": "High or critical", "value": severities.get("critical", 0) + severities.get("high", 0), "unit": "alerts", "help": "Severity reflects potential impact, not proof."},
        {"key": "confidence", "label": "Mean score", "value": avg_conf, "unit": "0–1", "help": "Mean stored score. Hybrid/heuristic scores are not calibrated probabilities."},
        {"key": "flows", "label": "Flows analysed", "value": flows, "unit": "flows", "help": "Flow records considered in the selected window.", "note": coverage_note},
    ]


@router.get("")
def detection_catalog(
    user: User = Depends(require_permissions("detections.view")),
    db: Session = Depends(get_db),
):
    modules = db.query(DetectionModule).order_by(DetectionModule.id).all()
    payload = []
    for module in modules:
        item = module_payload(module)
        item["slug"] = next((slug for slug, code in MODULE_MAP.items() if code == module.code), None)
        item["confidence_badge"] = _confidence_badge(module)
        payload.append(item)
    return {
        "modules": payload,
        "notes": [
            "Each workspace analyses only the telemetry fields available in the selected environment.",
            "Coverage gaps are reported explicitly instead of being estimated.",
        ],
    }


@router.get("/{slug}")
def detection_workspace(
    slug: str,
    workspace: str = Query("live-ops"),
    range_key: str = Query("24h", alias="range"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("detections.view")),
    db: Session = Depends(get_db),
):
    if slug not in MODULE_MAP:
        raise HTTPException(status_code=404, detail="Unknown detector workspace")
    ws = get_workspace_or_404(db, workspace)
    start_dt, end_dt, label = window(range_key, start, end)
    code = MODULE_MAP[slug]
    base = _base(db, ws, code, start_dt, end_dt, slug)
    module: DetectionModule = base["module"]
    alerts: list[SecurityAlert] = base["alerts"]

    bucket_seconds = 300 if (end_dt - start_dt) <= timedelta(hours=12) else 3600
    buckets = _bucket_series(start_dt, end_dt, bucket_seconds)
    bucket_index = {label_: i for i, label_ in enumerate(buckets)}

    flows = _flow_rows(db, ws, start_dt, end_dt)
    availability: dict[str, bool] = {}
    charts: dict = {}
    analysis: list[dict] = []
    tables: list[dict] = []
    coverage_note = None

    def bucket_of(ts: datetime) -> str:
        return _bucket_label(_floor(ts, bucket_seconds), bucket_seconds)

    if slug == "ddos":
        availability = {
            "packet_counts": any(f.packets for f in flows),
            "protocol": any(f.protocol for f in flows),
            "tcp_flags": any(f.tcp_flags for f in flows),
            "byte_counts": any(f.bytes_total for f in flows),
        }
        top_dest = Counter(f.dst_ip for f in flows).most_common(3)
        dest_ips = [ip for ip, _ in top_dest]
        pps = {b: 0.0 for b in buckets}
        bps = {b: 0.0 for b in buckets}
        syn = {b: 0 for b in buckets}
        ack = {b: 0 for b in buckets}
        src_sets: dict[str, set] = defaultdict(set)
        for flow in flows:
            b = bucket_of(flow.ts)
            pps[b] = pps.get(b, 0) + (flow.packets or 0) / bucket_seconds
            bps[b] = bps.get(b, 0) + ((flow.bytes_total or 0) * 8) / bucket_seconds
            flags = (flow.tcp_flags or "").upper()
            if "SYN" in flags:
                syn[b] = syn.get(b, 0) + 1
            if "ACK" in flags:
                ack[b] = ack.get(b, 0) + 1
            src_sets[b].add(flow.src_ip)
        attack_flows = [f for f in flows if any(f.dst_ip == a.dest_ip for a in alerts)] or flows
        charts["pps_timeline"] = [{"bucket": b, "pps": round(pps.get(b, 0), 2), "bps": round(bps.get(b, 0), 1)} for b in buckets]
        charts["syn_ack"] = [{"bucket": b, "syn": syn.get(b, 0), "ack": ack.get(b, 0)} for b in buckets]
        charts["unique_sources"] = [{"bucket": b, "sources": len(src_sets.get(b, set()))} for b in buckets]
        per_bucket_entropy = []
        for b in buckets:
            sources = list(src_sets.get(b, set()))
            per_bucket_entropy.append({"bucket": b, "entropy": round(shannon_entropy(sources), 2) if sources else 0})
        charts["source_entropy"] = per_bucket_entropy
        udp_ports = Counter(f.dst_port for f in flows if f.protocol == "UDP" and f.dst_port)
        charts["udp_ports"] = [{"port": str(p), "count": c} for p, c in udp_ports.most_common(10)]
        charts["targets"] = [{"ip": ip, "flows": c} for ip, c in top_dest]
        analysis = [
            {"label": "Top destination", "value": top_dest[0][0] if top_dest else "—"},
            {"label": "Peak packet rate", "value": f"{max(pps.values(), default=0):,.0f} pps"},
            {"label": "Peak bit rate", "value": f"{max(bps.values(), default=0) / 1_000_000:.1f} Mbps"},
            {
                "label": "UDP share",
                "value": f"{sum(1 for f in flows if f.protocol == 'UDP') / max(1, len(flows)):.0%}",
                "note": "A high UDP share with reflector ports is a behavioural lead, not proof of spoofing.",
            },
        ]
        tables = [
            {
                "destination": a.dest_ip,
                "protocol": a.protocol,
                "severity": a.severity,
                "confidence": a.confidence,
                "first_seen": iso(a.first_seen),
                "summary": a.summary,
            }
            for a in alerts[:8]
        ]
        if not availability["packet_counts"]:
            coverage_note = "Packet counts missing: rate-based DDoS detection cannot be evaluated for this telemetry."

    elif slug == "beaconing":
        availability = {"timestamps": True, "endpoints": any(f.dst_port for f in flows)}
        pairs: dict[tuple, list[FlowRecord]] = defaultdict(list)
        for flow in flows:
            pairs[(flow.src_ip, flow.dst_ip, flow.dst_port)].append(flow)
        ranked = []
        for key, group in pairs.items():
            if len(group) < 6:
                continue
            ordered = sorted(group, key=lambda f: f.ts)
            intervals = [(ordered[i + 1].ts - ordered[i].ts).total_seconds() for i in range(len(ordered) - 1)]
            intervals = [i for i in intervals if i > 0]
            if len(intervals) < 5:
                continue
            mean = statistics.fmean(intervals)
            cv = statistics.pstdev(intervals) / mean if mean else 9
            ranked.append((key, ordered, intervals, mean, cv))
        ranked.sort(key=lambda item: item[4])
        top = ranked[:12]
        charts["connections"] = [
            {
                "src": key[0], "dst": key[1], "port": key[2], "connections": len(group),
                "mean_interval": round(mean, 1), "cv": round(cv, 3),
            }
            for key, group, _, mean, cv in top
        ]
        interval_values = [i for _, _, intervals, _, _ in top for i in intervals]
        charts["interval_histogram"] = _histogram(interval_values, [10, 30, 60, 300, 900, 3600], ["<10s", "10–30s", "30–60s", "1–5m", "5–15m", "15–60m", "≥60m"])
        charts["cv_trend"] = [
            {"pair": f"{key[1]}:{key[2]}", "cv": round(cv, 3), "src": key[0], "mean": round(mean, 1)}
            for key, _, _, mean, cv in top
        ]
        events = []
        heat = defaultdict(lambda: {"low": 0, "medium": 0, "high": 0})
        for key, group, intervals, mean, cv in top[:3]:
            cursor = group[0].ts
            for flow in group[:40]:
                events.append({
                    "ts": iso(flow.ts),
                    "src": flow.src_ip,
                    "dst": flow.dst_ip,
                    "port": flow.dst_port,
                    "interval_s": round((flow.ts - cursor).total_seconds(), 1) if flow.ts != group[0].ts else None,
                })
                cursor = flow.ts
        for flow in flows:
            hour_key = flow.ts.strftime("%H:00")
            cv_band = "low" if (flow.packets or 0) > 3 else "medium"
            heat[hour_key][cv_band] += 1
        charts["events"] = events
        charts["heatmap"] = [{"hour": h, **v} for h, v in sorted(heat.items())]
        charts["destination_frequency"] = [
            {"destination": f"{a.dest_ip}:{a.dest_port}", "alerts": sum(1 for x in alerts if x.dest_ip == a.dest_ip)}
            for a in alerts[:8]
        ]
        analysis = [
            {"label": "Regular pairs", "value": len(ranked)},
            {"label": "Lowest CV", "value": f"{top[0][4]:.3f}" if top else "—"},
            {"label": "Most frequent interval", "value": f"{top[0][3]:.0f}s" if top else "—"},
            {"label": "Note", "value": "Observation window requirement", "note": "Beaconing needs repeated callbacks; detection latency is reported separately from observation time."},
        ]
        tables = [
            {
                "source": a.source_ip, "destination": a.dest_ip, "port": a.dest_port,
                "severity": a.severity, "confidence": a.confidence, "summary": a.summary,
            }
            for a in alerts[:8]
        ]
        if not availability["endpoints"]:
            coverage_note = "No destination endpoints available; beaconing cannot be assessed."

    elif slug == "dns":
        dns_flows = [f for f in flows if f.dns_query]
        availability = {
            "query_names": bool(dns_flows),
            "response_codes": any(f.dns_rcode for f in dns_flows),
            "record_types": any(f.dns_qtype for f in dns_flows),
        }
        domains = [f.dns_query for f in dns_flows if f.dns_query]
        entropies = [char_entropy(".".join(d.split(".")[:-1]) if d.count(".") > 1 else d) for d in domains]
        lengths = [len(d) for d in domains]
        labels = [len(d.split(".")[0]) for d in domains]
        charts["entropy_distribution"] = _histogram(entropies, [1, 2, 3, 3.5, 4, 4.5, 5], ["<1", "1–2", "2–3", "3–3.5", "3.5–4", "4–4.5", "4.5–5", "≥5"])
        charts["length_distribution"] = _histogram([float(v) for v in lengths], [20, 40, 60, 80, 100, 150], ["<20", "20–40", "40–60", "60–80", "80–100", "100–150", "≥150"])
        charts["label_length"] = _histogram([float(v) for v in labels], [10, 20, 30, 40, 50], ["<10", "10–20", "20–30", "30–40", "40–50", "≥50"])
        qtype_counts = Counter(f.dns_qtype or "unknown" for f in dns_flows)
        charts["qtypes"] = [{"type": k, "count": v} for k, v in qtype_counts.most_common()]
        query_buckets = Counter(bucket_of(f.ts) for f in dns_flows)
        charts["query_timeline"] = [{"bucket": b, "queries": query_buckets.get(b, 0)} for b in buckets]
        nx = sum(1 for f in dns_flows if (f.dns_rcode or "").upper() == "NXDOMAIN")
        charts["nxdomain"] = [
            {"label": "NXDOMAIN", "count": nx},
            {"label": "Other / no response code", "count": len(dns_flows) - nx},
        ]
        domain_stats = Counter(domains)
        tables = []
        for domain, count in domain_stats.most_common(20):
            ent = char_entropy(".".join(domain.split(".")[:-1]) if domain.count(".") > 1 else domain)
            tables.append({
                "domain": domain,
                "queries": count,
                "entropy": round(ent, 2),
                "label_length": len(domain.split(".")[0]),
                "qtype": Counter(f.dns_qtype or "?" for f in dns_flows if f.dns_query == domain).most_common(1)[0][0],
                "suspect": ent >= 3.35 or len(domain.split(".")[0]) >= 38,
            })
        analysis = [
            {"label": "DNS flows", "value": len(dns_flows)},
            {"label": "Unique names", "value": len(set(domains))},
            {"label": "Mean entropy", "value": f"{statistics.fmean(entropies):.2f} bits" if entropies else "—"},
            {"label": "NXDOMAIN ratio", "value": f"{nx / max(1, len(dns_flows)):.0%}" if availability["response_codes"] else "not available"},
        ]
        if not availability["query_names"]:
            coverage_note = "DNS query names were not captured. Analysis reports insufficient visibility instead of estimating."
        elif not availability["response_codes"]:
            coverage_note = "NXDOMAIN ratio unavailable: response codes were not captured."

    elif slug == "encrypted":
        enc_flows = [f for f in flows if f.tls_ja3 or f.tls_sni or f.quic or (f.app_proto or "") in {"tls", "quic_udp443"}]
        availability = {
            "ja3": any(f.tls_ja3 for f in enc_flows),
            "sni": any(f.tls_sni for f in enc_flows),
            "cipher": any(f.tls_cipher for f in enc_flows),
            "version": any(f.tls_version for f in enc_flows),
            "quic": any(f.quic for f in enc_flows),
        }
        fingerprints = Counter(f.tls_ja3 for f in enc_flows if f.tls_ja3)
        charts["fingerprints"] = [{"ja3": k, "count": v} for k, v in fingerprints.most_common(12)]
        ciphers = Counter(f.tls_cipher for f in enc_flows if f.tls_cipher)
        charts["ciphers"] = [{"cipher": k, "count": v} for k, v in ciphers.most_common(10)]
        versions = Counter(f.tls_version for f in enc_flows if f.tls_version)
        charts["versions"] = [{"version": k, "count": v} for k, v in versions.most_common()]
        charts["duration"] = _histogram([f.duration_ms / 1000 for f in enc_flows], [1, 5, 20, 60, 300], ["<1s", "1–5s", "5–20s", "20–60s", "1–5m", "≥5m"])
        charts["sizes"] = _histogram([float(f.bytes_total) for f in enc_flows], [1_000, 10_000, 100_000, 1_000_000, 10_000_000], ["<1KB", "1–10KB", "10–100KB", "0.1–1MB", "1–10MB", "≥10MB"])
        charts["timeline"] = [{"bucket": b, "sessions": sum(1 for f in enc_flows if bucket_of(f.ts) == b)} for b in buckets]
        charts["protocols"] = [{"protocol": k, "count": v} for k, v in Counter("QUIC" if f.quic else f.protocol for f in enc_flows).most_common()]
        analysis = [
            {"label": "Encrypted sessions", "value": len(enc_flows)},
            {"label": "Distinct JA3", "value": len(fingerprints)},
            {"label": "SNI present", "value": f"{sum(1 for f in enc_flows if f.tls_sni) / max(1, len(enc_flows)):.0%}"},
            {"label": "Payload visibility", "value": "not decrypted", "note": "Analysis is limited to observable handshake metadata."},
        ]
        tables = [
            {
                "source": a.source_ip, "destination": a.dest_ip, "port": a.dest_port,
                "severity": a.severity, "confidence": a.confidence, "summary": a.summary,
            }
            for a in alerts[:8]
        ]
        if not availability["ja3"]:
            coverage_note = "JA3 fingerprints unavailable in this telemetry; encrypted-session analysis is limited to observed session metadata."

    elif slug == "scanning":
        scanned = [f for f in flows if f.dst_port]
        availability = {"ports": bool(scanned), "tcp_flags": any(f.tcp_flags for f in scanned)}
        per_src: dict[str, dict] = defaultdict(lambda: {"ports": set(), "hosts": set(), "attempts": 0, "first": None, "last": None})
        scan_buckets = {b: {"ports": set(), "attempts": 0} for b in buckets}
        port_counts: Counter = Counter()
        for flow in scanned:
            entry = per_src[flow.src_ip]
            entry["ports"].add(flow.dst_port)
            entry["hosts"].add(flow.dst_ip)
            entry["attempts"] += 1
            entry["first"] = flow.ts if entry["first"] is None else min(entry["first"], flow.ts)
            entry["last"] = flow.ts if entry["last"] is None else max(entry["last"], flow.ts)
            b = bucket_of(flow.ts)
            scan_buckets.setdefault(b, {"ports": set(), "attempts": 0})
            scan_buckets[b]["ports"].add(flow.dst_port)
            scan_buckets[b]["attempts"] += 1
            port_counts[flow.dst_port] += 1
        charts["ports_timeline"] = [{"bucket": b, "unique_ports": len(scan_buckets[b]["ports"]), "attempts": scan_buckets[b]["attempts"]} for b in buckets]
        charts["port_histogram"] = [{"port": str(p), "count": c} for p, c in port_counts.most_common(25)]
        charts["hosts_timeline"] = [{"bucket": b, "hosts": len({f.dst_ip for f in scanned if bucket_of(f.ts) == b})} for b in buckets]
        tables = [
            {
                "source": src,
                "unique_ports": len(meta["ports"]),
                "unique_hosts": len(meta["hosts"]),
                "attempts": meta["attempts"],
                "first_seen": iso(meta["first"]),
                "last_seen": iso(meta["last"]),
            }
            for src, meta in sorted(per_src.items(), key=lambda item: len(item[1]["ports"]), reverse=True)[:12]
        ]
        analysis = [
            {"label": "Scanning candidates", "value": sum(1 for m in per_src.values() if len(m["ports"]) >= 20)},
            {"label": "Max ports/source", "value": max((len(m["ports"]) for m in per_src.values()), default=0)},
            {"label": "Max hosts/source", "value": max((len(m["hosts"]) for m in per_src.values()), default=0)},
            {"label": "Flows analysed", "value": len(scanned)},
        ]
        if not availability["ports"]:
            coverage_note = "Destination ports were not captured; port-scanning analysis is unavailable."

    else:  # exfiltration
        outbound = [f for f in flows if f.direction == "outbound" and f.bytes_out > 0]
        availability = {"directional_bytes": bool(outbound), "zones": True}
        out_series = {b: {"bytes_out": 0, "bytes_in": 0, "flows": 0} for b in buckets}
        ratio_by_dest: dict[str, dict] = defaultdict(lambda: {"out": 0, "in": 0, "flows": 0})
        for flow in outbound:
            b = bucket_of(flow.ts)
            out_series.setdefault(b, {"bytes_out": 0, "bytes_in": 0, "flows": 0})
            out_series[b]["bytes_out"] += flow.bytes_out or 0
            out_series[b]["bytes_in"] += flow.bytes_in or 0
            out_series[b]["flows"] += 1
            ratio_by_dest[flow.dst_ip]["out"] += flow.bytes_out or 0
            ratio_by_dest[flow.dst_ip]["in"] += flow.bytes_in or 0
            ratio_by_dest[flow.dst_ip]["flows"] += 1
        charts["bytes_timeline"] = [
            {"bucket": b, "out_mib": round(v["bytes_out"] / 1_048_576, 3), "in_mib": round(v["bytes_in"] / 1_048_576, 3), "flows": v["flows"]}
            for b, v in out_series.items()
        ]
        charts["destination_ratios"] = [
            {
                "destination": dst, "out_mib": round(meta["out"] / 1_048_576, 2),
                "in_mib": round(meta["in"] / 1_048_576, 3),
                "ratio": round(meta["out"] / max(1, meta["in"]), 1),
            }
            for dst, meta in sorted(ratio_by_dest.items(), key=lambda item: item[1]["out"], reverse=True)[:10]
        ]
        charts["scatter"] = [
            {
                "duration_s": round((f.duration_ms or 0) / 1000, 1),
                "out_bytes": f.bytes_out,
                "destination": f.dst_ip,
                "src": f.src_ip,
            }
            for f in sorted(outbound, key=lambda f: f.bytes_out, reverse=True)[:120]
        ]
        analysis = [
            {"label": "Outbound flows", "value": len(outbound)},
            {"label": "Outbound volume", "value": f"{sum(f.bytes_out for f in outbound) / 1_073_741_824:.2f} GiB"},
            {"label": "External destinations", "value": len({f.dst_ip for f in outbound})},
            {"label": "Direction method", "value": "configured zones", "note": "Direction is derived from workspace internal CIDRs; when unavailable, the assessment is incomplete."},
        ]
        tables = [
            {
                "source": a.source_ip, "destination": a.dest_ip, "severity": a.severity,
                "confidence": a.confidence, "summary": a.summary, "first_seen": iso(a.first_seen),
            }
            for a in alerts[:8]
        ]
        if not availability["directional_bytes"]:
            coverage_note = "Directional byte fields are unavailable; exfiltration is reported as an incomplete assessment."

    return {
        "slug": slug,
        "workspace": {"slug": ws.slug, "name": ws.name, "environment": ws.environment},
        "range": {"key": range_key, "label": label, "start": iso(start_dt), "end": iso(end_dt)},
        "module": {
            "code": module.code,
            "name": module.name,
            "threat_class": module.threat_class,
            "technique": module.technique,
            "description": module.description,
            "version": module.version,
            "model_name": module.model_name,
            "status": module.status if module.enabled else "DISABLED",
            "confidence_badge": _confidence_badge(module),
            "thresholds": module.thresholds,
        },
        "kpis": _kpis(alerts, len(flows), coverage_note),
        "availability": availability,
        "coverage_note": coverage_note,
        "charts": charts,
        "analysis": analysis,
        "tables": tables,
        "alerts": base["alert_payloads"],
        "has_data": bool(flows or alerts),
    }
