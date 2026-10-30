from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import FlowRecord
from .security import severity_for_score
from .text import plural

BUCKET_SECONDS = 60
SCAN_BUCKET_SECONDS = 300

REFLECTION_PORTS = {53, 123, 389, 1900, 11211, 161, 5353, 137}


@dataclass
class EvidenceItem:
    feature: str
    observed: str
    baseline: str | None = None
    unit: str | None = None
    description: str = ""
    flow_ids: list[int] = field(default_factory=list)


@dataclass
class Detection:
    detector_code: str
    threat_class: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    confidence_type: str
    summary: str
    evidence: list[EvidenceItem]
    flow_ids: list[int]
    baseline: dict
    scenario_id: str | None = None
    model_version_id: int | None = None
    dedup_key: str | None = None

    @property
    def severity(self) -> str:
        return severity_for_score(self.confidence)


def shannon_entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _median(values: list[float]) -> float | None:
    clean = [v for v in values if v is not None]
    return round(statistics.median(clean), 3) if clean else None


def _clamp(value: float, low: float = 0.0, high: float = 0.99) -> float:
    return max(low, min(high, value))


def _fmt_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:,.1f} {unit}"
        size /= 1024
    return f"{value:,.0f} B"


def _bucket(ts: datetime, seconds: int) -> int:
    return int(ts.timestamp()) // seconds


def _flow_ids(flows: list[FlowRecord], limit: int = 60) -> list[int]:
    return [f.id for f in flows[:limit] if f.id is not None]


def _scenario_of(flows: list[FlowRecord]) -> str | None:
    for flow in flows:
        if flow.scenario_id:
            return flow.scenario_id
    return None


def _model_score(code: str, features: dict) -> dict | None:
    try:
        from . import ml

        return ml.score(code, features)
    except Exception:
        return None


def _combine(rule_score: float, model: dict | None) -> tuple[float, str, int | None]:
    if model and model.get("probability") is not None:
        probability = float(model["probability"])
        combined = round(_clamp(0.45 * rule_score + 0.55 * probability, 0.05, 0.99), 3)
        return combined, "hybrid_score", model.get("model_version_id")
    return round(_clamp(rule_score, 0.05, 0.99), 3), "heuristic_score", None


# ---------------------------------------------------------------------------
# 1. Port scanning
# ---------------------------------------------------------------------------


def detect_port_scan(flows: list[FlowRecord], thresholds: dict | None = None) -> list[Detection]:
    th = thresholds or {}
    min_ports = int(th.get("unique_ports", 20))
    min_hosts = int(th.get("unique_hosts", 12))
    min_attempts = int(th.get("attempts", 30))
    buckets: dict[tuple[str, int], list[FlowRecord]] = defaultdict(list)
    per_src_buckets: dict[str, list[dict]] = defaultdict(list)
    for flow in flows:
        if flow.dst_port <= 0 or flow.protocol not in {"TCP", "UDP", "SCTP"}:
            continue
        buckets[(flow.src_ip, _bucket(flow.ts, SCAN_BUCKET_SECONDS))].append(flow)

    metrics_by_key: dict[tuple[str, int], dict] = {}
    for (src, _b), group in buckets.items():
        ports = [f.dst_port for f in group]
        hosts = {f.dst_ip for f in group}
        syn_only = sum(
            1
            for f in group
            if (f.tcp_flags or "").upper().find("SYN") >= 0
            and (f.tcp_flags or "").upper().find("ACK") < 0
        )
        metrics_by_key[(src, _b)] = {
            "unique_ports": len(set(ports)),
            "unique_hosts": len(hosts),
            "attempts": len(group),
            "syn_only": syn_only,
            "port_entropy": shannon_entropy([str(p) for p in ports]),
            "duration_s": max(1.0, (max(f.ts for f in group) - min(f.ts for f in group)).total_seconds()),
        }
        per_src_buckets[src].append(metrics_by_key[(src, _b)])

    detections: list[Detection] = []
    for (src, _b), metrics in metrics_by_key.items():
        if metrics["unique_ports"] < min_ports and not (
            metrics["unique_hosts"] >= min_hosts and metrics["attempts"] >= min_attempts
        ):
            continue
        group = buckets[(src, _b)]
        baseline_ports = _median(
            [m["unique_ports"] for m in per_src_buckets[src] if m is not metrics]
        )
        horizontal = metrics["unique_hosts"] >= max(5, metrics["unique_ports"] // 4)
        rule = _clamp(
            0.45
            + min(0.3, metrics["unique_ports"] / 300)
            + min(0.12, metrics["unique_hosts"] / 120)
            + (0.05 if horizontal else 0.02)
        )
        features = {
            "unique_ports": metrics["unique_ports"],
            "unique_hosts": metrics["unique_hosts"],
            "attempts": metrics["attempts"],
            "duration_s": metrics["duration_s"],
            "failed_ratio": metrics["syn_only"] / max(1, metrics["attempts"]),
            "port_entropy": round(metrics["port_entropy"], 3),
        }
        confidence, ctype, model_id = _combine(rule, _model_score("scanning", features))
        top_dst = Counter(f.dst_ip for f in group).most_common(3)
        host_word = "host" if metrics["unique_hosts"] == 1 else "hosts"
        summary = (
            f"Source {src} contacted {metrics['unique_ports']} unique destination ports "
            f"across {metrics['unique_hosts']} {host_word} in {metrics['duration_s']:.0f}s — "
            f"{'horizontal' if horizontal else 'vertical'} fan-out consistent with port scanning."
        )
        evidence = [
            EvidenceItem(
                feature="unique_destination_ports",
                observed=str(metrics["unique_ports"]),
                baseline=f"{baseline_ports:.0f}" if baseline_ports is not None else "insufficient baseline",
                unit="ports",
                description="Distinct destination ports contacted within the observation window.",
                flow_ids=_flow_ids(group),
            ),
            EvidenceItem(
                feature="connection_attempts",
                observed=str(metrics["attempts"]),
                baseline=str(int(_median([m["attempts"] for m in per_src_buckets[src] if m is not metrics]) or 0)),
                unit="attempts",
                description="Observed connection attempts in the same window.",
            ),
            EvidenceItem(
                feature="unique_destination_hosts",
                observed=str(metrics["unique_hosts"]),
                unit="hosts",
                description="Distinct destination hosts contacted.",
            ),
            EvidenceItem(
                feature="syn_without_ack_ratio",
                observed=f"{features['failed_ratio']:.2f}",
                unit="ratio",
                description="Share of attempts with SYN and no ACK flag observed (where TCP flags were captured).",
            ),
            EvidenceItem(
                feature="destination_port_entropy",
                observed=f"{features['port_entropy']:.2f}",
                unit="bits",
                description="Shannon entropy over observed destination ports.",
            ),
            EvidenceItem(
                feature="scan_orientation",
                observed="horizontal (host sweep)" if horizontal else "vertical (port sweep)",
                description="Derived from the host/port fan-out relationship.",
            ),
        ]
        detections.append(
            Detection(
                detector_code="port_scan_detector",
                threat_class="Possible_Port_Scan",
                source_ip=src,
                dest_ip=top_dst[0][0],
                source_port=0,
                dest_port=top_dst[0][1],
                protocol=group[0].protocol,
                first_seen=min(f.ts for f in group),
                last_seen=max(f.ts for f in group),
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(group),
                baseline={"unique_ports": baseline_ports},
                scenario_id=_scenario_of(group),
                model_version_id=model_id,
                dedup_key=f"scan:{src}:{_b}",
            )
        )
    return detections


# ---------------------------------------------------------------------------
# 2. DDoS
# ---------------------------------------------------------------------------


def detect_ddos(flows: list[FlowRecord], thresholds: dict | None = None) -> list[Detection]:
    th = thresholds or {}
    pps_floor = float(th.get("pps_floor", 120))
    baseline_multiple = float(th.get("baseline_multiple", 5))
    syn_ratio_threshold = float(th.get("syn_ratio", 0.6))
    volumetric_bps = float(th.get("volumetric_bps", 2_000_000))
    buckets: dict[tuple[str, int], list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        buckets[(flow.dst_ip, _bucket(flow.ts, BUCKET_SECONDS))].append(flow)

    metrics: dict[tuple[str, int], dict] = {}
    per_dst: dict[str, list[dict]] = defaultdict(list)
    for key, group in buckets.items():
        packets = sum(f.packets for f in group)
        byte_total = sum(f.bytes_total for f in group)
        unique_sources = {f.src_ip for f in group}
        syn = sum(1 for f in group if "SYN" in (f.tcp_flags or "").upper())
        ack = sum(1 for f in group if "ACK" in (f.tcp_flags or "").upper())
        duration = max(1.0, (max(f.ts for f in group) - min(f.ts for f in group)).total_seconds())
        item = {
            "pps": round(packets / duration, 2),
            "bps": round(byte_total * 8 / duration, 2),
            "syn": syn,
            "ack": ack,
            "syn_ratio": syn / max(1, syn + ack),
            "unique_sources": len(unique_sources),
            "src_entropy": round(shannon_entropy(list(unique_sources)), 3),
            "udp_share": sum(1 for f in group if f.protocol == "UDP") / max(1, len(group)),
            "duration_s": duration,
        }
        metrics[key] = item
        per_dst[key[0]].append(item)

    detections: list[Detection] = []
    for (dst, bucket), item in metrics.items():
        group = buckets[(dst, bucket)]
        baseline_pps = _median([m["pps"] for m in per_dst[dst] if m is not item])
        baseline_bps = _median([m["bps"] for m in per_dst[dst] if m is not item])
        volume_threshold = max(pps_floor, (baseline_pps or 0) * baseline_multiple)
        syn_flood = item["pps"] >= volume_threshold and item["syn_ratio"] >= syn_ratio_threshold
        volumetric = (
            item["pps"] >= max(pps_floor * 1.6, (baseline_pps or 0) * baseline_multiple * 1.5)
            and item["bps"] >= volumetric_bps
        )
        if not (syn_flood or volumetric):
            continue
        rule = _clamp(
            0.48
            + min(0.25, item["pps"] / 4000)
            + min(0.15, item["unique_sources"] / 400)
            + (0.08 if item["syn_ratio"] >= 0.75 else 0.02)
        )
        features = {
            "pps": item["pps"],
            "bps": item["bps"],
            "syn_ratio": item["syn_ratio"],
            "unique_sources": item["unique_sources"],
            "src_entropy": item["src_entropy"],
            "baseline_pps": baseline_pps or 0.0,
        }
        confidence, ctype, model_id = _combine(rule, _model_score("ddos", features))
        protocol = Counter(f.protocol for f in group).most_common(1)[0][0]
        top_port = Counter(f.dst_port for f in group if f.dst_port).most_common(1)
        reflection = protocol == "UDP" and (
            (top_port and top_port[0][0] in REFLECTION_PORTS) or item["udp_share"] > 0.6
        )
        kind = "SYN-flood pattern" if syn_flood else "volumetric transfer"
        source_word = "address" if item["unique_sources"] == 1 else "addresses"
        summary = (
            f"Traffic to {dst} reached {item['pps']:,.0f} packets/s across "
            f"{item['unique_sources']:,} source {source_word} within {item['duration_s']:.0f}s "
            f"({kind}). Baseline for this destination was approximately "
            f"{baseline_pps if baseline_pps is not None else 0:.1f} packets/s."
        )
        evidence = [
            EvidenceItem("packets_per_second", f"{item['pps']:,.1f}", f"{baseline_pps or 0:,.1f}", "pps",
                         "Aggregate packet rate observed at the destination.", _flow_ids(group)),
            EvidenceItem("bits_per_second", f"{item['bps']:,.0f}", f"{baseline_bps or 0:,.0f}", "bps",
                         "Aggregate bit rate observed at the destination."),
            EvidenceItem("syn_ack_ratio", f"{item['syn_ratio']:.2f}", None, "ratio",
                         "SYN observations divided by SYN+ACK observations; high values indicate unanswered connection attempts."),
            EvidenceItem("unique_source_addresses", f"{item['unique_sources']:,}", None, "addresses",
                         "Distinct observed source addresses within the window."),
            EvidenceItem("source_address_entropy", f"{item['src_entropy']:.2f}", None, "bits",
                         "Distribution spread of source addresses. High entropy is consistent with a distributed pattern; it does not confirm spoofing."),
            EvidenceItem(
                "udp_characterisation",
                "potential reflection/amplification signature" if reflection else "not indicated",
                None,
                None,
                "Based on UDP share and destination ports associated with reflector services. "
                "This is a behavioural indicator only and does not confirm source spoofing.",
            ),
        ]
        detections.append(
            Detection(
                detector_code="ddos_detector",
                threat_class="Possible_DDoS",
                source_ip=Counter(f.src_ip for f in group).most_common(1)[0][0],
                dest_ip=dst,
                source_port=0,
                dest_port=top_port[0][0] if top_port else 0,
                protocol=protocol,
                first_seen=min(f.ts for f in group),
                last_seen=max(f.ts for f in group),
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(group),
                baseline={"pps": baseline_pps, "bps": baseline_bps},
                scenario_id=_scenario_of(group),
                model_version_id=model_id,
                dedup_key=f"ddos:{dst}:{bucket}",
            )
        )
    return detections


# ---------------------------------------------------------------------------
# 3. Beaconing
# ---------------------------------------------------------------------------


def detect_beaconing(flows: list[FlowRecord], thresholds: dict | None = None) -> list[Detection]:
    th = thresholds or {}
    min_connections = int(th.get("min_connections", 6))
    max_cv = float(th.get("max_cv", 0.4))
    bounds = th.get("interval_bounds_seconds", [10, 3600])
    groups: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    for flow in flows:
        groups[(flow.src_ip, flow.dst_ip, flow.dst_port)].append(flow)

    detections: list[Detection] = []
    for (src, dst, port), group in groups.items():
        if len(group) < min_connections:
            continue
        ordered = sorted(group, key=lambda f: f.ts)
        intervals = [
            (ordered[i + 1].ts - ordered[i].ts).total_seconds()
            for i in range(len(ordered) - 1)
        ]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) < 5:
            continue
        mean_interval = statistics.fmean(intervals)
        if not (float(bounds[0]) <= mean_interval <= float(bounds[1])):
            continue
        cv = statistics.pstdev(intervals) / mean_interval if mean_interval else 1.0
        rounded = Counter(round(i / 5) * 5 for i in intervals)
        mode_share = rounded.most_common(1)[0][1] / len(intervals)
        span_minutes = (ordered[-1].ts - ordered[0].ts).total_seconds() / 60
        if cv > max_cv or mode_share < 0.6:
            continue
        rule = _clamp(0.42 + (0.4 - cv) * 1.1 + min(0.12, len(group) * 0.01) + mode_share * 0.1)
        features = {
            "connections": len(group),
            "mean_interval_s": round(mean_interval, 3),
            "cv": round(cv, 3),
            "min_interval_s": round(min(intervals), 3),
            "max_interval_s": round(max(intervals), 3),
            "unique_dests": 1,
        }
        confidence, ctype, _ = _combine(rule, None)
        model_id = None
        anomaly = None
        try:
            from . import ml

            anomaly = ml.beacon_anomaly(features)
            if anomaly:
                model_id = anomaly.get("model_version_id")
        except Exception:
            anomaly = None
        summary = (
            f"{src} connected to {dst}:{port} {len(group)} times over {span_minutes:.0f} minutes "
            f"with a {mean_interval:.1f}s interval and coefficient of variation {cv:.2f}. "
            f"The regularity is consistent with automated command-and-control beaconing."
        )
        evidence = [
            EvidenceItem("observed_interval", f"{mean_interval:.1f}", None, "seconds",
                         "Mean inter-arrival time between observed connections.", _flow_ids(ordered)),
            EvidenceItem("repeated_connections", str(len(group)), None, "connections",
                         "Number of repeated connections to the same destination."),
            EvidenceItem("timing_variation_cv", f"{cv:.3f}", None, "coefficient of variation",
                         "Standard deviation of inter-arrival times divided by their mean. Lower values are more periodic."),
            EvidenceItem("interval_mode_share", f"{mode_share:.2f}", None, "ratio",
                         "Share of intervals falling within the dominant 5-second interval bucket."),
            EvidenceItem("destination_concentration", "1.00", None, "ratio",
                         "All observed connections share this single destination endpoint."),
            EvidenceItem("observation_span", f"{span_minutes:.0f}", None, "minutes",
                         "Observation window length. Behavioural detections may require extended windows."),
        ]
        if anomaly:
            evidence.append(
                EvidenceItem(
                    "model_anomaly_score",
                    f"{anomaly['anomaly_score']:.2f}",
                    None,
                    "anomaly score (0-1)",
                    f"Isolation Forest {anomaly['model_version']} support score. This is an anomaly "
                    "score, not a calibrated probability.",
                )
            )
        detections.append(
            Detection(
                detector_code="beaconing_detector",
                threat_class="Possible_C2_Beaconing",
                source_ip=src,
                dest_ip=dst,
                source_port=0,
                dest_port=port,
                protocol=ordered[0].protocol,
                first_seen=ordered[0].ts,
                last_seen=ordered[-1].ts,
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(ordered),
                baseline={"mean_interval_s": round(mean_interval, 3), "cv": round(cv, 3)},
                scenario_id=_scenario_of(ordered),
                model_version_id=model_id,
                dedup_key=f"beacon:{src}:{dst}:{port}",
            )
        )
    return detections


# ---------------------------------------------------------------------------
# 4. DGA / DNS tunnelling
# ---------------------------------------------------------------------------


def _registered_part(domain: str) -> str:
    labels = [label for label in domain.split(".") if label]
    if len(labels) <= 2:
        return labels[0] if labels else ""
    return ".".join(labels[:-1])


def detect_dns(flows: list[FlowRecord], thresholds: dict | None = None) -> list[Detection]:
    th = thresholds or {}
    min_queries = int(th.get("min_queries", 12))
    entropy_threshold = float(th.get("mean_entropy", 3.35))
    label_length = int(th.get("label_length", 38))
    dns_flows = [f for f in flows if f.dns_query]
    if not dns_flows:
        return []
    buckets: dict[tuple[str, int], list[FlowRecord]] = defaultdict(list)
    for flow in dns_flows:
        buckets[(flow.src_ip, _bucket(flow.ts, 600))].append(flow)

    detections: list[Detection] = []
    for (src, bucket), group in buckets.items():
        queries = [f.dns_query or "" for f in group]
        if len(queries) < min_queries:
            continue
        entropies = [char_entropy(_registered_part(q)) for q in queries]
        labels = [len((q.split(".")[0] if q else "")) for q in queries]
        lengths = [len(q) for q in queries]
        unique = len(set(queries))
        nxdomain = sum(1 for f in group if (f.dns_rcode or "").upper() == "NXDOMAIN")
        txt = sum(1 for f in group if (f.dns_qtype or "").upper() in {"TXT", "NULL", "CNAME"})
        digit_ratio = sum(sum(ch.isdigit() for ch in q) / max(1, len(q)) for q in queries) / len(queries)
        mean_entropy = statistics.fmean(entropies)
        max_label = max(labels)
        mean_len = statistics.fmean(lengths)
        duration = max(1.0, (max(f.ts for f in group) - min(f.ts for f in group)).total_seconds())
        qpm = len(group) / (duration / 60)
        nx_ratio = nxdomain / len(group)
        txt_ratio = txt / len(group)
        high_entropy = mean_entropy >= entropy_threshold and unique >= min_queries
        tunnelling = (
            max_label >= label_length
            and len(group) >= min_queries
            and (txt_ratio >= 0.3 or mean_len >= label_length + 7)
        )
        if not (high_entropy or tunnelling):
            continue
        rule = _clamp(
            0.4
            + min(0.22, (mean_entropy - 3.0) * 0.35)
            + (0.12 if tunnelling else 0.05)
            + min(0.08, unique / 100)
            + (0.06 if nx_ratio > 0.5 else 0)
        )
        features = {
            "mean_entropy": round(mean_entropy, 3),
            "max_label_len": max_label,
            "mean_query_len": round(mean_len, 2),
            "unique_domains": unique,
            "nxdomain_ratio": round(nx_ratio, 3),
            "queries_per_min": round(qpm, 2),
            "digit_ratio": round(digit_ratio, 3),
            "txt_ratio": round(txt_ratio, 3),
        }
        model = None
        try:
            from . import ml

            model = ml.score_dns(queries)
        except Exception:
            model = None
        if model:
            confidence = round(_clamp(0.45 * rule + 0.55 * float(model["probability"])), 3)
            ctype = "hybrid_score"
            model_id = model.get("model_version_id")
        else:
            confidence, ctype, model_id = _combine(rule, None)
        kind = "DNS tunnelling pattern" if tunnelling else "high-entropy domain generation pattern"
        top_domains = Counter(queries).most_common(4)
        summary = (
            f"{src} issued {len(group)} DNS queries in {duration/60:.1f} minutes with mean "
            f"registered-label entropy {mean_entropy:.2f} bits and {unique} unique names — "
            f"consistent with a {kind}."
        )
        evidence = [
            EvidenceItem("unique_domains", str(unique), None, "domains",
                         "Unique query names observed in the window.", _flow_ids(group)),
            EvidenceItem("mean_domain_entropy", f"{mean_entropy:.2f}", None, "bits/char",
                         "Mean Shannon entropy of the registered portion of observed query names."),
            EvidenceItem("max_query_label_length", str(max_label), None, "characters",
                         "Longest left-most label observed."),
            EvidenceItem("queries_per_minute", f"{qpm:.1f}", None, "queries/min",
                         "Query rate for this source in the observation window."),
            EvidenceItem("nxdomain_ratio", f"{nx_ratio:.2f}" if nxdomain else "not available", None, "ratio",
                         "Share of responses with NXDOMAIN, where response codes were captured."),
            EvidenceItem("record_type_share", f"TXT/CNAME {txt_ratio:.0%}", None, "ratio",
                         "Share of TXT, NULL and CNAME queries, which can carry tunnelled payloads."),
            EvidenceItem("sample_domains", ", ".join(d for d, _ in top_domains)[:255], None, None,
                         "Most frequent query names observed (truncated for display)."),
        ]
        if model:
            evidence.append(
                EvidenceItem(
                    "domain_model_probability",
                    f"{model['probability']:.2f}",
                    None,
                    "probability",
                    f"Mean calibrated probability across {model['scored_domains']} sampled query names "
                    f"(model {model['model_version']}, character n-gram classifier).",
                )
            )
        detections.append(
            Detection(
                detector_code="dns_detector",
                threat_class="Possible_DGA_or_DNS_Tunnelling",
                source_ip=src,
                dest_ip=Counter(f.dst_ip for f in group).most_common(1)[0][0],
                source_port=0,
                dest_port=53,
                protocol="UDP",
                first_seen=min(f.ts for f in group),
                last_seen=max(f.ts for f in group),
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(group),
                baseline={},
                scenario_id=_scenario_of(group),
                model_version_id=model_id,
                dedup_key=f"dns:{src}:{bucket}",
            )
        )
    return detections


# ---------------------------------------------------------------------------
# 5. TLS / QUIC metadata
# ---------------------------------------------------------------------------


def detect_encrypted(flows: list[FlowRecord], thresholds: dict | None = None) -> list[Detection]:
    th = thresholds or {}
    rarity_floor = float(th.get("rarity_floor", 0.6))
    max_confidence = float(th.get("max_confidence", 0.7))
    encrypted = [
        f for f in flows
        if f.tls_ja3 or (f.app_proto or "").lower() in {"tls", "ssl", "quic_udp443", "quic"}
    ]
    if not encrypted:
        return []
    fingerprint_counts = Counter(f.tls_ja3 for f in encrypted if f.tls_ja3)
    groups: dict[tuple[str, str, int, str | None], list[FlowRecord]] = defaultdict(list)
    for flow in encrypted:
        groups[(flow.src_ip, flow.dst_ip, flow.dst_port, flow.tls_ja3)].append(flow)

    detections: list[Detection] = []
    for (src, dst, port, ja3), group in groups.items():
        ordered = sorted(group, key=lambda f: f.ts)
        rarity = 1.0 - min(1.0, fingerprint_counts.get(ja3, 0) / max(3, len(encrypted) / 4))
        sni_missing = not any(f.tls_sni for f in group)
        nonstandard_port = port not in (443, 8443, 9443)
        repeated = len(group) >= 3
        small_fixed = (
            len(group) >= 3
            and statistics.pstdev([f.bytes_total for f in group]) < 500
            and statistics.fmean([f.bytes_total for f in group]) < 8000
        )
        suspicious = (sni_missing or nonstandard_port) and (repeated or rarity > 0.8)
        if not (suspicious and (rarity > rarity_floor or small_fixed)):
            continue
        rule = _clamp(0.36 + rarity * 0.2 + (0.08 if sni_missing else 0) + (0.06 if nonstandard_port else 0) + (0.04 if repeated else 0))
        features = {
            "ja3_rarity": round(rarity, 3),
            "connections": len(group),
            "avg_duration": round(statistics.fmean([f.duration_ms for f in group]) / 1000, 2),
            "avg_bytes": round(statistics.fmean([f.bytes_total for f in group]), 1),
            "sni_missing": 1.0 if sni_missing else 0.0,
        }
        confidence, ctype, model_id = _combine(rule, _model_score("encrypted", features))
        confidence = round(min(confidence, max_confidence), 3)  # metadata alone cannot justify high certainty
        sessions_word = plural(len(group), "encrypted session")
        share_word = "shares" if len(group) == 1 else "share"
        summary = (
            f"{len(group)} {sessions_word} from {src} to {dst}:{port} {share_word} an uncommon "
            f"TLS client fingerprint (JA3) with {'no SNI' if sni_missing else 'SNI present'}"
            f"{' and a non-standard service port' if nonstandard_port else ''}. "
            f"Unusual fingerprints are an investigative lead, not proof of malicious activity."
        )
        evidence = [
            EvidenceItem("tls_ja3_fingerprint", ja3 or "not available", None, None,
                         "MD5 fingerprint of observable ClientHello fields (JA3).", _flow_ids(ordered)),
            EvidenceItem("fingerprint_rarity", f"{rarity:.2f}", None, "score 0-1",
                         "Relative scarcity of the fingerprint among observed encrypted sessions in this dataset."),
            EvidenceItem("sni_observed", "absent" if sni_missing else "present", None, None,
                         "Server Name Indication is optional and its absence is not inherently malicious."),
            EvidenceItem("destination_port", str(port), None, None,
                         "Non-standard ports can indicate evasion, but also legitimate custom services."),
            EvidenceItem("sessions_observed", str(len(group)), None, "sessions",
                         "Number of sessions matching this fingerprint and endpoint pair."),
            EvidenceItem("payload_visibility", "not decrypted", None, None,
                         "SENTINEL AI never decrypts TLS or QUIC payloads; conclusions are limited to handshake metadata."),
        ]
        detections.append(
            Detection(
                detector_code="encrypted_metadata_detector",
                threat_class="Unusual_TLS_Metadata",
                source_ip=src,
                dest_ip=dst,
                source_port=0,
                dest_port=port,
                protocol="UDP" if any(f.quic for f in group) else "TCP",
                first_seen=ordered[0].ts,
                last_seen=ordered[-1].ts,
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(ordered),
                baseline={},
                scenario_id=_scenario_of(ordered),
                model_version_id=model_id,
                dedup_key=f"tls:{src}:{dst}:{port}:{ja3}",
            )
        )
    return detections


# ---------------------------------------------------------------------------
# 6. Data exfiltration
# ---------------------------------------------------------------------------


def detect_exfiltration(flows: list[FlowRecord], thresholds: dict | None = None) -> tuple[list[Detection], dict]:
    th = thresholds or {}
    min_outbound = float(th.get("min_outbound_bytes", 10_000_000))
    min_ratio = float(th.get("min_ratio", 6))
    baseline_multiple = float(th.get("baseline_multiple", 4))
    outbound = [f for f in flows if f.direction == "outbound" and f.bytes_out > 0]
    coverage = {
        "directional_flows": len(outbound),
        "flows_total": len(flows),
        "direction_available": len(outbound) > 0,
    }
    if not outbound:
        return [], coverage

    groups: dict[tuple[str, str], list[FlowRecord]] = defaultdict(list)
    for flow in outbound:
        groups[(flow.src_ip, flow.dst_ip)].append(flow)

    detections: list[Detection] = []
    for (src, dst), group in groups.items():
        out_bytes = sum(f.bytes_out for f in group)
        in_bytes = sum(f.bytes_in for f in group)
        if out_bytes < min_outbound:
            continue
        ratio = out_bytes / max(1, in_bytes)
        pair_volumes = sorted(
            sum(f.bytes_out for f in g) for (s, _d), g in groups.items() if s == src
        )
        baseline = _median([v for v in pair_volumes if v < out_bytes]) if len(pair_volumes) > 1 else None
        duration = max(1.0, (max(f.ts for f in group) - min(f.ts for f in group)).total_seconds())
        deviation = out_bytes / baseline if baseline else None
        if not (ratio >= min_ratio and (deviation is None or deviation >= baseline_multiple)):
            continue
        rule = _clamp(
            0.44
            + min(0.2, math.log10(max(1, out_bytes / 1_000_000)) * 0.1)
            + min(0.18, ratio / 80)
            + (0.08 if deviation and deviation >= 10 else 0)
        )
        features = {
            "out_bytes": out_bytes,
            "in_bytes": in_bytes,
            "ratio": round(ratio, 2),
            "duration_s": duration,
            "baseline_ratio": round(deviation or 0, 2),
        }
        confidence, ctype, model_id = _combine(rule, _model_score("exfiltration", features))
        summary = (
            f"{src} transferred {_fmt_bytes(out_bytes)} outbound to {dst} in "
            f"{duration/60:.0f} minutes, {ratio:.1f}x the inbound volume"
            f"{f' and {deviation:.1f}x this source’s typical per-destination volume' if deviation else ''}."
        )
        evidence = [
            EvidenceItem("outbound_bytes", _fmt_bytes(out_bytes), None, None,
                         "Bytes sent from the internal source to the external destination.", _flow_ids(group)),
            EvidenceItem("inbound_bytes", _fmt_bytes(in_bytes), None, None,
                         "Bytes received from the destination in the same sessions."),
            EvidenceItem("outbound_inbound_ratio", f"{ratio:.2f}", None, "ratio",
                         "Outbound bytes divided by inbound bytes."),
            EvidenceItem("baseline_destination_volume", _fmt_bytes(baseline) if baseline else "insufficient baseline",
                         None, None,
                         "Median outbound volume to other destinations by this source."),
            EvidenceItem("transfer_duration", f"{duration/60:.1f}", None, "minutes",
                         "Span between first and last observed flow in this pair."),
            EvidenceItem("direction_method", "configured internal network zones", None, None,
                         "Traffic direction is derived from workspace zone configuration, not guessed."),
        ]
        detections.append(
            Detection(
                detector_code="exfiltration_detector",
                threat_class="Possible_Data_Exfiltration",
                source_ip=src,
                dest_ip=dst,
                source_port=0,
                dest_port=Counter(f.dst_port for f in group).most_common(1)[0][0],
                protocol=Counter(f.protocol for f in group).most_common(1)[0][0],
                first_seen=min(f.ts for f in group),
                last_seen=max(f.ts for f in group),
                confidence=confidence,
                confidence_type=ctype,
                summary=summary,
                evidence=evidence,
                flow_ids=_flow_ids(group),
                baseline={"per_destination_volume": baseline},
                scenario_id=_scenario_of(group),
                model_version_id=model_id,
                dedup_key=f"exfil:{src}:{dst}",
            )
        )
    return detections, coverage


DETECTOR_FUNCTIONS = {
    "port_scan_detector": detect_port_scan,
    "ddos_detector": detect_ddos,
    "beaconing_detector": detect_beaconing,
    "dns_detector": detect_dns,
    "encrypted_metadata_detector": detect_encrypted,
}

EVIDENCE_COVERAGE = {
    "ddos_detector": ("packet rates, TCP flags, source cardinality and protocol mix", "packets"),
    "port_scan_detector": ("destination ports, connection attempts and TCP flags", "dst_port"),
    "beaconing_detector": ("repeated connection timestamps to a shared endpoint", "timestamps"),
    "dns_detector": ("DNS query names, record types and response codes", "dns_query"),
    "encrypted_metadata_detector": ("TLS ClientHello metadata (JA3, SNI, version, cipher)", "tls_ja3"),
    "exfiltration_detector": ("directional byte volumes based on configured zones", "bytes_out"),
}
