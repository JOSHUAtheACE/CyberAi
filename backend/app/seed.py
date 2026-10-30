from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import ml
from .config import DEMO_PASSWORD
from .demo import generate_demo_corpus
from .models import (
    AlertLink,
    DemoDataset,
    DetectionModule,
    FlowRecord,
    InvestigationCase,
    InvestigationNote,
    ModelVersion,
    ProviderConfig,
    Role,
    RuntimeSetting,
    SecurityAlert,
    SystemEvent,
    TrafficSource,
    User,
    Workspace,
    utcnow,
)
from .pipeline import insert_flows, run_detection
from .security import ROLE_DEFINITIONS, hash_password

DEMO_USERS = [
    ("analyst@sentinela.ai", "Maya Chen", "soc_analyst"),
    ("engineer@sentinela.ai", "Jonas Weber", "network_engineer"),
    ("ml@sentinela.ai", "Priya Raman", "ml_engineer"),
    ("auditor@sentinela.ai", "Alex Morgan", "auditor"),
]

MODULE_DEFINITIONS = [
    {
        "code": "ddos_detector",
        "name": "DDoS Baseline Detector",
        "threat_class": "Possible_DDoS",
        "technique": "Sliding-window baseline deviation with protocol and flag composition analysis",
        "description": (
            "Compares per-destination packet and bit rates against an observed baseline and "
            "characterises SYN/ACK imbalance, source cardinality and UDP reflector patterns. "
            "Source entropy alone is never treated as proof of spoofing."
        ),
        "model_name": "Statistical baseline (no trained model)",
        "version": "stat-1.3.0",
        "feature_count": 6,
        "supported_inputs": ["flow_records", "packet_counts", "tcp_flags", "byte_counts"],
        "thresholds": {
            "pps_floor": 120,
            "baseline_multiple": 5,
            "syn_ratio": 0.6,
            "volumetric_bps": 2_000_000,
        },
    },
    {
        "code": "port_scan_detector",
        "name": "Port Fan-Out Detector",
        "threat_class": "Possible_Port_Scan",
        "technique": "Destination-port fan-out analysis with a calibrated Random Forest model",
        "description": (
            "Measures unique destination ports and hosts per source, failed-connection ratio and "
            "port entropy over a five-minute window, then combines the rule score with the "
            "calibrated model output."
        ),
        "model_name": "Port Scan Classifier",
        "version": "1.0.0",
        "feature_count": 6,
        "supported_inputs": ["flow_records", "destination_ports", "tcp_flags"],
        "thresholds": {"unique_ports": 20, "unique_hosts": 12, "attempts": 30, "window_seconds": 300},
    },
    {
        "code": "beaconing_detector",
        "name": "C2 Beaconing Detector",
        "threat_class": "Possible_C2_Beaconing",
        "technique": "Inter-arrival periodicity analysis with Isolation Forest support scoring",
        "description": (
            "Groups repeated connections to a shared endpoint, then evaluates interval regularity, "
            "coefficient of variation and destination concentration. Requires an extended "
            "observation window; observation time is reported separately from processing latency."
        ),
        "model_name": "Beaconing Anomaly Model",
        "version": "1.0.0",
        "feature_count": 6,
        "supported_inputs": ["flow_records", "timestamps", "destination_endpoints"],
        "thresholds": {"min_connections": 6, "max_cv": 0.4, "interval_bounds_seconds": [10, 3600]},
    },
    {
        "code": "dns_detector",
        "name": "DGA & Tunnelling Detector",
        "threat_class": "Possible_DGA_or_DNS_Tunnelling",
        "technique": "Domain entropy statistics plus calibrated character n-gram classification",
        "description": (
            "Analyses query-name entropy, label length, record types, NXDOMAIN ratio and query "
            "rate. If query names or response data were not captured, the module reports "
            "insufficient visibility rather than inferring behaviour."
        ),
        "model_name": "DGA / Tunnelling Domain Classifier",
        "version": "1.0.0",
        "feature_count": 8,
        "supported_inputs": ["dns_query_names", "dns_record_types", "dns_response_codes"],
        "thresholds": {"mean_entropy": 3.35, "min_queries": 12, "label_length": 38, "window_seconds": 600},
    },
    {
        "code": "encrypted_metadata_detector",
        "name": "TLS / QUIC Metadata Analyser",
        "threat_class": "Unusual_TLS_Metadata",
        "technique": "Handshake fingerprint rarity and endpoint heuristics (metadata only)",
        "description": (
            "Inspects observable TLS ClientHello metadata (JA3, SNI, version, cipher) and QUIC "
            "transport indicators. Payloads are never decrypted and fingerprint rarity alone "
            "is capped below high severity."
        ),
        "model_name": "Heuristic metadata analyser",
        "version": "heur-1.1.0",
        "feature_count": 5,
        "supported_inputs": ["tls_ja3", "tls_sni", "tls_version", "tls_cipher", "quic"],
        "thresholds": {"rarity_floor": 0.6, "max_confidence": 0.7},
    },
    {
        "code": "exfiltration_detector",
        "name": "Data Exfiltration Detector",
        "threat_class": "Possible_Data_Exfiltration",
        "technique": "Directional volume baselines with a calibrated Gradient Boosting model",
        "description": (
            "Compares outbound volume and outbound/inbound ratio against per-source baselines. "
            "Traffic direction is derived from configured network zones; when direction is "
            "unavailable, the assessment is marked incomplete instead of estimated."
        ),
        "model_name": "Data Exfiltration Classifier",
        "version": "1.0.0",
        "feature_count": 5,
        "supported_inputs": ["directional_bytes", "flow_duration", "configured_zones"],
        "thresholds": {"min_outbound_bytes": 10_000_000, "min_ratio": 6, "baseline_multiple": 4},
    },
]

PROVIDERS = [
    {
        "provider": "threatfox",
        "display_name": "ThreatFox (abuse.ch)",
        "docs_url": "https://threatfox.abuse.ch/api/",
        "credential_env": ["THREATFOX_AUTH_KEY"],
        "attribution": "abuse.ch / ThreatFox",
        "rate_limit": {"requests_per_minute": 60, "tracking": "provider headers, retry-after aware"},
        "notes": "IOC search for public indicators only; requests disabled unless approved.",
    },
    {
        "provider": "urlhaus",
        "display_name": "URLhaus (abuse.ch)",
        "docs_url": "https://urlhaus.abuse.ch/api/",
        "credential_env": ["URLHAUS_AUTH_KEY"],
        "attribution": "abuse.ch / URLhaus",
        "rate_limit": {"requests_per_minute": 60, "tracking": "provider headers"},
        "notes": "Malware URL/host reputation lookup for public indicators.",
    },
    {
        "provider": "abuseipdb",
        "display_name": "AbuseIPDB",
        "docs_url": "https://docs.abuseipdb.com/",
        "credential_env": ["ABUSEIPDB_API_KEY"],
        "attribution": "AbuseIPDB",
        "rate_limit": {"requests_per_minute": 60, "daily_quota": 1000},
        "notes": "IP reputation reporting; external enrichment requires administrator approval.",
    },
    {
        "provider": "greynoise",
        "display_name": "GreyNoise",
        "docs_url": "https://docs.greynoise.io/",
        "credential_env": ["GREYNOISE_API_KEY"],
        "attribution": "GreyNoise Intelligence",
        "rate_limit": {"requests_per_minute": 60},
        "notes": "Contextual classification of internet background noise (community API).",
    },
    {
        "provider": "maxmind",
        "display_name": "MaxMind GeoLite2",
        "docs_url": "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        "credential_env": ["MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY", "MAXMIND_DB_PATH"],
        "attribution": "MaxMind GeoLite2",
        "rate_limit": {"note": "Local database lookup; no per-request network calls"},
        "notes": "Local geolocation enrichment. Coordinates approximate network registration, not physical devices.",
    },
    {
        "provider": "offline_snapshot",
        "display_name": "Offline TI snapshot",
        "docs_url": "https://github.com/",
        "credential_env": [],
        "attribution": "Administrator-imported snapshot",
        "rate_limit": {"note": "Local import only — suitable for air-gapped deployments"},
        "notes": "Imports a signed-off JSON indicator snapshot with source, licence and validity metadata.",
    },
]


def _ensure_roles(db: Session) -> None:
    for definition in ROLE_DEFINITIONS:
        role = db.query(Role).filter(Role.code == definition["code"]).first()
        if not role:
            db.add(
                Role(
                    code=definition["code"],
                    name=definition["name"],
                    description=definition["description"],
                    permissions=definition["permissions"],
                )
            )
            continue
        # Keep permission definitions authoritative across upgrades.
        role.name = definition["name"]
        role.description = definition["description"]
        role.permissions = definition["permissions"]
    db.flush()


def _ensure_users(db: Session) -> None:
    roles = {r.code: r for r in db.query(Role).all()}
    accounts = [
        (os.environ.get("SENTINEL_ADMIN_EMAIL", "admin@sentinela.ai"), "Avery Stone", "security_admin", False),
        *[(email, name, role, True) for email, name, role in DEMO_USERS],
    ]
    password = os.environ.get("SENTINEL_ADMIN_PASSWORD", DEMO_PASSWORD)
    for email, name, role_code, is_demo in accounts:
        if db.query(User).filter(User.email == email).first():
            continue
        db.add(
            User(
                email=email,
                name=name,
                role_id=roles[role_code].id,
                password_hash=hash_password(DEMO_PASSWORD if is_demo else password),
                is_demo=is_demo,
            )
        )
    db.flush()


def _ensure_workspaces(db: Session) -> dict[str, Workspace]:
    definitions = [
        ("live-ops", "Live Operations", "LIVE", "Production monitoring enclave. Receives telemetry from approved collectors only."),
        ("demo", "Demo Workspace", "DEMO", "Synthetic demonstration workspace. Never mixed with live telemetry."),
        ("replay-lab", "Replay Lab", "REPLAY", "Re-processes recorded captures and demo scenarios at a controlled rate."),
    ]
    result: dict[str, Workspace] = {}
    for slug, name, environment, description in definitions:
        ws = db.query(Workspace).filter(Workspace.slug == slug).first()
        if not ws:
            ws = Workspace(
                slug=slug,
                name=name,
                environment=environment,
                description=description,
                internal_cidrs=["10.20.0.0/16"] if environment != "LIVE" else ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            )
            db.add(ws)
            db.flush()
        result[slug] = ws
    return result


def _ensure_modules(db: Session) -> None:
    for definition in MODULE_DEFINITIONS:
        if db.query(DetectionModule).filter(DetectionModule.code == definition["code"]).first():
            continue
        db.add(
            DetectionModule(
                code=definition["code"],
                name=definition["name"],
                threat_class=definition["threat_class"],
                technique=definition["technique"],
                description=definition["description"],
                model_name=definition["model_name"],
                version=definition["version"],
                feature_count=definition["feature_count"],
                supported_inputs=definition["supported_inputs"],
                thresholds=definition["thresholds"],
                status="ACTIVE",
                enabled=True,
            )
        )
    db.flush()


def _ensure_providers(db: Session) -> None:
    for definition in PROVIDERS:
        provider = db.query(ProviderConfig).filter(ProviderConfig.provider == definition["provider"]).first()
        configured = (
            definition["provider"] == "offline_snapshot"
            or all(bool(os.environ.get(name)) for name in definition["credential_env"])
            or (definition["provider"] == "maxmind" and bool(os.environ.get("MAXMIND_DB_PATH")))
        )
        if provider:
            provider.configured = configured
            if configured and provider.status == "NOT_CONFIGURED":
                provider.status = "READY"
            continue
        db.add(
            ProviderConfig(
                provider=definition["provider"],
                display_name=definition["display_name"],
                docs_url=definition["docs_url"],
                credential_env=definition["credential_env"],
                attribution=definition["attribution"],
                rate_limit=definition["rate_limit"],
                notes=definition["notes"],
                configured=configured,
                enabled=definition["provider"] == "offline_snapshot",
                status="READY" if configured else "NOT_CONFIGURED",
            )
        )
    db.flush()


def _ensure_runtime_settings(db: Session) -> None:
    defaults = {
        "external_enrichment": {"enabled": False},
        "retention": {"flow_days": 90, "alert_days": 365, "audit_days": 730},
        "notifications": {"critical_email": False, "webhook": ""},
        "demo_mode": {"enabled": True},
    }
    for key, value in defaults.items():
        if not db.get(RuntimeSetting, key):
            db.add(RuntimeSetting(key=key, value=value))
    db.flush()


def _ensure_sources(db: Session, workspaces: dict[str, Workspace]) -> None:
    definitions = [
        (workspaces["live-ops"], "Core NetFlow Collector", "netflow", "collector-core-01"),
        (workspaces["live-ops"], "DMZ Zeek Sensor", "zeek", "sensor-dmz-02"),
        (workspaces["live-ops"], "Edge sFlow Agent", "sflow", "agent-edge-07"),
    ]
    for workspace, name, kind, identifier in definitions:
        if db.query(TrafficSource).filter(TrafficSource.identifier == identifier).first():
            continue
        db.add(
            TrafficSource(
                workspace_id=workspace.id,
                name=name,
                kind=kind,
                identifier=identifier,
                status="DISCONNECTED",
                config={
                    "transport": "Collector push over approved one-way monitoring path",
                    "deployment_note": "Collector runs inside the monitoring enclave; the browser is never a packet source.",
                },
            )
        )
    db.flush()


def _seed_demo(db: Session, workspaces: dict[str, Workspace]) -> None:
    demo_ws = workspaces["demo"]
    corpus = generate_demo_corpus()
    datasets = {item["scenario_id"]: item for item in corpus["datasets"]}

    for item in corpus["datasets"]:
        if db.query(DemoDataset).filter(DemoDataset.scenario_id == item["scenario_id"]).first():
            continue
        db.add(
            DemoDataset(
                scenario_id=item["scenario_id"],
                name=item["name"],
                threat_class=item["threat_class"],
                description=item["description"],
                expected_features=item["expected_features"],
                ground_truth=item["ground_truth"],
                timespan=item["timespan"],
                flow_count=sum(1 for f in corpus["flows"] if f.scenario_id == item["scenario_id"]),
            )
        )
    db.flush()

    existing_flows = (
        db.query(func.count(FlowRecord.id))
        .filter(FlowRecord.workspace_id == demo_ws.id)
        .scalar()
        or 0
    )
    if existing_flows == 0:
        flows = corpus["flows"]
        inserted: list[FlowRecord] = []
        for index in range(0, len(flows), 800):
            inserted.extend(
                insert_flows(
                    db,
                    workspace=demo_ws,
                    environment="DEMO",
                    flows=flows[index : index + 800],
                    demo=True,
                )
            )
        db.flush()
        result = run_detection(
            db,
            workspace=demo_ws,
            environment="DEMO",
            flows=inserted,
            data_source="synthetic_demo_corpus",
            broadcast=False,
        )
        db.add(
            SystemEvent(
                category="demo",
                message=(
                    f"Demo corpus loaded: {len(inserted):,} synthetic flow records and "
                    f"{result['alerts_created']} evidence-backed alerts across all six modules."
                ),
                meta={"datasets": len(datasets), "alerts": result["alerts_created"]},
            )
        )

    _decorate_demo_alerts(db)
    db.flush()


def _decorate_demo_alerts(db: Session) -> None:
    """Give a subset of demo alerts realistic investigation states and notes."""
    analyst = db.query(User).filter(User.email == "analyst@sentinela.ai").first()
    if not analyst:
        return
    alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.environment == "DEMO")
        .order_by(SecurityAlert.id.desc())
        .all()
    )
    if not alerts:
        return
    patterns = ["ACKNOWLEDGED", "OPEN", "INVESTIGATING", "OPEN", "FALSE_POSITIVE", "OPEN", "CLOSED"]
    notes = [
        "Confirmed with the network team that this egress path is not part of the approved service catalogue.",
        "Cross-checked against the change calendar — no matching maintenance window.",
        "Host owner contacted; monitoring continues while scoping is reviewed. No active remediation applied from this platform.",
        "Reviewed the raw evidence. Behaviour matches a scheduled backup window; marked as false positive by the analyst.",
    ]
    for index, alert in enumerate(alerts):
        status = patterns[index % len(patterns)]
        if alert.status != "OPEN" and alert.status != status:
            continue
        alert.status = status
        if status != "OPEN":
            alert.assignee_id = analyst.id
            case = (
                db.query(InvestigationCase)
                .filter(InvestigationCase.alert_id == alert.id)
                .first()
            )
            if not case:
                db.flush()
                case = InvestigationCase(
                    case_code=f"CASE-{alert.id:05d}",
                    alert_id=alert.id,
                    title=f"{alert.threat_class.replace('_', ' ')} — {alert.source_ip} → {alert.dest_ip}",
                    status="CLOSED" if status in {"CLOSED", "FALSE_POSITIVE"} else "IN_PROGRESS",
                    owner_id=analyst.id,
                )
                db.add(case)
                db.flush()
            if index % 3 == 0:
                db.add(
                    InvestigationNote(
                        case_id=case.id,
                        author_id=analyst.id,
                        body=notes[index % len(notes)],
                    )
                )
    # Persist a couple of related-alert links across the same source.
    db.flush()
    grouped: dict[str, list[SecurityAlert]] = {}
    for alert in alerts:
        grouped.setdefault(alert.source_ip, []).append(alert)
    for group in grouped.values():
        if len(group) >= 2:
            exists = (
                db.query(AlertLink)
                .filter(
                    AlertLink.alert_id == group[0].id,
                    AlertLink.related_alert_id == group[1].id,
                )
                .first()
            )
            if not exists:
                db.add(AlertLink(alert_id=group[0].id, related_alert_id=group[1].id))


def seed_database(db: Session) -> dict:
    _ensure_roles(db)
    _ensure_users(db)
    workspaces = _ensure_workspaces(db)
    _ensure_modules(db)
    _ensure_providers(db)
    _ensure_runtime_settings(db)
    _ensure_sources(db, workspaces)

    if not db.query(ModelVersion).first():
        ml.train_all(db, version="1.0.0")
    ml.load_active_models(db)

    _seed_demo(db, workspaces)

    if not db.query(SystemEvent).filter(SystemEvent.category == "system").first():
        db.add(
            SystemEvent(
                category="system",
                message="SENTINEL AI monitoring platform initialised. External enrichment disabled by default.",
                meta={"one_way_boundary": True, "demo_mode": True},
            )
        )
    db.commit()
    return {"workspaces": list(workspaces.keys()), "demo": True}
