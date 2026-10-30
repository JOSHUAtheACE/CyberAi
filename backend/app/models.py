from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    role: Mapped[Role] = relationship(lazy="joined")


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)  # LIVE/REPLAY/DEMO
    description: Mapped[str] = mapped_column(Text, default="")
    internal_cidrs: Mapped[list] = mapped_column(
        JSON, default=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )


class TrafficSource(Base, TimestampMixin):
    __tablename__ = "traffic_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # netflow/ipfix/sflow/zeek/pcap
    identifier: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="DISCONNECTED")
    api_key_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_record_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    records_invalid: Mapped[int] = mapped_column(Integer, default=0)
    records_dropped: Mapped[int] = mapped_column(Integer, default=0)
    records_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    workspace: Mapped[Workspace] = relationship()


class IngestionJob(Base, TimestampMixin):
    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("traffic_sources.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # pcap/flows/zeek/feed
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="QUEUED")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    original_filename: Mapped[str] = mapped_column(String(255), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    records_valid: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)


class CaptureFile(Base):
    __tablename__ = "capture_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("ingestion_jobs.id"), unique=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    capture_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    capture_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    validation: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class FlowRecord(Base):
    __tablename__ = "flow_records"
    __table_args__ = (
        Index("ix_flow_env_ts", "environment", "ts"),
        Index("ix_flow_workspace_ts", "workspace_id", "ts"),
        Index("ix_flow_pair", "src_ip", "dst_ip"),
        Index("ix_flow_job", "job_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(24), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_jobs.id"), nullable=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("traffic_sources.id"), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(12), default="TCP")
    app_proto: Mapped[str | None] = mapped_column(String(32), nullable=True)
    bytes_total: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flags: Mapped[str | None] = mapped_column(String(32), nullable=True)
    direction: Mapped[str] = mapped_column(String(16), default="unknown")
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dns_qtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    dns_rcode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tls_sni: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_ja3: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String(24), nullable=True)
    tls_cipher: Mapped[str | None] = mapped_column(String(64), nullable=True)
    quic: Mapped[bool] = mapped_column(Boolean, default=False)
    src_country: Mapped[str | None] = mapped_column(String(4), nullable=True)
    src_city: Mapped[str | None] = mapped_column(String(120), nullable=True)
    src_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    src_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    dst_country: Mapped[str | None] = mapped_column(String(4), nullable=True)
    dst_city: Mapped[str | None] = mapped_column(String(120), nullable=True)
    dst_lat: Mapped[float | None] = mapped_column(Float, nullable=True)
    dst_lon: Mapped[float | None] = mapped_column(Float, nullable=True)
    geo_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    scenario_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    label: Mapped[str | None] = mapped_column(String(48), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class FeatureObservation(Base):
    __tablename__ = "feature_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    detector_code: Mapped[str] = mapped_column(String(48), index=True)
    entity: Mapped[str] = mapped_column(String(160))
    window_start: Mapped[datetime] = mapped_column(DateTime)
    window_end: Mapped[datetime] = mapped_column(DateTime)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DetectionModule(Base, TimestampMixin):
    __tablename__ = "detection_modules"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    threat_class: Mapped[str] = mapped_column(String(64), nullable=False)
    technique: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    model_name: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(24), default="")
    supported_inputs: Mapped[list] = mapped_column(JSON, default=list)
    feature_count: Mapped[int] = mapped_column(Integer, default=0)
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    detections_total: Mapped[int] = mapped_column(Integer, default=0)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    detector_code: Mapped[str] = mapped_column(String(48), index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(24), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(120), nullable=False)
    confidence_type: Mapped[str] = mapped_column(String(48), default="calibrated_probability")
    dataset_name: Mapped[str] = mapped_column(String(160), default="")
    dataset_version: Mapped[str] = mapped_column(String(32), default="")
    dataset_licence: Mapped[str] = mapped_column(String(120), default="")
    features: Mapped[list] = mapped_column(JSON, default=list)
    artifact_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE")
    metrics_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id: Mapped[int] = mapped_column(primary_key=True)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), index=True)
    dataset_name: Mapped[str] = mapped_column(String(160))
    dataset_version: Mapped[str] = mapped_column(String(32))
    dataset_licence: Mapped[str] = mapped_column(String(160))
    train_period: Mapped[str] = mapped_column(String(80), default="")
    validation_period: Mapped[str] = mapped_column(String(80), default="")
    test_period: Mapped[str] = mapped_column(String(80), default="")
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    class_distribution: Mapped[dict] = mapped_column(JSON, default=dict)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    roc_auc: Mapped[float | None] = mapped_column(Float, nullable=True)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SecurityAlert(Base, TimestampMixin):
    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_alert_env_first", "environment", "first_seen"),
        Index("ix_alert_env_status", "environment", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_code: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    threat_class: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_type: Mapped[str] = mapped_column(String(48), default="heuristic_score")
    detector_code: Mapped[str] = mapped_column(String(48), index=True)
    model_version_id: Mapped[int | None] = mapped_column(ForeignKey("model_versions.id"), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, default=0)
    dest_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    dest_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(12), default="TCP")
    status: Mapped[str] = mapped_column(String(24), default="OPEN")
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    data_source: Mapped[str] = mapped_column(String(64), default="ingested_flow_capture")
    scenario_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    flow_ids: Mapped[list] = mapped_column(JSON, default=list)
    baseline: Mapped[dict] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    recurrence: Mapped[int] = mapped_column(Integer, default=1)
    assignee: Mapped[User | None] = relationship(lazy="joined")


class AlertEvidence(Base):
    __tablename__ = "alert_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"), index=True)
    kind: Mapped[str] = mapped_column(String(48), default="feature")
    feature: Mapped[str] = mapped_column(String(120))
    observed_value: Mapped[str] = mapped_column(String(255))
    baseline_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    unit: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    flow_ids: Mapped[list] = mapped_column(JSON, default=list)


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_code: Mapped[str] = mapped_column(String(24), unique=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(24), default="OPEN")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    alert: Mapped[SecurityAlert] = relationship()
    owner: Mapped[User | None] = relationship(lazy="joined")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("investigation_cases.id"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    author: Mapped[User] = relationship(lazy="joined")


class AlertLink(Base):
    __tablename__ = "alert_links"
    __table_args__ = (UniqueConstraint("alert_id", "related_alert_id", name="uq_alert_link"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"), index=True)
    related_alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"))


class ThreatIntelIndicator(Base):
    __tablename__ = "threat_intel_indicators"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(48), index=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(24), default="ip")
    verdict: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    licence: Mapped[str | None] = mapped_column(String(160), nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(48), index=True)
    indicator: Mapped[str] = mapped_column(String(255))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("security_alerts.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="OK")
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ProviderConfig(Base, TimestampMixin):
    __tablename__ = "provider_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(48), default="threat_intelligence")
    docs_url: Mapped[str] = mapped_column(String(255), default="")
    credential_env: Mapped[list] = mapped_column(JSON, default=list)
    configured: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(24), default="NOT_CONFIGURED")
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit: Mapped[dict] = mapped_column(JSON, default=dict)
    attribution: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime)
    period_end: Mapped[datetime] = mapped_column(DateTime)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="READY")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ReplaySession(Base):
    __tablename__ = "replay_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    dataset_id: Mapped[int | None] = mapped_column(ForeignKey("demo_datasets.id"), nullable=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_jobs.id"), nullable=True)
    dataset_label: Mapped[str] = mapped_column(String(160), default="")
    environment: Mapped[str] = mapped_column(String(16), default="DEMO")
    status: Mapped[str] = mapped_column(String(24), default="READY")
    speed: Mapped[float] = mapped_column(Float, default=1.0)
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)
    current_rate: Mapped[float] = mapped_column(Float, default=0.0)
    processing_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    categories: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DemoDataset(Base):
    __tablename__ = "demo_datasets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    threat_class: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    expected_features: Mapped[list] = mapped_column(JSON, default=list)
    ground_truth: Mapped[dict] = mapped_column(JSON, default=dict)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    timespan: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RuntimeSetting(Base):
    __tablename__ = "runtime_settings"

    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class SystemEvent(Base):
    __tablename__ = "system_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    level: Mapped[str] = mapped_column(String(16), default="INFO")
    category: Mapped[str] = mapped_column(String(48), default="system")
    message: Mapped[str] = mapped_column(String(512))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_email: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource_type: Mapped[str] = mapped_column(String(48), default="")
    resource_id: Mapped[str] = mapped_column(String(64), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
