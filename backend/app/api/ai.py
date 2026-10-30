from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ml
from ..database import get_db
from ..deps import record_audit, require_permissions
from ..models import DetectionModule, ModelVersion, User, utcnow
from ..serializers import iso, module_payload
from .dashboard import _build_insights, get_workspace_or_404, window

router = APIRouter(prefix="/ai", tags=["AI & models"])

MODEL_CODES = {
    "port_scan_detector": "scanning",
    "exfiltration_detector": "exfiltration",
    "dns_detector": "dns",
    "beaconing_detector": "beaconing",
}


def _model_summary(row: ModelVersion | None) -> dict | None:
    if not row:
        return None
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "algorithm": row.algorithm,
        "confidence_type": row.confidence_type,
        "dataset_name": row.dataset_name,
        "dataset_version": row.dataset_version,
        "dataset_licence": row.dataset_licence,
        "features": row.features,
        "status": row.status,
        "metrics_summary": row.metrics_summary,
        "trained_at": iso(row.trained_at),
    }


@router.get("/overview")
def ai_overview(
    user: User = Depends(require_permissions("ai.view")),
    db: Session = Depends(get_db),
):
    catalog = ml.model_catalog(db)
    modules = db.query(DetectionModule).order_by(DetectionModule.id).all()
    active_models: dict[str, ModelVersion] = {}
    for row in (
        db.query(ModelVersion)
        .filter(ModelVersion.status == "ACTIVE")
        .order_by(ModelVersion.trained_at.desc())
        .all()
    ):
        active_models.setdefault(row.detector_code, row)

    evaluations = {}
    for code, row in active_models.items():
        payload = ml.evaluation_payload(db, row.id)
        if payload:
            evaluations[row.id] = payload

    detectors = []
    for module in modules:
        model_code = MODEL_CODES.get(module.code)
        model = active_models.get(model_code) if model_code else None
        item = module_payload(module)
        item.update(
            {
                "ml_supported": bool(model_code),
                "model_code": model_code,
                "model": _model_summary(model),
                "evaluation": evaluations.get(model.id) if model else None,
            }
        )
        detectors.append(item)

    dataset_versions = sorted({row.dataset_version for row in active_models.values() if row.dataset_version})
    dataset_names = sorted({row.dataset_name for row in active_models.values() if row.dataset_name})
    return {
        "generated_at": iso(utcnow()),
        "models": catalog,
        "detectors": detectors,
        "active_model_versions": {
            code: _model_summary(row) for code, row in active_models.items()
        },
        "dataset_provenance": {
            "names": dataset_names,
            "versions": dataset_versions,
            "description": (
                "Models are trained and evaluated on the labelled synthetic corpus shipped with the "
                "platform: a 24-hour behavioural baseline plus labelled scenario bursts per detector. "
                "Grouped scenario splits prevent records from the same scenario leaking across splits."
            ),
            "licence": "Synthetic in-house dataset (no third-party personal data)",
            "not_production_accuracy": True,
        },
        "score_semantics": [
            {"type": "calibrated_probability", "meaning": "Calibrated classifier probability on labelled synthetic data."},
            {"type": "hybrid_score", "meaning": "Deterministic rule evidence blended with model score; not a probability."},
            {"type": "heuristic_score", "meaning": "Rule/heuristic strength indicator; not a probability."},
            {"type": "anomaly_score", "meaning": "IsolationForest-derived anomaly strength; not a probability of compromise."},
        ],
        "coverage_notes": [
            {
                "detector": module.code,
                "reason": (
                    "Behavioural model requires repeated observations and timing fields."
                    if module.code in {"beaconing_detector", "dns_detector", "exfiltration_detector"}
                    else "Requires packet, port and byte fields from the ingested telemetry."
                ),
            }
            for module in modules
        ],
        "disclaimer": (
            "Every metric shown was measured on the labelled synthetic evaluation split. "
            "These are engineering benchmarks, not production detection accuracy claims."
        ),
    }


@router.get("/models/{model_id}/evaluation")
def model_evaluation(
    model_id: int,
    user: User = Depends(require_permissions("ai.view")),
    db: Session = Depends(get_db),
):
    payload = ml.evaluation_payload(db, model_id)
    if not payload:
        raise HTTPException(status_code=404, detail="No evaluation recorded for this model version")
    return payload


class TrainRequest(BaseModel):
    version: str | None = None


@router.post("/train")
def train_models(
    payload: TrainRequest,
    user: User = Depends(require_permissions("ai.models.manage")),
    db: Session = Depends(get_db),
):
    version = (payload.version or utcnow().strftime("%Y.%m.%d-%H%M")).strip()[:24]
    versions = ml.train_all(db, version=version)
    ml.load_active_models(db)
    record_audit(
        db,
        actor=user,
        action="ai.models_trained",
        resource_type="model_version",
        resource_id=",".join(str(row.id) for row in versions),
        meta={"version": version, "models": len(versions)},
    )
    db.commit()
    return {
        "version": version,
        "trained": len(versions),
        "models": ml.model_catalog(db),
        "notice": "Training and evaluation ran locally on the labelled synthetic dataset.",
    }


class DetectorUpdate(BaseModel):
    thresholds: dict | None = None
    enabled: bool | None = None


@router.patch("/detectors/{code}")
def update_detector(
    code: str,
    payload: DetectorUpdate,
    user: User = Depends(require_permissions("thresholds.manage")),
    db: Session = Depends(get_db),
):
    module = db.query(DetectionModule).filter(DetectionModule.code == code).first()
    if not module:
        raise HTTPException(status_code=404, detail="Detection module not found")

    changes: dict = {}
    if payload.thresholds is not None:
        current = dict(module.thresholds or {})
        for key, value in payload.thresholds.items():
            if key not in current:
                raise HTTPException(status_code=400, detail=f"Unknown threshold: {key}")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise HTTPException(status_code=400, detail=f"Threshold {key} must be numeric")
            if value < 0:
                raise HTTPException(status_code=400, detail=f"Threshold {key} must be non-negative")
            current[key] = value
        module.thresholds = current
        changes["thresholds"] = current
    if payload.enabled is not None:
        module.enabled = payload.enabled
        module.status = "ACTIVE" if payload.enabled else "DISABLED"
        changes["enabled"] = payload.enabled
    if not changes:
        raise HTTPException(status_code=400, detail="No supported changes supplied")

    record_audit(
        db,
        actor=user,
        action="detector.config_updated",
        resource_type="detection_module",
        resource_id=module.id,
        meta=changes,
    )
    db.commit()
    db.refresh(module)
    return module_payload(module)


@router.get("/insights")
def insights(
    workspace: str = Query("live-ops"),
    range: str = Query("24h"),
    start: str | None = None,
    end: str | None = None,
    user: User = Depends(require_permissions("ai.view")),
    db: Session = Depends(get_db),
):
    ws = get_workspace_or_404(db, workspace)
    start_dt, end_dt, label = window(range, start, end)
    result = _build_insights(db, ws, start_dt, end_dt)
    result["period"] = {"label": label, "start": iso(start_dt), "end": iso(end_dt)}
    result["workspace"] = {"slug": ws.slug, "environment": ws.environment}
    return result
