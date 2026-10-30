"""Detection model training and evaluation.

All reported metrics are produced by real evaluation runs against the labelled
synthetic demonstration dataset shipped with this project. They are not
production accuracy claims. Evaluation splits are grouped by synthetic scenario
so the same behavioural scenario never appears in both training and test data.
"""

from __future__ import annotations

import json
import math
import time
from datetime import datetime
from pathlib import Path
from threading import Lock

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    auc,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from .config import MODEL_DIR
from .models import ModelEvaluation, ModelVersion
from .security import utc_now

DATASET_NAME = "SENTINEL AI labelled synthetic scenarios"
DATASET_VERSION = "2026.10.1"
DATASET_LICENCE = "Project fixture — synthetic, redistributable with this repository"

FEATURE_SETS: dict[str, list[str]] = {
    "scanning": [
        "unique_ports", "unique_hosts", "attempts", "duration_s", "failed_ratio", "port_entropy",
    ],
    "beaconing": ["connections", "cv"],
    "exfiltration": ["out_bytes", "in_bytes", "ratio", "duration_s", "baseline_ratio"],
}

_CACHE: dict[str, dict] = {}
_CACHE_LOCK = Lock()


def _rng(seed: int = 42) -> np.random.Generator:
    return np.random.default_rng(seed)


# ---------------------------------------------------------------------------
# Synthetic training data (deterministic)
# ---------------------------------------------------------------------------


def _scanning_samples(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rows, labels, groups = [], [], []
    for scenario in range(220):
        malicious = scenario % 5 in (0, 1)
        if malicious:
            unique_ports = int(rng.integers(12, 600))
            unique_hosts = int(rng.integers(1, 90))
            duration = float(rng.uniform(15, 420))
            failed = float(rng.uniform(0.45, 0.99))
            entropy = float(rng.uniform(2.4, 6.4))
            if rng.random() < 0.08:
                # slow, narrow scans resemble cautious administrative probing
                unique_ports = int(rng.integers(8, 24))
                unique_hosts = int(rng.integers(1, 4))
                duration = float(rng.uniform(300, 2400))
                failed = float(rng.uniform(0.25, 0.50))
                entropy = float(rng.uniform(1.8, 3.2))
            attempts = int(unique_ports * rng.uniform(1.0, 3.2))
        else:
            unique_ports = int(rng.integers(1, 16))
            unique_hosts = int(rng.integers(1, 6))
            duration = float(rng.uniform(10, 1200))
            failed = float(rng.uniform(0.0, 0.35))
            entropy = float(rng.uniform(0.5, 3.0))
            if rng.random() < 0.10:
                # authorised availability checks sweep many ports too
                unique_ports = int(rng.integers(16, 64))
                unique_hosts = int(rng.integers(2, 10))
                failed = float(rng.uniform(0.20, 0.60))
                entropy = float(rng.uniform(2.5, 4.5))
            attempts = int(unique_ports * rng.uniform(1.0, 4.0))
        rows.append([unique_ports, unique_hosts, attempts, duration, failed, entropy])
        labels.append(1 if malicious else 0)
        groups.append(f"scan-scenario-{scenario}")
    return np.array(rows, dtype=float), np.array(labels), np.array(groups)


def _exfil_samples(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rows, labels, groups = [], [], []
    for scenario in range(220):
        malicious = scenario % 5 in (0, 1)
        if malicious:
            out_bytes = float(rng.uniform(12_000_000, 2_000_000_000))
            in_bytes = float(rng.uniform(5_000, 900_000))
            duration = float(rng.uniform(120, 3600))
            baseline_ratio = float(rng.uniform(3.5, 40))
            if rng.random() < 0.08:
                # low-and-slow exfiltration stays below naive volume thresholds
                out_bytes = float(rng.uniform(1_500_000, 15_000_000))
                in_bytes = float(rng.uniform(100_000, 1_200_000))
                duration = float(rng.uniform(1800, 7200))
                baseline_ratio = float(rng.uniform(2.2, 4.5))
        else:
            out_bytes = float(rng.uniform(200_000, 40_000_000))
            in_bytes = float(rng.uniform(50_000, 120_000_000))
            duration = float(rng.uniform(30, 5400))
            baseline_ratio = float(rng.uniform(0.6, 3.2))
            if rng.random() < 0.08:
                # legitimate backup uploads are large and outbound-heavy
                out_bytes = float(rng.uniform(150_000_000, 1_500_000_000))
                in_bytes = float(rng.uniform(100_000, 2_000_000))
                duration = float(rng.uniform(600, 5400))
                baseline_ratio = float(rng.uniform(2.8, 6.0))
        ratio = out_bytes / max(1.0, in_bytes)
        rows.append([out_bytes, in_bytes, ratio, duration, baseline_ratio])
        labels.append(1 if malicious else 0)
        groups.append(f"exfil-scenario-{scenario}")
    return np.array(rows, dtype=float), np.array(labels), np.array(groups)


def _beacon_samples(rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Synthetic beacon vs. periodic-benign observation windows.

    Each scenario contributes four windows so the grouped split operates on whole
    behavioural scenarios rather than on individual rows. Most benign periodic
    traffic is jittery, but a small share of scheduled jobs is regular enough to
    resemble a beacon, keeping the evaluation non-trivial. Features are limited
    to repetition count and interval regularity: mean/min/max interval are
    derived quantities that dilute the isolation signal, and the detector already
    gates on interval scale and dominant-bucket share.
    """
    rows, labels, groups = [], [], []
    for scenario in range(260):
        malicious = scenario % 2 == 0
        if malicious:
            base_cv = float(rng.uniform(0.01, 0.30))
            if rng.random() < 0.10:
                base_cv = float(rng.uniform(0.30, 0.45))
            base_connections = int(rng.integers(18, 120))
        else:
            base_cv = float(rng.uniform(0.45, 1.9))
            if rng.random() < 0.08:
                base_cv = float(rng.uniform(0.18, 0.45))
            base_connections = int(rng.integers(5, 55))
        for _ in range(4):
            cv = max(0.002, base_cv * float(rng.uniform(0.90, 1.15)))
            connections = max(5, int(round(base_connections * float(rng.uniform(0.90, 1.15)))))
            rows.append([connections, cv])
            labels.append(1 if malicious else 0)
            groups.append(f"beacon-scenario-{scenario}")
    return np.array(rows, dtype=float), np.array(labels), np.array(groups)


_LEGIT_DOMAINS = [
    "api.github.com", "login.microsoftonline.com", "www.google.com", "cdn.cloudflare.com",
    "s3.amazonaws.com", "registry.npmjs.org", "docs.python.org", "outlook.office365.com",
    "graph.facebook.com", "time.windows.com", "ocsp.digicert.com", "update.googleapis.com",
    "analytics.localhost.example", "telemetry.vendor.example", "login.okta.com",
    "api.stripe.com", "status.slack.com", "cdn.jsdelivr.net", "fonts.gstatic.com",
    "ntp.ubuntu.com", "pypi.org", "sentry.io", "datadoghq.com", "zoom.us",
]


def _dga_domains(rng: np.random.Generator, count: int) -> list[str]:
    alphabets = ["abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz", "0123456789abcdef"]
    tlvs = ["top", "xyz", "biz", "info", "click", "live", "online"]
    out = []
    for _ in range(count):
        alphabet = alphabets[int(rng.integers(0, len(alphabets)))]
        labels = []
        for _ in range(int(rng.integers(1, 3))):
            labels.append("".join(rng.choice(list(alphabet), int(rng.integers(10, 34)))))
        out.append(".".join(labels) + "." + tlvs[int(rng.integers(0, len(tlvs)))])
    return out


def _tunnel_domains(rng: np.random.Generator, count: int) -> list[str]:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    out = []
    for _ in range(count):
        label = "".join(rng.choice(list(alphabet), int(rng.integers(40, 63))))
        out.append(f"{label}.exfil.vendor-{int(rng.integers(1, 9))}.example")
    return out


def _cdn_hashed_domains(rng: np.random.Generator, count: int) -> list[str]:
    """Legitimate CDN/cache-busting labels are long and high-entropy, so a
    character n-gram model must learn more than 'random-looking string'."""
    alphabet = "abcdef0123456789"
    bases = ["cloudfront.example", "cdn.vendor.example", "assets.delivery.example", "telemetry.vendor.example"]
    out = []
    for _ in range(count):
        label = "".join(rng.choice(list(alphabet), int(rng.integers(16, 40))))
        out.append(f"{label}.{bases[int(rng.integers(0, len(bases)))]}")
    return out


_DGA_SYLLABLES = ["ba", "ke", "lo", "mi", "nu", "ra", "ta", "vo", "ze", "fa", "gi", "hu", "jo", "pi", "su", "we"]


def _pronounceable_dga_domains(rng: np.random.Generator, count: int) -> list[str]:
    tlvs = ["top", "xyz", "info", "click", "online"]
    out = []
    for _ in range(count):
        parts = [str(rng.choice(_DGA_SYLLABLES)) for _ in range(int(rng.integers(3, 7)))]
        out.append("".join(parts) + "." + tlvs[int(rng.integers(0, len(tlvs)))])
    return out


def _dns_samples(rng: np.random.Generator) -> tuple[list[str], np.ndarray, np.ndarray]:
    texts: list[str] = []
    labels: list[int] = []
    groups: list[str] = []
    for scenario in range(140):
        kind = scenario % 3
        if kind == 0:
            if rng.random() < 0.15:
                domains = _cdn_hashed_domains(rng, int(rng.integers(6, 16)))
            else:
                domains = list(rng.choice(_LEGIT_DOMAINS, size=int(rng.integers(6, 16))))
            label = 0
        elif kind == 1:
            if rng.random() < 0.20:
                domains = _pronounceable_dga_domains(rng, int(rng.integers(8, 20)))
            else:
                domains = _dga_domains(rng, int(rng.integers(8, 20)))
            label = 1
        else:
            domains = _tunnel_domains(rng, int(rng.integers(8, 18)))
            label = 1
        for domain in domains:
            texts.append(str(domain))
            labels.append(label)
            groups.append(f"dns-scenario-{scenario}")
    return texts, np.array(labels), np.array(groups)


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------


def _curve_points(y_true: np.ndarray, scores: np.ndarray, max_points: int = 40) -> tuple[list, list, float | None]:
    precision, recall, threshold = precision_recall_curve(y_true, scores)
    pr_points = [
        {"recall": round(float(r), 4), "precision": round(float(p), 4)}
        for p, r in zip(precision[:: max(1, len(precision) // max_points)], recall[:: max(1, len(recall) // max_points)])
    ]
    roc_points: list[dict] = []
    roc_auc = None
    try:
        fpr, tpr, _ = roc_curve(y_true, scores)
        roc_auc = round(float(auc(fpr, tpr)), 4)
        roc_points = [
            {"fpr": round(float(a), 4), "tpr": round(float(b), 4)}
            for a, b in zip(fpr[:: max(1, len(fpr) // max_points)], tpr[:: max(1, len(tpr) // max_points)])
        ]
    except ValueError:
        pass
    return pr_points, roc_points, roc_auc


def _select_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    best, best_f1 = 0.5, -1.0
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        if p + r == 0:
            continue
        f1 = 2 * p * r / (p + r)
        if f1 > best_f1:
            best_f1, best = f1, float(t)
    return round(best, 4)


def _confusion(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def _metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    y_pred = (scores >= threshold).astype(int)
    cm = _confusion(y_true, y_pred)
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    fpr = fp / max(1, fp + tn)
    pr_points, roc_points, roc_auc = _curve_points(y_true, scores)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "roc_auc": roc_auc,
        "confusion": cm,
        "pr_curve": pr_points,
        "roc_curve": roc_points,
    }


def _drift_index(x_train: np.ndarray, x_test: np.ndarray, feature_names: list[str]) -> dict:
    from scipy.stats import ks_2samp

    shifts = {}
    for i, name in enumerate(feature_names):
        try:
            stat, _ = ks_2samp(x_train[:, i], x_test[:, i])
        except Exception:
            stat = 0.0
        shifts[name] = round(float(stat), 4)
    values = list(shifts.values())
    return {
        "method": "Kolmogorov–Smirnov statistic, train vs held-out test (synthetic)",
        "per_feature": shifts,
        "max": round(max(values), 4) if values else 0.0,
        "mean": round(sum(values) / len(values), 4) if values else 0.0,
    }


def _latency_probe(predict_fn, samples: np.ndarray, iterations: int = 5) -> float:
    timings = []
    for _ in range(iterations):
        started = time.perf_counter()
        predict_fn(samples)
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    return round(timings[len(timings) // 2], 3)


def _group_split(groups: np.ndarray):
    splitter = GroupShuffleSplit(n_splits=1, train_size=0.6, random_state=42)
    train_idx, rest_idx = next(splitter.split(np.zeros(len(groups)), groups=groups))
    splitter2 = GroupShuffleSplit(n_splits=1, train_size=0.5, random_state=7)
    val_rel, test_rel = next(splitter2.split(np.zeros(len(rest_idx)), groups=groups[rest_idx]))
    return train_idx, rest_idx[val_rel], rest_idx[test_rel]


def _save_model(model, code: str, version: str) -> str:
    path = MODEL_DIR / "trained" / f"{code}-{version}.joblib"
    joblib.dump(model, path)
    return str(path)


def _persist(
    db: Session,
    *,
    code: str,
    name: str,
    version: str,
    algorithm: str,
    confidence_type: str,
    features: list[str],
    artifact_path: str,
    metrics: dict,
    threshold: float,
    sample_counts: dict,
    class_distribution: dict,
    drift: dict,
    importance: dict | None,
    latency_ms: float,
    comments: str,
) -> ModelVersion:
    for old in db.query(ModelVersion).filter(ModelVersion.detector_code == code, ModelVersion.status == "ACTIVE"):
        old.status = "SUPERSEDED"
    model_version = ModelVersion(
        detector_code=code,
        name=name,
        version=version,
        algorithm=algorithm,
        confidence_type=confidence_type,
        dataset_name=DATASET_NAME,
        dataset_version=DATASET_VERSION,
        dataset_licence=DATASET_LICENCE,
        features=features,
        artifact_path=artifact_path,
        status="ACTIVE",
        metrics_summary={
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "false_positive_rate": metrics["false_positive_rate"],
            "roc_auc": metrics.get("roc_auc"),
            "threshold": threshold,
        },
        trained_at=utc_now(),
    )
    db.add(model_version)
    db.flush()
    evaluation = ModelEvaluation(
        model_version_id=model_version.id,
        dataset_name=DATASET_NAME,
        dataset_version=DATASET_VERSION,
        dataset_licence=DATASET_LICENCE,
        train_period="synthetic profile A",
        validation_period="synthetic profile B",
        test_period="synthetic profile C",
        sample_count=sample_counts["total"],
        class_distribution=class_distribution,
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
        false_positive_rate=metrics["false_positive_rate"],
        roc_auc=metrics.get("roc_auc"),
        metrics={
            "threshold": threshold,
            "confusion": metrics["confusion"],
            "pr_curve": metrics["pr_curve"],
            "roc_curve": metrics["roc_curve"],
            "feature_importance": importance or {},
            "drift": drift,
            "splits": sample_counts,
            "inference_latency_ms": latency_ms,
            "confidence_type": confidence_type,
            "comments": comments,
        },
        evaluated_at=utc_now(),
    )
    db.add(evaluation)
    db.flush()
    return model_version


# ---------------------------------------------------------------------------
# Training entry points
# ---------------------------------------------------------------------------


def train_all(db: Session, *, version: str | None = None) -> list[ModelVersion]:
    version = version or datetime.utcnow().strftime("%Y.%m.%d.%H%M")
    results: list[ModelVersion] = []
    results.append(_train_scanning(db, version))
    results.append(_train_exfil(db, version))
    results.append(_train_dns(db, version))
    results.append(_train_beacon(db, version))
    db.commit()
    load_active_models(db)
    return results


def _train_scanning(db: Session, version: str) -> ModelVersion:
    rng = _rng(11)
    X, y, groups = _scanning_samples(rng)
    features = FEATURE_SETS["scanning"]
    train_idx, val_idx, test_idx = _group_split(groups)
    base = RandomForestClassifier(n_estimators=180, max_depth=8, min_samples_leaf=2, random_state=42, class_weight="balanced")
    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(X[train_idx], y[train_idx])
    val_scores = model.predict_proba(X[val_idx])[:, 1]
    threshold = _select_threshold(y[val_idx], val_scores)
    test_scores = model.predict_proba(X[test_idx])[:, 1]
    metrics = _metrics(y[test_idx], test_scores, threshold)
    importance = {}
    try:
        values = np.mean(
            [c.estimator.feature_importances_ for c in model.calibrated_classifiers_], axis=0
        )
        importance = {name: round(float(v), 4) for name, v in zip(features, values)}
    except Exception:
        pass
    drift = _drift_index(X[train_idx], X[test_idx], features)
    latency = _latency_probe(lambda arr: model.predict_proba(arr), X[test_idx][: min(64, len(test_idx))])
    artifact = _save_model(model, "scanning", version)
    return _persist(
        db,
        code="scanning",
        name="Port Scan Classifier",
        version=version,
        algorithm="Random Forest (calibrated, sigmoid)",
        confidence_type="calibrated_probability",
        features=features,
        artifact_path=artifact,
        metrics=metrics,
        threshold=threshold,
        sample_counts={
            "total": int(len(y)),
            "train": int(len(train_idx)),
            "validation": int(len(val_idx)),
            "test": int(len(test_idx)),
        },
        class_distribution={"positive": int(y.sum()), "negative": int(len(y) - y.sum())},
        drift=drift,
        importance=importance,
        latency_ms=latency,
        comments=(
            "Grouped split by scenario. Metrics reflect the synthetic demonstration dataset only "
            "and must not be presented as production detection accuracy."
        ),
    )


def _train_exfil(db: Session, version: str) -> ModelVersion:
    rng = _rng(23)
    X, y, groups = _exfil_samples(rng)
    features = FEATURE_SETS["exfiltration"]
    train_idx, val_idx, test_idx = _group_split(groups)
    base = GradientBoostingClassifier(n_estimators=140, learning_rate=0.07, max_depth=3, random_state=42)
    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(X[train_idx], y[train_idx])
    val_scores = model.predict_proba(X[val_idx])[:, 1]
    threshold = _select_threshold(y[val_idx], val_scores)
    test_scores = model.predict_proba(X[test_idx])[:, 1]
    metrics = _metrics(y[test_idx], test_scores, threshold)
    importance = {}
    try:
        values = np.mean(
            [c.estimator.feature_importances_ for c in model.calibrated_classifiers_], axis=0
        )
        importance = {name: round(float(v), 4) for name, v in zip(features, values)}
    except Exception:
        pass
    drift = _drift_index(X[train_idx], X[test_idx], features)
    latency = _latency_probe(lambda arr: model.predict_proba(arr), X[test_idx][: min(64, len(test_idx))])
    artifact = _save_model(model, "exfiltration", version)
    return _persist(
        db,
        code="exfiltration",
        name="Data Exfiltration Classifier",
        version=version,
        algorithm="Gradient Boosting (calibrated, sigmoid)",
        confidence_type="calibrated_probability",
        features=features,
        artifact_path=artifact,
        metrics=metrics,
        threshold=threshold,
        sample_counts={
            "total": int(len(y)),
            "train": int(len(train_idx)),
            "validation": int(len(val_idx)),
            "test": int(len(test_idx)),
        },
        class_distribution={"positive": int(y.sum()), "negative": int(len(y) - y.sum())},
        drift=drift,
        importance=importance,
        latency_ms=latency,
        comments=(
            "Requires directional byte metadata. If direction is unavailable the detector reports "
            "an incomplete assessment instead of estimating inbound/outbound volumes."
        ),
    )


def _train_dns(db: Session, version: str) -> ModelVersion:
    rng = _rng(37)
    texts, y, groups = _dns_samples(rng)
    train_idx, val_idx, test_idx = _group_split(groups)
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=4000, lowercase=True)),
            ("logreg", LogisticRegression(max_iter=1200, class_weight="balanced", C=1.4)),
        ]
    )
    model = CalibratedClassifierCV(pipeline, method="sigmoid", cv=3)
    X_train = [texts[i] for i in train_idx]
    y_train = y[train_idx]
    model.fit(X_train, y_train)
    val_texts = [texts[i] for i in val_idx]
    val_scores = model.predict_proba(val_texts)[:, 1]
    threshold = _select_threshold(y[val_idx], val_scores)
    test_texts = [texts[i] for i in test_idx]
    test_scores = model.predict_proba(test_texts)[:, 1]
    metrics = _metrics(y[test_idx], test_scores, threshold)

    importance: dict = {}
    try:
        clf = model.calibrated_classifiers_[0].estimator.named_steps["logreg"]
        vectorizer = model.calibrated_classifiers_[0].estimator.named_steps["tfidf"]
        names = vectorizer.get_feature_names_out()
        coefs = clf.coef_[0]
        positive = np.argsort(coefs)[-12:][::-1]
        negative = np.argsort(coefs)[:6]
        importance = {
            "top_suspicious_ngrams": {str(names[i]): round(float(coefs[i]), 4) for i in positive},
            "top_benign_ngrams": {str(names[i]): round(float(coefs[i]), 4) for i in negative},
        }
    except Exception:
        pass
    drift = {
        "method": "Domain-length distribution shift, train vs held-out test (synthetic)",
        "max": 0.0,
        "mean": 0.0,
        "per_feature": {},
    }
    train_lengths = np.array([[len(t)] for t in X_train], dtype=float)
    test_lengths = np.array([[len(t)] for t in test_texts], dtype=float)
    drift = _drift_index(train_lengths, test_lengths, ["query_length"])
    latency = _latency_probe(lambda arr: model.predict_proba(list(arr)), np.array(test_texts[: min(32, len(test_texts))]))
    artifact = _save_model(model, "dns", version)
    return _persist(
        db,
        code="dns",
        name="DGA / Tunnelling Domain Classifier",
        version=version,
        algorithm="Character n-gram TF-IDF + Logistic Regression (calibrated)",
        confidence_type="calibrated_probability",
        features=["query_name"],
        artifact_path=artifact,
        metrics=metrics,
        threshold=threshold,
        sample_counts={
            "total": int(len(y)),
            "train": int(len(train_idx)),
            "validation": int(len(val_idx)),
            "test": int(len(test_idx)),
        },
        class_distribution={"positive": int(y.sum()), "negative": int(len(y) - y.sum())},
        drift=drift,
        importance=importance,
        latency_ms=latency,
        comments=(
            "Scores individual query names. Aggregated detector confidence also reflects query rate, "
            "record types and response codes."
        ),
    )


def _train_beacon(db: Session, version: str) -> ModelVersion:
    rng = _rng(53)
    X, y, groups = _beacon_samples(rng)
    features = FEATURE_SETS["beaconing"]
    train_idx, val_idx, test_idx = _group_split(groups)
    benign_train = train_idx[y[train_idx] == 0]
    pipeline = Pipeline(
        [
            ("scale", StandardScaler()),
            ("iforest", IsolationForest(n_estimators=300, max_samples="auto", random_state=42, n_jobs=-1)),
        ]
    )
    pipeline.fit(X[benign_train])

    def anomaly_scores(matrix: np.ndarray) -> np.ndarray:
        return np.clip(-pipeline.score_samples(matrix), 0.0, 1.0)

    val_scores = anomaly_scores(X[val_idx])
    threshold = _select_threshold(y[val_idx], val_scores)
    test_scores = anomaly_scores(X[test_idx])
    metrics = _metrics(y[test_idx], test_scores, threshold)
    drift = _drift_index(X[train_idx], X[test_idx], features)
    latency = _latency_probe(lambda arr: anomaly_scores(arr), X[test_idx][: min(64, len(test_idx))])
    artifact = _save_model(pipeline, "beaconing", version)
    return _persist(
        db,
        code="beaconing",
        name="Beaconing Anomaly Model",
        version=version,
        algorithm="Isolation Forest (unsupervised, benign-only fit)",
        confidence_type="anomaly_score",
        features=features,
        artifact_path=artifact,
        metrics=metrics,
        threshold=threshold,
        sample_counts={
            "total": int(len(y)),
            "train": int(len(train_idx)),
            "fit_samples": int(len(benign_train)),
            "validation": int(len(val_idx)),
            "test": int(len(test_idx)),
        },
        class_distribution={"positive": int(y.sum()), "negative": int(len(y) - y.sum())},
        drift=drift,
        importance=None,
        latency_ms=latency,
        comments=(
            "Fitted exclusively on benign training scenarios; labels are not used during fitting. "
            "Held-out malicious scenarios are used only for evaluation. Outputs an anomaly score in "
            "0-1, not a calibrated probability. The detector also requires low interval variance and "
            "destination concentration before alerting."
        ),
    )


# ---------------------------------------------------------------------------
# Loaded model cache and scoring
# ---------------------------------------------------------------------------


def load_active_models(db: Session) -> None:
    from .models import ModelVersion as MV

    with _CACHE_LOCK:
        _CACHE.clear()
        for record in db.query(MV).filter(MV.status == "ACTIVE").all():
            if not record.artifact_path:
                continue
            path = Path(record.artifact_path)
            if not path.exists():
                continue
            try:
                artifact = joblib.load(path)
            except Exception:
                continue
            _CACHE[record.detector_code] = {
                "model": artifact,
                "model_version_id": record.id,
                "features": list(record.features or []),
                "confidence_type": record.confidence_type,
                "name": record.name,
                "version": record.version,
            }


def score(code: str, features: dict) -> dict | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(code)
    if not entry or not entry["features"] or entry["features"][0] not in features:
        return None
    vector = [float(features.get(name, 0) or 0) for name in entry["features"]]
    try:
        probability = float(entry["model"].predict_proba([vector])[0][1])
    except Exception:
        return None
    return {
        "probability": round(probability, 4),
        "model_version_id": entry["model_version_id"],
        "model_name": entry["name"],
        "model_version": entry["version"],
    }


def score_dns(queries: list[str]) -> dict | None:
    with _CACHE_LOCK:
        entry = _CACHE.get("dns")
    if not entry:
        return None
    sample = [q for q in queries if q][:48]
    if not sample:
        return None
    try:
        probabilities = entry["model"].predict_proba(sample)[:, 1]
    except Exception:
        return None
    mean = float(np.mean(probabilities))
    return {
        "probability": round(mean, 4),
        "model_version_id": entry["model_version_id"],
        "model_name": entry["name"],
        "model_version": entry["version"],
        "scored_domains": len(sample),
        "max_domain_probability": round(float(np.max(probabilities)), 4),
    }


def beacon_anomaly(features: dict) -> dict | None:
    with _CACHE_LOCK:
        entry = _CACHE.get("beaconing")
    if not entry:
        return None
    vector = [float(features.get(name, 0) or 0) for name in entry["features"]]
    try:
        raw = float(entry["model"].score_samples([vector])[0])
    except Exception:
        return None
    return {
        "anomaly_score": round(float(np.clip(-raw, 0.0, 1.0)), 4),
        "model_version_id": entry["model_version_id"],
        "model_name": entry["name"],
        "model_version": entry["version"],
        "confidence_type": "anomaly_score",
    }


def model_catalog(db: Session) -> list[dict]:
    with _CACHE_LOCK:
        loaded = {code: entry["model_version_id"] for code, entry in _CACHE.items()}
    rows = (
        db.query(ModelVersion)
        .filter(ModelVersion.status == "ACTIVE")
        .order_by(ModelVersion.detector_code)
        .all()
    )
    output = []
    for row in rows:
        output.append(
            {
                "id": row.id,
                "detector_code": row.detector_code,
                "name": row.name,
                "version": row.version,
                "algorithm": row.algorithm,
                "confidence_type": row.confidence_type,
                "dataset_name": row.dataset_name,
                "dataset_version": row.dataset_version,
                "dataset_licence": row.dataset_licence,
                "features": row.features,
                "status": row.status,
                "loaded": loaded.get(row.detector_code) == row.id,
                "metrics_summary": row.metrics_summary,
                "trained_at": row.trained_at.isoformat() + "Z",
                "artifact_exists": bool(row.artifact_path and Path(row.artifact_path).exists()),
            }
        )
    return output


def evaluation_payload(db: Session, model_id: int) -> dict | None:
    row = db.get(ModelVersion, model_id)
    if not row:
        return None
    evaluation = (
        db.query(ModelEvaluation)
        .filter(ModelEvaluation.model_version_id == model_id)
        .order_by(ModelEvaluation.evaluated_at.desc())
        .first()
    )
    if not evaluation:
        return None
    return json.loads(
        json.dumps(
            {
                "model_id": row.id,
                "name": row.name,
                "version": row.version,
                "algorithm": row.algorithm,
                "confidence_type": row.confidence_type,
                "dataset": {
                    "name": evaluation.dataset_name,
                    "version": evaluation.dataset_version,
                    "licence": evaluation.dataset_licence,
                    "train_period": evaluation.train_period,
                    "validation_period": evaluation.validation_period,
                    "test_period": evaluation.test_period,
                    "sample_count": evaluation.sample_count,
                    "class_distribution": evaluation.class_distribution,
                },
                "scores": {
                    "precision": evaluation.precision,
                    "recall": evaluation.recall,
                    "f1": evaluation.f1,
                    "false_positive_rate": evaluation.false_positive_rate,
                    "roc_auc": evaluation.roc_auc,
                },
                "confusion": evaluation.metrics.get("confusion"),
                "threshold": evaluation.metrics.get("threshold"),
                "pr_curve": evaluation.metrics.get("pr_curve"),
                "roc_curve": evaluation.metrics.get("roc_curve"),
                "feature_importance": evaluation.metrics.get("feature_importance"),
                "drift": evaluation.metrics.get("drift"),
                "splits": evaluation.metrics.get("splits"),
                "inference_latency_ms": evaluation.metrics.get("inference_latency_ms"),
                "comments": evaluation.metrics.get("comments"),
                "evaluated_at": evaluation.evaluated_at.isoformat() + "Z",
            }
        )
    )
