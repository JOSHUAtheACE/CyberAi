# Benchmark results

This page reports the numbers the platform actually stores for its four trained models. Every
figure below was read back from `GET /api/v1/ai/models/{id}/evaluation` against the running
build, not copied from a design document.

> **Read this first.** These are engineering benchmarks on a small, labelled **synthetic**
> corpus that ships with the repository. They are not production detection accuracy, not
> vendor comparisons, and not evidence that the models will perform similarly on your
> traffic. Sample sizes are small enough that a handful of records move the metrics by
> several points. Treat them as a regression baseline for the training pipeline.

---

## 1. Evaluation protocol

| Element | Implementation |
| --- | --- |
| Corpus | `SENTINEL AI labelled synthetic scenarios`, version `2026.10.1`, generated deterministically at train time |
| Split | 60 / 20 / 20 train / validation / test, grouped by synthetic scenario (`GroupShuffleSplit`) |
| Why grouped | Whole behavioural scenarios are held out, so a test row never shares a generator family with a training row |
| Seed | Data seeds 11 (scanning), 23 (exfiltration), 37 (DNS), 53 (beaconing); split seeds 42 and 7 |
| Threshold | Selected on the validation split by maximum F1 over the precision–recall curve |
| Metrics | Computed on the held-out test split only, at the stored threshold |
| Curves | 40-point subsampled PR and ROC curves stored with the evaluation |
| Drift | Kolmogorov–Smirnov statistic between train and test feature distributions |
| Latency | Median of 5 batch timings on up to 64 test rows, single process, development hardware |

Model artefacts live in `models/trained/*.joblib`; evaluation records live in the
`model_evaluations` table. Retraining supersedes the previous active version rather than
deleting it, so history stays auditable.

---

## 2. Headline results

Model version `2026.10.30b`. Latency is per-batch median for the batch described above and is
not an end-to-end detection latency.

| Detector | Algorithm | Confidence type | Samples | Test rows | Threshold | Precision | Recall | F1 | FPR | ROC AUC | Latency |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Port scan | Random Forest, sigmoid-calibrated | calibrated probability | 220 | 44 | 0.0463 | 0.9375 | 1.0000 | 0.9677 | 0.0345 | 1.0000 | 46.5 ms |
| Exfiltration | Gradient Boosting, sigmoid-calibrated | calibrated probability | 220 | 44 | 0.6276 | 0.8824 | 1.0000 | 0.9375 | 0.0690 | 1.0000 | 3.5 ms |
| DGA / DNS | char n-gram TF-IDF + Logistic Regression, sigmoid-calibrated | calibrated probability | 1665 | 354 | 0.9594 | 1.0000 | 0.9966 | 0.9983 | 0.0000 | 1.0000 | 16.1 ms |
| Beaconing | Isolation Forest, benign-only fit | anomaly score | 1040 | 208 | 0.6106 | 0.9579 | 0.7845 | 0.8626 | 0.0435 | 0.9425 | 35.3 ms |

### Confusion matrices (test split)

| Detector | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: |
| Port scan | 28 | 1 | 0 | 15 |
| Exfiltration | 27 | 2 | 0 | 15 |
| DGA / DNS | 56 | 0 | 1 | 297 |
| Beaconing | 88 | 4 | 25 | 91 |

### Class balance and split sizes

| Detector | Positives | Negatives | Train | Validation | Test | Fit rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Port scan | 88 | 132 | 132 | 44 | 44 | 132 |
| Exfiltration | 88 | 132 | 132 | 44 | 44 | 132 |
| DGA / DNS | 1174 | 491 | 979 | 332 | 354 | 979 |
| Beaconing | 520 | 520 | 624 | 208 | 208 | 320 (benign only) |

Beaconing is the only unsupervised model: the Isolation Forest is fitted on benign training
rows only (320), and malicious labels are used solely for threshold selection and evaluation.

---

## 3. How to read these numbers

**Small test sets widen the error bars.** The port-scan and exfiltration test splits contain
44 rows each. One false positive is 3.5–6.9 percentage points of FPR. Do not present
these as stable estimates of field performance.

**Synthetic data is separable by construction.** The generators deliberately overlap
malicious and benign distributions (slow narrow scans, authorised availability sweeps,
legitimate backup uploads, scheduled jobs with low jitter, hashed CDN labels), but they
still share structure with the held-out scenarios. Real traffic contains behaviours no
generator anticipated. Expect materially lower precision in production until the models are
retrained on labelled telemetry from your own environment.

**The DNS model is near-saturated and that is expected.** Character n-gram models separate
generated strings from curated real domains very well. The hard cases — long, high-entropy
*legitimate* CDN cache-busting labels — are present in the benign set at a low rate. The
0.9966 recall with zero observed false positives reflects 354 test rows, not a guarantee.

**Beaconing has the weakest recall and the strongest caveat.** It reports an anomaly score,
not a probability. The detector additionally gates on interval scale, coefficient of
variation and destination concentration before alerting, so the model is supporting
evidence rather than the sole decision. Low-and-slow callbacks with heavy jitter are the
known blind spot; recall of 0.7845 on this corpus is consistent with that.

**Latency here is model inference, not detection time.** The product reports detection-stage
duration from completed ingestion jobs separately, and shows an empty state when no
measurement exists. It never substitutes a model timing for a pipeline timing.

**Drift statistics are diagnostic, not alarms.** The stored KS maxima are 0.2197 (port scan),
0.2424 (exfiltration), 0.1236 (DNS) and 0.1362 (beaconing). They describe how far the
held-out synthetic profile moved from the training profile. No automatic retraining or
alerting is triggered by them.

---

## 4. How model output becomes an alert score

| Detector | Combination | Confidence label |
| --- | --- | --- |
| Port scan | `0.45 × rule + 0.55 × calibrated probability` | `hybrid_score` |
| Exfiltration | `0.45 × rule + 0.55 × calibrated probability` | `hybrid_score` |
| DGA / DNS | `0.45 × rule + 0.55 × mean domain probability` (max 48 names scored per window) | `hybrid_score` |
| DDoS | rule only — no trained model | `heuristic_score` |
| TLS / QUIC | rule only, hard-capped at 0.70 | `heuristic_score` |
| Beaconing | rule only for the alert score; Isolation Forest reported as supporting evidence | `heuristic_score` |

Severity is derived from the combined score, not from the model alone: critical ≥ 0.90,
high ≥ 0.75, medium ≥ 0.55, low ≥ 0.35, otherwise informational. The TLS cap exists because
handshake metadata cannot justify high certainty about intent.

---

## 5. Reproducing a run

```bash
# Requires an account with ai.evaluate (Security Administrator or ML Engineer)
curl -b cookies.txt -X POST "http://127.0.0.1:8000/api/v1/ai/train" \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"workspace":"demo"}'

# List active models and their stored summaries
curl -b cookies.txt "http://127.0.0.1:8000/api/v1/ai/overview?workspace=demo"

# Full evaluation payload for one model, including curves and confusion matrix
curl -b cookies.txt "http://127.0.0.1:8000/api/v1/ai/models/9/evaluation"
```

Training is deterministic for a fixed scikit-learn and numpy version, which is why
`backend/requirements.txt` pins them. A different library version can legitimately produce
different numbers; that is a version change, not a quality change.

---

## 6. What is deliberately not claimed

- No accuracy percentage is shown next to a live alert, because a model metric measured on
  another corpus is not the probability that this alert is a true positive.
- No comparison to commercial or academic detectors is made. None was run.
- No F1, precision or recall is attributed to the DDoS or TLS/QUIC modules, which are
  rule-based and have no trained artefact.
- No "human-level" or "expert SOC" claims. The models rank and prioritise; analysts decide.
