# Detection methodology

SENTINEL AI runs six behavioural detection modules over normalised flow metadata. Five are
rule-gated with an optional model contribution; one (beaconing) is rule-scored with an
unsupervised model as supporting evidence. There is no packet payload inspection anywhere in
the detection path.

This page describes exactly what each module looks at, when it fires, how its score is
formed, and what it deliberately refuses to conclude.

---

## 1. Common pipeline

```
validated flow records
        │
        ├─ group into a per-module observation window
        ├─ compute window features (counts, rates, entropy, regularity, volumes)
        ├─ gate: is there enough telemetry and does the behaviour cross the floor?
        ├─ score: rule score, optionally fused with a calibrated model
        ├─ build evidence items (observed value, baseline, unit, description, flow ids)
        ├─ deduplicate against open alerts with the same dedup key
        └─ persist alert + evidence + feature observation, publish to the event bus
```

Every stage operates on stored `flow_records`; nothing is estimated. If the fields a module
needs are absent, the module produces no detection and the coverage report says why.

### Score arithmetic

| Situation | Score |
| --- | --- |
| Model probability available | `clamp(0.45 × rule + 0.55 × probability, 0.05, 0.99)` |
| No model | `clamp(rule, 0.05, 0.99)` |
| TLS / QUIC | same as above, then capped at `0.70` |

The confidence type is stored alongside the score (`hybrid_score` or `heuristic_score`) and
surfaced in the interface, so an analyst can tell whether a number came from a calibrated
model or from hand-tuned weights.

### Severity

| Score | Severity |
| --- | --- |
| ≥ 0.90 | critical |
| ≥ 0.75 | high |
| ≥ 0.55 | medium |
| ≥ 0.35 | low |
| < 0.35 | informational |

### Deduplication

An alert is merged into an existing one when workspace, environment, detector and dedup key
match and the existing alert is not `CLOSED` or `FALSE_POSITIVE`. A merge extends `last_seen`,
increments `recurrence`, and refreshes the evidence payload. It does not create a second
alert. Dedup keys are listed per module below.

Alert lifecycle: `OPEN → ACKNOWLEDGED → INVESTIGATING → CLOSED`, with `FALSE_POSITIVE` as a
terminal alternative. All transitions are recorded in the audit log; none of them touch
network infrastructure.

---

## 2. Port scanning

**Detector code** `port_scan_detector` · **Threat class** `Possible_Port_Scan`

| Property | Value |
| --- | --- |
| Window | 300 s per source address |
| Gate | ≥ 20 unique destination ports, **or** ≥ 12 unique hosts with ≥ 30 attempts |
| Default thresholds | `unique_ports=20`, `unique_hosts=12`, `attempts=30`, `window_seconds=300` |
| Protocol scope | TCP, UDP, SCTP with a non-zero destination port |
| Model | Random Forest, sigmoid-calibrated; features `unique_ports, unique_hosts, attempts, duration_s, failed_ratio, port_entropy` |
| Dedup key | `scan:<source>:<bucket>` |

**Rule score** starts at 0.45 and adds up to 0.30 for port fan-out (ports ÷ 300), up to 0.12
for host fan-out (hosts ÷ 120), and 0.05 for a horizontal pattern (hosts ≥ max(5, ports ÷ 4))
or 0.02 otherwise.

**Evidence** includes unique destination ports with the source's median as baseline, attempt
count with median baseline, unique hosts, SYN-without-ACK ratio (only where TCP flags were
captured), destination-port Shannon entropy, and a derived orientation (`horizontal host
sweep` or `vertical port sweep`).

**Known ambiguity.** Vulnerability scanners, asset inventory jobs and load-balancer health
checks produce the same fan-out. The detector describes the behaviour; it does not assert
intent. A narrow scan across one service is more likely administrative than a wide sweep.

---

## 3. DDoS and volumetric floods

**Detector code** `ddos_detector` · **Threat class** `Possible_DDoS`

| Property | Value |
| --- | --- |
| Window | 60 s per destination address |
| Gate | SYN-flood pattern **or** volumetric transfer (see below) |
| Default thresholds | `pps_floor=120`, `baseline_multiple=5`, `syn_ratio=0.6`, `volumetric_bps=2,000,000` |
| Model | none — statistical baseline |
| Dedup key | `ddos:<destination>:<bucket>` |

The per-destination baseline is the median packet and bit rate across the destination's other
one-minute buckets in the processed batch. Volume threshold is
`max(pps_floor, baseline_pps × baseline_multiple)`.

- **SYN-flood pattern:** packet rate ≥ volume threshold **and** SYN ÷ (SYN + ACK) ≥ 0.6.
- **Volumetric transfer:** packet rate ≥ `max(pps_floor × 1.6, baseline × multiple × 1.5)` **and**
  bit rate ≥ 2 Mbit/s.

**Rule score** starts at 0.48, adds up to 0.25 for packet rate (pps ÷ 4000), up to 0.15 for
source cardinality (sources ÷ 400), and 0.08 when the SYN ratio is ≥ 0.75 (0.02 otherwise).

**Evidence** includes packets/s and bits/s against baseline, SYN/ACK ratio, unique source
addresses, source-address entropy and a UDP characterisation. The evidence text states
explicitly that high source entropy is consistent with a distributed pattern but does **not**
confirm spoofing, and that reflector-port overlap is behavioural only.

**Known ambiguity.** Bulk transfers, backups and content distribution to one destination can
look volumetric. The baseline comparison exists to keep steady high-volume services quiet.

---

## 4. C2 beaconing

**Detector code** `beaconing_detector` · **Threat class** `Possible_C2_Beaconing`

| Property | Value |
| --- | --- |
| Window | entire processed batch, grouped by `(source, destination, destination port)` |
| Gate | ≥ 6 connections; ≥ 5 positive intervals; mean interval within 10–3600 s; CV ≤ 0.4; dominant 5-second bucket share ≥ 0.6 |
| Default thresholds | `min_connections=6`, `max_cv=0.4`, `interval_bounds_seconds=[10, 3600]` |
| Model | Isolation Forest fitted on benign rows only; reported as an anomaly score in evidence |
| Dedup key | `beacon:<source>:<destination>:<port>` |

The coefficient of variation is the population standard deviation of inter-arrival times
divided by their mean. Intervals are also rounded to the nearest 5 seconds and the share of
the modal bucket is computed, which suppresses traffic that is merely low-rate.

**Rule score** is `0.42 + (0.40 − CV) × 1.1 + min(0.12, connections × 0.01) + mode_share × 0.10`.
It does not include mean/min/max interval, because scale is already gated and those values
dilute the regularity signal.

**Evidence** includes mean interval, repeated connection count, CV, dominant-bucket share,
destination concentration, observation span, and — when available — the Isolation Forest
anomaly score labelled explicitly as "anomaly score, not a calibrated probability".

**Known ambiguity.** Scheduled jobs, monitoring agents, NTP and some SaaS heartbeats are
periodic. The model is non-trivial for precisely this reason: a small share of benign
scheduled traffic is regular enough to resemble a beacon. Low-and-slow callbacks with heavy
jitter are the module's main blind spot, and this is stated in the UI.

---

## 5. DGA and DNS tunnelling

**Detector code** `dns_detector` · **Threat class** `Possible_DGA_or_DNS_Tunnelling`

| Property | Value |
| --- | --- |
| Window | 600 s per source address |
| Gate | ≥ 12 DNS queries in the window and either high entropy **or** a tunnelling pattern |
| Default thresholds | `min_queries=12`, `mean_entropy=3.35`, `label_length=38`, `window_seconds=600` |
| Model | character 3–5-gram TF-IDF + Logistic Regression, sigmoid-calibrated; up to 48 names scored per window |
| Dedup key | `dns:<source>:<bucket>` |

**Entropy** is computed over the registered portion of each query name (all labels except the
final TLD label) and averaged across the window.

- **High entropy:** mean entropy ≥ 3.35 bits and unique names ≥ 12.
- **Tunnelling pattern:** longest left-most label ≥ 38 characters, ≥ 12 queries, and either
  TXT/NULL/CNAME share ≥ 0.3 or mean query length ≥ 45.

**Rule score** starts at 0.40, adds up to 0.22 from entropy above 3.0, 0.12 for tunnelling
(0.05 for entropy alone), up to 0.08 for unique-name count, and 0.06 when NXDOMAIN exceeds
half of responses.

**Evidence** includes unique domains, mean domain entropy, maximum label length, queries per
minute, NXDOMAIN ratio (or "not available" when response codes were absent), TXT/CNAME share,
truncated sample domains, and the mean calibrated domain probability with the number of
scored names.

**Known ambiguity.** CDN cache-busting, telemetry identifiers and some analytics SDKs use
long, high-entropy labels. The training corpus includes them deliberately so the model does
not simply learn "random-looking = malicious". When query names were not captured, the module
reports insufficient visibility instead of inferring.

---

## 6. TLS and QUIC metadata

**Detector code** `encrypted_metadata_detector` · **Threat class** `Unusual_TLS_Metadata`

| Property | Value |
| --- | --- |
| Window | entire processed batch, grouped by `(source, destination, port, JA3)` |
| Gate | suspicious endpoint **and** (rare fingerprint or small fixed-size sessions) |
| Default thresholds | `rarity_floor=0.6`, `max_confidence=0.7` |
| Model | none — heuristic metadata analyser |
| Dedup key | `tls:<source>:<destination>:<port>:<ja3>` |

A flow is in scope when it carries a JA3 fingerprint or its application protocol is TLS, SSL
or QUIC. Rarity is `1 − min(1, fingerprint_count ÷ max(3, encrypted_sessions ÷ 4))`.

- **Suspicious endpoint:** no SNI observed **or** destination port outside 443/8443/9443.
- **Repeated:** ≥ 3 sessions. **Small fixed:** ≥ 3 sessions, byte standard deviation < 500 and
  mean < 8,000 bytes.
- Fires when `suspicious AND (rarity > 0.6 OR small_fixed)`.

**Rule score** starts at 0.36, adds `rarity × 0.2`, 0.08 for missing SNI, 0.06 for a
non-standard port and 0.04 for repetition. The result is then hard-capped at 0.70 so metadata
alone can never produce a critical alert.

**Evidence** includes the JA3 value, rarity score, SNI presence, destination port, session
count and an explicit `payload_visibility: not decrypted` item.

**Known ambiguity.** Custom enterprise clients, embedded devices and some game or voice
clients use uncommon fingerprints on unusual ports. This module is an investigative lead, not
a verdict, and the summary text says so.

---

## 7. Data exfiltration

**Detector code** `exfiltration_detector` · **Threat class** `Possible_Data_Exfiltration`

| Property | Value |
| --- | --- |
| Window | entire processed batch, grouped by `(source, destination)` |
| Gate | outbound bytes ≥ 10,000,000 **and** outbound/inbound ratio ≥ 6 **and** source baseline deviation ≥ 4× (when a baseline exists) |
| Default thresholds | `min_outbound_bytes=10_000_000`, `min_ratio=6`, `baseline_multiple=4` |
| Model | Gradient Boosting, sigmoid-calibrated; features `out_bytes, in_bytes, ratio, duration_s, baseline_ratio` |
| Dedup key | `exfil:<source>:<destination>` |

Only flows marked `outbound` with positive `bytes_out` participate. Direction comes from the
workspace's configured internal CIDRs or a declared direction field — never from a guess. The
baseline is the median outbound volume from the same source to its other destinations, using
pairs smaller than the candidate.

**Rule score** starts at 0.44, adds up to 0.20 from the log10 of outbound megabytes, up to
0.18 from the outbound/inbound ratio (÷ 80), and 0.08 when deviation ≥ 10×.

**Evidence** includes outbound and inbound bytes, the ratio, the per-destination baseline (or
"insufficient baseline"), transfer duration, and a `direction_method` item stating that
direction derives from configured zones.

**Known ambiguity.** Backup uploads, off-site replication and large legitimate SaaS uploads
are outbound-heavy. Directional metadata is required; when it is unavailable the module
returns an incomplete-assessment coverage record instead of estimating volumes, and the UI
shows that state.

---

## 8. Coverage and honesty rules

The following are enforced in code, not just documented:

1. **No input, no alert.** A module that lacks its required fields yields nothing rather than
   a low-confidence guess.
2. **Coverage is reported.** The pipeline returns an exfiltration coverage object
   (`directional_flows`, `flows_total`, `direction_available`) and the interface renders
   insufficient-visibility states.
3. **Evidence is concrete.** Each item carries the observed value, and a baseline where one
   exists, or the literal text `insufficient baseline`.
4. **Ground truth is not an input.** `scenario_id` and `label` travel with records for replay
   evaluation and are never read by a detector. No detection decision references them.
5. **No enrichment dependency.** Detection works entirely offline. Threat intelligence is
   contextual and optional.
6. **No active response.** The platform writes records. It does not probe, block, isolate or
   modify any network device.

---

## 9. Detection vs replay vs demo

Detections run on whatever flows are inserted. The environment tag (`LIVE`, `REPLAY`, `DEMO`)
is stored on the alert, and the event bus scopes subscribers to one environment. Replay
workspaces are reset before a new session, so a replay never contaminates the alert queue of
another workspace.

Replay re-runs the same detectors at an accelerated clock (`0.5×/1×/2×/5×`, with timeline
compression capped so a long capture stays interactive). Compression is recorded in the
session event metadata. It changes how fast time passes in the replay, never the analysis.
