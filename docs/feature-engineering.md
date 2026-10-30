# Feature engineering

Detection quality depends more on honest normalisation than on model choice. This page
documents how raw exports become canonical flow records, which features each module computes,
and what the platform does when a field is missing.

The guiding rule: **a feature is either observed or absent.** Nothing is imputed, smoothed or
inferred to fill a gap that would change a detection decision.

---

## 1. Canonical flow schema

Every source — CSV, TSV, JSON, JSONL, Zeek, PCAP, PCAPNG or the collector feed — is normalised
into one record shape before anything else happens.

| Canonical field | Type | Notes |
| --- | --- | --- |
| `ts` | UTC datetime | Required. Epoch seconds/milliseconds/nanoseconds, ISO 8601, or common date formats |
| `src_ip`, `dst_ip` | IP string | Required. Validated with `ipaddress`; invalid values are rejected |
| `src_port`, `dst_port` | int 0–65535 | Out-of-range rejects the row |
| `protocol` | enum | Numeric IP protocol mapped (6→TCP, 17→UDP, 1→ICMP); unknown values become `OTHER` |
| `app_proto` | string | Transport/application hint, truncated to 32 chars |
| `bytes_total` | int | Derived as `bytes_out + bytes_in` when absent |
| `bytes_out`, `bytes_in` | int | Directional volumes where the source provides them |
| `packets` | int | Sum of `packets_out + packets_in` when only split counters exist |
| `duration_ms` | int | Seconds fields are converted; sub-second precision retained in ms |
| `tcp_flags` | string | Free-form flag text; the detector checks for `SYN` and `ACK` substrings |
| `dns_query`, `dns_qtype`, `dns_rcode` | string | Lower-cased, trailing dot stripped, 255-char cap |
| `tls_sni`, `tls_ja3`, `tls_version`, `tls_cipher` | string | Handshake metadata only; no payload |
| `quic` | bool | Set by the PCAP parser for QUIC transport |
| `direction` | enum | `internal`, `outbound`, `inbound`, `transit` (see §2) |
| `scenario_id`, `label` | string | Evaluation metadata; never read by a detector |
| `meta` | JSON | Column list, direction availability, declared direction, replay origin |

### Field aliases

Real exports disagree about names. The normaliser accepts a documented alias set, for example:

| Canonical | Accepted aliases |
| --- | --- |
| `ts` | `timestamp`, `time`, `first_seen`, `datetime`, `start_time`, `@timestamp`, `event_time` |
| `src_ip` | `source_ip`, `src`, `id.orig_h`, `srcaddr`, `client_ip`, `ip_src`, `src_addr` |
| `dst_ip` | `dest_ip`, `dst`, `id.resp_h`, `dstaddr`, `server_ip`, `ip_dst`, `dst_addr` |
| `src_port` / `dst_port` | `sport`/`dport`, `id.orig_p`/`id.resp_p`, `client_port`/`server_port` |
| `protocol` | `proto`, `transport`, `ip_proto` |
| `bytes_total` | `bytes`, `total_bytes`, `octets`, `total_bytes_fwd` |
| `bytes_out` / `bytes_in` | `orig_bytes`/`resp_bytes`, `out_bytes`/`in_bytes`, `fwd_bytes`/`bwd_bytes` |
| `duration` | `duration_seconds`, `duration_s`, `flow_duration` |
| `dns_query` | `query`, `qname`, `dns_question` |
| `tls_ja3` | `ja3`, `ja3_hash` |

Alias matching is case-insensitive and ignores surrounding whitespace. The ingestion preview
shows the resolved mapping, so an operator can see exactly which column became which field
before committing an upload.

### Rejection reasons

Rows are rejected with a machine-readable reason rather than silently dropped:

| Reason | Cause |
| --- | --- |
| `invalid_or_missing_timestamp` | No parseable time value |
| `missing_source_or_destination` | Empty address |
| `invalid_ip_address` | Not a valid IPv4/IPv6 literal |
| `invalid_port` | Port above 65535 or negative |

Counts are aggregated per reason and returned in the quality report and on the job record.

---

## 2. Direction

Direction is not guessed from port numbers or address familiarity. It is derived from the
workspace's configured internal CIDR list:

| Source | Destination | Direction |
| --- | --- | --- |
| internal | internal | `internal` |
| internal | external | `outbound` |
| external | internal | `inbound` |
| external | external | `transit` |

Private, loopback and link-local addresses are always treated as internal regardless of CIDR
configuration. An explicit `direction` field in the source overrides the derivation and is
recorded in `meta.declared_direction`. The exfiltration module consumes only `outbound`
records; the UI reports `direction_available: false` when there are none, instead of
estimating.

The demo workspace uses `10.20.0.0/16`; the live workspace defaults to the RFC 1918 ranges
until an administrator configures real internal networks.

---

## 3. Geospatial features

`src_country`, `src_city`, `src_lat`, `src_lon` and the destination equivalents are populated
only when a real signal exists:

- **Live telemetry:** MaxMind GeoLite2, if a local database is configured and the address is
  public. Source is labelled `maxmind_geolite2`.
- **Demo workspace:** configured synthetic site metadata, labelled `demo_synthetic`, or
  configured asset locations labelled `demo_configured_asset`. All coordinates are fixed
  fixtures, never derived from the address.
- **Otherwise:** no coordinates. Private and reserved addresses are never assigned invented
  locations.

Every record carries `geo_source` so the map can distinguish a real lookup from a fixture.

---

## 4. Detector features

### Port scanning (300 s window per source)

| Feature | Definition |
| --- | --- |
| `unique_ports` | Distinct `dst_port` values in the window |
| `unique_hosts` | Distinct `dst_ip` values in the window |
| `attempts` | Flow count in the window |
| `failed_ratio` | Share of attempts whose TCP flags contain `SYN` and not `ACK` |
| `port_entropy` | Shannon entropy over the multiset of destination ports |
| `duration_s` | Last minus first timestamp, floored at 1 s |
| Horizontal flag | `unique_hosts ≥ max(5, unique_ports ÷ 4)` |

### DDoS (60 s window per destination)

| Feature | Definition |
| --- | --- |
| `pps` | Sum of packets ÷ window duration |
| `bps` | Sum of bytes × 8 ÷ window duration |
| `syn_ratio` | SYN count ÷ (SYN + ACK) |
| `unique_sources` | Distinct source addresses |
| `src_entropy` | Shannon entropy over the source-address multiset |
| `udp_share` | UDP flows ÷ total flows |
| `baseline_pps`, `baseline_bps` | Median rates for the same destination in other buckets |

Reflector detection uses UDP share plus overlap with a fixed port set
(53, 123, 389, 1900, 11211, 161, 5353, 137) and is labelled behavioural, not proof of spoofing.

### Beaconing (whole batch per endpoint triple)

| Feature | Definition |
| --- | --- |
| `connections` | Flows to the same `(src, dst, dport)` |
| `mean_interval_s` | Mean positive inter-arrival time |
| `cv` | Population standard deviation ÷ mean interval |
| `mode_share` | Share of intervals in the dominant 5-second bucket |
| `min_interval_s`, `max_interval_s` | Interval extremes (evidence only) |
| `observation_span` | Last minus first timestamp |

### DGA / DNS (600 s window per source)

| Feature | Definition |
| --- | --- |
| `mean_entropy` | Mean Shannon entropy of the registered portion of each query name |
| `max_label_len` | Longest left-most label |
| `mean_query_len` | Mean full-name length |
| `unique_domains` | Distinct query names |
| `nxdomain_ratio` | Share of responses with NXDOMAIN, where captured |
| `queries_per_min` | Window rate |
| `digit_ratio` | Mean share of digits per query |
| `txt_ratio` | Share of TXT, NULL and CNAME queries |

The registered portion strips the final label, so `a1b2.example.com` is measured on
`a1b2.example` — the TLD does not dominate the entropy figure.

### TLS / QUIC (whole batch per fingerprint-endpoint tuple)

| Feature | Definition |
| --- | --- |
| `ja3_rarity` | `1 − min(1, fingerprint_count ÷ max(3, encrypted_sessions ÷ 4))` |
| `connections` | Sessions in the tuple |
| `avg_duration` | Mean duration in seconds |
| `avg_bytes` | Mean total bytes |
| `sni_missing` | 1 when no session carried SNI |

### Exfiltration (whole batch per source-destination pair)

| Feature | Definition |
| --- | --- |
| `out_bytes` | Sum of `bytes_out` |
| `in_bytes` | Sum of `bytes_in` |
| `ratio` | `out_bytes ÷ max(1, in_bytes)` |
| `duration_s` | First-to-last span |
| `baseline_ratio` | `out_bytes ÷ median(other outbound volumes from this source)`, when available |

---

## 5. Model feature sets

Model inputs are deliberately narrow. A larger feature set would look more impressive and
generalise worse, and the record-level raw data is not always present in production exports.

| Model | Features | Dimensionality |
| --- | --- | --- |
| Port scan | `unique_ports, unique_hosts, attempts, duration_s, failed_ratio, port_entropy` | 6 numeric |
| Exfiltration | `out_bytes, in_bytes, ratio, duration_s, baseline_ratio` | 5 numeric |
| Beaconing | `connections, cv` | 2 numeric |
| DGA / DNS | `query_name` | character 3–5-gram TF-IDF, 4,000 features max |

Beaconing uses only two features on purpose: mean, minimum and maximum interval are derived
quantities that dilute the isolation signal, and the detector already gates on interval scale
and modal-bucket share. Scaling is fitted inside the pipeline (`StandardScaler`), so training
and inference cannot drift apart.

Byte-scale features are left in raw units for the tree models, which are invariant to
monotonic transforms. The DNS model operates on lower-cased character n-grams, which makes it
robust to subdomain prefix changes and does not require a tokeniser that would split on dots.

### Training-data construction

Each model's synthetic corpus is generated deterministically from a fixed seed. Benign and
malicious generators overlap deliberately:

- Scans: 8% of malicious samples are slow and narrow, resembling cautious admin probing; 10% of
  benign samples are authorised availability sweeps across many ports.
- Exfiltration: 8% of malicious samples are low-and-slow below naive volume thresholds; 8% of
  benign samples are large outbound backups.
- Beaconing: 8% of benign scheduled jobs are regular enough to resemble a beacon; 10% of
  malicious samples are jittery.
- DNS: benign includes long high-entropy CDN cache-busting labels; malicious includes
  pronounceable DGA families that are not simply random strings.

The grouped split keeps whole scenarios together, so the evaluation measures generalisation
to new scenarios rather than memorisation of rows. See
[benchmark results](benchmark-results.md) for the measured outcome.

---

## 6. Evidence features vs model features

They are not the same list, and that is intentional. Model features are the smallest numeric
vector that separates classes. Evidence features are what an analyst needs to verify the
alert by hand.

| Detector | Model inputs | Evidence shown to the analyst |
| --- | --- | --- |
| Port scan | 6 numeric | ports, attempts, hosts, SYN ratio, entropy, orientation, flow ids |
| DDoS | none | pps/bps vs baseline, SYN/ACK ratio, source count, source entropy, UDP characterisation |
| Beaconing | 2 numeric (support only) | interval, count, CV, modal share, concentration, span, anomaly score |
| DNS | raw query names | entropy, label length, qpm, NXDOMAIN, record types, sample domains, domain probability |
| TLS/QUIC | none | JA3, rarity, SNI, port, session count, payload-visibility statement |
| Exfiltration | 5 numeric | out/in bytes, ratio, baseline volume, duration, direction method |

Every evidence row stores `observed`, optional `baseline`, optional `unit`, a plain-language
`description`, and the ids of contributing flows (capped at 60 per item). The alert detail page
links back to those flows, which is what makes a finding reviewable.

---

## 7. Missingness policy

| Missing input | Consequence |
| --- | --- |
| Timestamps | Row rejected at ingestion |
| Addresses or ports | Row rejected at ingestion |
| Directional bytes | Exfiltration module returns an incomplete-assessment coverage record; no estimation |
| DNS query names | DNS module produces no detections; coverage says the field was absent |
| TCP flags | SYN-based features are computed from what exists; the evidence text notes the limitation |
| TLS metadata | TLS module produces no detections |
| Byte counts | Volume-based features are zero; no synthetic fill |
| Baseline (single observation) | Evidence prints `insufficient baseline`; gates that require deviation are skipped |

The ingestion preview's **absence report** lists ten capability flags (timestamps, addresses,
ports, byte counts, directional bytes, packets, TCP flags, DNS names, TLS metadata, durations)
so an operator can see, before uploading, which modules the export can support. The
**supported modules** map is computed from the same column set.

---

## 8. Anti-leakage guarantees

- `scenario_id` and `label` are stored for replay evaluation and reporting. No detector reads
  them; no model feature set includes them.
- Model thresholds are selected on the validation split, then frozen before the test split is
  scored.
- Drift is measured between train and test features, not between train and the same rows.
- The replay workspace is cleared before each session, so previous replay alerts cannot
  influence deduplication of a new run.
- Demo and live records are separated by workspace and environment at the storage layer, not
  by a UI filter.
