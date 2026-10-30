# Limitations

Every product has boundaries. This page lists them plainly so operators can decide where
SENTINEL AI fits and where it does not. None of these is a hidden defect; each is a known
trade-off with a described behaviour in the product.

---

## 1. What this platform is not

- **Not a prevention system.** It does not block, quarantine, rate-limit, isolate, reconfigure
  or probe any host, firewall, switch or endpoint. There is no active response feature, by
  design and by policy.
- **Not a full packet capture archive.** PCAP is parsed into flow metadata. The platform does
  not store packet payloads for later search, and it does not reassemble streams.
- **Not an endpoint or identity product.** It has no EDR telemetry, process trees, user
  logins, DNS server logs or cloud audit logs unless those are converted into flow records
  and ingested.
- **Not a SIEM replacement.** There is no correlation across arbitrary log sources, no
  long-term hot storage tier, and no log forwarding.
- **Not a decryption tool.** TLS and QUIC payloads are never decrypted. Encrypted analysis is
  limited to handshake metadata and volume/timing behaviour.
- **Not a threat-intelligence provider.** It consumes limited public indicator services and a
  local snapshot. It does not collect, curate or redistribute intelligence.
- **Not a compliance archive.** Reports are operational summaries, not immutable,
  WORM-backed records.

---

## 2. Detection limits

### General

- Detections are only as good as the fields present. Missing DNS names, TCP flags, directional
  bytes or TLS metadata silently remove a module's ability to see a behaviour; the UI reports
  that gap instead of guessing.
- Behavioural windows need enough observations. A five-minute capture cannot demonstrate a
  forty-minute beacon, and the product will not pretend it did.
- All thresholds ship as sensible defaults, not tuned values for your network. They are
  editable, but tuning is an operational responsibility.
- No detection has been validated against your traffic. Stored model metrics come from a
  synthetic corpus; see §3.

### Per module

| Module | Known blind spot |
| --- | --- |
| Port scan | Administrative scanners, inventory agents and health checks look identical; narrow scans may fall below the fan-out gate |
| DDoS | Legitimate bulk transfers to one destination can resemble volumetric floods; slow-ramp floods below the floor are missed |
| Beaconing | Jittered low-and-slow callbacks, infrequent beacons under six connections, and long intervals beyond one hour are missed or weakened |
| DGA / DNS | Encrypted DNS (DoH/DoT) hides query names; CDN and telemetry identifiers can resemble generated domains |
| TLS / QUIC | Fingerprint rarity is dataset-relative; uncommon but legitimate clients trigger leads, and encrypted payload intent is unknowable |
| Exfiltration | Requires directional metadata and configured zones; large legitimate uploads and backups can resemble exfiltration; in-protocol smuggling inside normal volume is missed |

### Correlation

Alerts are deduplicated per detector and dedup key. The platform does not perform
cross-detector attack-chain correlation, risk scoring across entities, or campaign clustering.
An analyst can link alerts manually. Automatic correlation is out of scope for this release.

---

## 3. Model and metric limits

- **Synthetic training data.** All four models are trained on a generated corpus shipped with
  the repository. It contains deliberate overlap between classes, but it is not your network.
- **Small evaluation sets.** Port scan and exfiltration evaluations use 44 test rows each. A
  single record moves FPR by several points. Confidence intervals are wide and not displayed
  because a small-sample interval on synthetic data would imply more precision than exists.
- **Optimistic by construction.** Generators and held-out scenarios share family structure.
  Expect lower field precision until retraining on labelled telemetry.
- **No probability calibration guarantee in the field.** Calibration is fitted on synthetic
  data. A stored `calibrated_probability` is honest about its method, not about your traffic.
- **Anomaly score is not a probability.** Beaconing reports an Isolation Forest score in
  0–1. It is labelled as such and is supporting evidence only.
- **Rule-based modules have no metrics.** DDoS and TLS/QUIC have no trained artefact, so no
  precision, recall or F1 is claimed for them.
- **Drift is diagnostic.** KS statistics are stored, but no retraining or alerting is
  triggered automatically.
- **No LLM in the detection path.** `SENTINEL_LLM_ENABLED` exists but is off by default and
  no detection or score depends on it. Insights are deterministic and traceable to stored
  data, which also means they are narrower than a generative summary would be.

---

## 4. Ingestion limits

| Limit | Value |
| --- | --- |
| Upload size | 50 MB default |
| PCAP packets per upload | 500,000 |
| Flow records per upload | 200,000 |
| Preview packets / records | 20,000 |
| Preview rows returned | 20 |
| Collector batch | 5,000 records |
| Replay session | 50,000 flows |

Additional parsing constraints:

- Supported capture link types are Ethernet (including up to three VLAN tags), Linux cooked
  capture, and raw IPv4/IPv6. Others produce an `unsupported_link_type` note.
- PCAP flow reconstruction covers TCP, UDP and ICMP. SCTP is accepted in flow exports but is
  not reconstructed from packets.
- Non-first IP fragments are skipped; there is no fragment reassembly.
- Simple Packet Blocks without timestamps are counted but do not contribute reliable timing.
- JSONL parsing skips malformed lines rather than failing the file, and the skip count is not
  individually listed beyond the quality totals.

---

## 5. Data and environment limits

- **Direction depends on configuration.** Until internal CIDRs reflect reality, `outbound`
  and `inbound` are wrong, which degrades exfiltration detection and topology semantics.
- **Geolocation is approximate.** Coordinates approximate network registration, not a device
  or a person. Private addresses are never assigned coordinates. Demo coordinates are fixtures,
  explicitly labelled.
- **No automatic retention or purge.** Data grows until an operator removes it. The schema
  retains provenance to support a future retention policy.
- **Time is UTC everywhere.** Local display conventions are not implemented; this avoids
  ambiguity but may surprise operators who expect local time.
- **Replay compresses long timelines.** Captures longer than 120 s of wall time are sped up,
  and the factor is recorded. A replay demonstrates detection behaviour, not real-time packet
  timing fidelity.
- **Replay is single-session per workspace.** A new session resets the REPLAY workspace, so
  two simultaneous replays into the same workspace are not supported.
- **Demo data is synthetic.** It uses reserved documentation addresses and generated
  behaviours. It is useful for demonstrating workflows, not for benchmarking against real
  attacks.

---

## 6. Integration limits

- **External enrichment is disabled by default** and requires both a deployment switch and a
  per-provider enable after approval.
- **Provider coverage varies.** A "no match" from ThreatFox, URLhaus, AbuseIPDB or GreyNoise
  means that provider had nothing at query time, not that the indicator is benign.
- **Caching can be stale.** Results are cached for 24 hours. The retrieval time and validity
  are shown; a stale answer is labelled as cached, not refreshed silently.
- **AbuseIPDB daily quota** is documented as 1,000/day but is not enforced by a persistent
  counter in this release; rely on the provider's own quota response.
- **MaxMind requires a local database** for geolocation. Without it, no coordinates appear.
  The platform does not call a MaxMind web service.
- **Offline snapshot import is trust-based.** Imported indicators are not cryptographically
  verified in this release; the metadata records the claimed source and licence.
- **No webhooks, SIEM forwarding or ticketing sync.** Alert export and report export are the
  supported outbound paths.

---

## 7. Platform and scale limits

- **SQLite, single process.** One Uvicorn worker per database is the supported topology. Write
  throughput, concurrent ingestion and replay concurrency are bounded accordingly.
- **In-process rate limiting.** Limits reset on restart and are per process. They are not a
  distributed control.
- **No migration framework.** `init_db` creates missing tables and seeding reconciles
  reference rows. A schema change needs an explicit migration, which this release does not
  ship.
- **No high availability.** No leader election, no replicated database, no automatic failover.
  Backups and a supervised restart are the recovery model.
- **Single node for replay and event bus.** Subscriber queues and replay controls are held in
  memory. A restart ends active replays and WebSocket sessions; the UI shows the stream as
  offline and reconnects.
- **Browser rendering limits.** The 3D globe needs WebGL; a static fallback is provided. Very
  large topologies are capped for readability rather than rendered in full.
- **Report and PDF generation are synchronous.** A very large report may occupy a request for
  a noticeable time. The PDF writer is intentionally plain and has no chart rendering.
- **No email delivery.** Password resets, invitations and digest emails are not implemented;
  accounts are created by an administrator.

---

## 8. Security limits

Implemented controls are described in the [README](../README.md) and
[deployment guide](deployment.md). The limits of those controls:

- **No MFA and no SSO/SAML/OIDC.** Authentication is email plus password with a signed
  session cookie.
- **Demo credentials are public by design.** If `SENTINEL_DEMO_ENABLED=true` is left on in a
  shared environment without changing the password, anyone who reads this repository can sign
  in. Treat that as a deployment error, not a product feature.
- **CSRF protection depends on the cookie flow.** Collector feed endpoints are exempt because
  they authenticate with a header key pair, not a browser session.
- **The rate limiter is memory-bound** and per process, so it does not survive restarts and
  cannot coordinate across replicas.
- **No WAF, bot detection or IP reputation** at the application layer. Those belong at the
  edge.
- **Audit logs are application-level records.** They are not tamper-evident against someone
  with direct database access.
- **Secret handling is environment-based.** There is no vault integration. Protect the process
  environment and `.env` file accordingly.
- **The development secret file** `data/.secret_key` exists for convenience. Production must
  set `SENTINEL_SECRET_KEY` explicitly.

---

## 9. Honesty invariants

These hold across the product and are the reason several screens show less than they could:

1. If a value was not measured, it is empty, null or explicitly "not available".
2. If a module lacked inputs, it reports insufficient visibility instead of a low score.
3. Demo and replay content is labelled on every surface where it appears.
4. Model metrics are attributed to the synthetic corpus, with sample sizes and thresholds.
5. External enrichment is labelled contextual, never conclusive.
6. Exports carry their query, period and limitations so a report cannot be repurposed as
   something it is not.
7. Nothing in the product claims to have prevented, blocked or remediated an attack.
