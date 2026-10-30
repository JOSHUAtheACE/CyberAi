# Data sources and ingestion

SENTINEL AI is passive. It accepts metadata that already exists and never generates traffic,
connects back to monitored hosts, or captures packets in the browser. This page covers every
way telemetry enters the platform, what is validated, what is deliberately discarded, and how
demo and replay differ from live data.

---

## 1. Entry points

| Entry point | Who uses it | Typical volume | Storage |
| --- | --- | --- | --- |
| File upload | Analyst or engineer validating an export | One-off investigation | Stored under `data/uploads`, hashed |
| Collector push | Enclave collector forwarding metadata | Continuous, ≤ 5,000 records/request | Stored in `flow_records` |
| Replay | Analyst re-processing a capture or demo scenario | Up to 50,000 flows per session | Isolated REPLAY workspace |
| Demo seed | First start with demo enabled | 11 labelled scenarios | DEMO workspace only |

### What the browser is not

The browser is never a packet source, never receives raw packets, and never originates a feed
connection. The collector runs inside the monitoring enclave and pushes a one-way copy of
metadata to the API.

---

## 2. File upload

`POST /api/v1/ingestion/preview` validates without persisting.
`POST /api/v1/ingestion/upload` accepts and processes asynchronously (HTTP 202).

### Accepted formats

| Extension | Parser | Kind |
| --- | --- | --- |
| `.pcap`, `.pcapng`, `.cap` | Binary capture parser | `pcap` |
| `.csv`, `.txt` | Delimited text with dialect sniffing (` ,` `;` tab `|`) | `flows` |
| `.tsv` | Tab-delimited; Zeek detection when `#fields` is present | `flows` / `zeek` |
| `.json` | Array, or an object containing `records`, `flows`, `data` or `events` | `flows` |
| `.jsonl`, `.ndjson` | One JSON object per line; malformed lines skipped | `flows` |
| `.log` | Zeek TSV when `#fields` appears in the header | `zeek` |

PCAP support covers classic pcap in both endiannesses with microsecond or nanosecond
timestamps, and pcapng with multiple interfaces, Enhanced Packet Blocks, Simple Packet Blocks
and the obsolete Packet Block. Unsupported link types produce a note rather than a crash.

The capture parser reconstructs flows from IP packets, including TCP, UDP, ICMP and SCTP,
and extracts DNS query metadata (name, type, response code) and TLS ClientHello metadata
(SNI, JA3, version, cipher) plus QUIC indicators. It never decrypts payloads; it reads
handshake fields that are transmitted in the clear.

### Limits

| Limit | Value | Enforced at |
| --- | --- | --- |
| Upload size | 50 MB default (`SENTINEL_MAX_UPLOAD_MB`) | HTTP 413 before parsing |
| Preview file size | 8 MB or the configured limit, whichever is smaller | Preview endpoint |
| Preview packets | 20,000 | Preview |
| Preview records | 20,000 | Preview |
| Full PCAP packets | 500,000 | Upload processing |
| Full flow records | 200,000 | Upload processing |
| Preview rows returned | 20 (25 configured maximum) | Response |

When a limit is hit, the result says so (`packet_limit_reached`, `flow_cardinality_limit_reached`,
or a record-limit note) instead of presenting a silently truncated dataset as complete.

### Validation and quality report

The preview returns:

- **`valid`** — whether at least one normalised record was produced.
- **`quality.total_rows`, `valid_records`, `rejected_records`** and **`rejection_reasons`**
  (see [feature engineering](feature-engineering.md#rejection-reasons)).
- **`columns_detected`** and **`column_mapping`** — which source column became which canonical
  field.
- **`supported_modules`** — DDoS, beaconing, DNS, encrypted, scanning and exfiltration, each
  true/false based on whether at least half its required inputs (minimum two) are present.
- **`absence_report`** — ten capability flags: timestamps, addresses, ports, byte counts,
  directional bytes, packets, TCP flags, DNS names, TLS metadata, durations.
- **`direction_available`** — whether any row carried directional byte counts.
- **`preview`** — up to 20 normalised rows.
- **`notes`** — parser caveats, duplicate detection and truncation notices.

PCAP previews additionally report packet count, reconstructed flow count, capture start and
end, link types and twelve sample flows.

### Upload processing

1. Content is read with a hard byte ceiling, SHA-256 hashed, and written under
   `data/uploads/<job>-<hash-prefix>-<filename>`.
2. A prior job with the same hash is recorded as `duplicate_of` in the job stats. It is not
   silently merged or deleted.
3. A background task parses, normalises, inserts in batches and runs all enabled detectors.
4. The job record moves through `QUEUED → PARSING → DETECTING → COMPLETE` (or `FAILED`), with
   record totals, valid/rejected counts, alerts generated, detection duration and parse notes.
5. An audit entry records filename, kind, bytes and hash; a system event records completion.

The interface polls the job and reports progress; it never displays a completed state before
the backend has written one.

---

## 3. Collector feed

Collectors are registered in the Admin/Ingestion area. Creating a source returns a raw API key
exactly once; only its SHA-256 fingerprint is stored. Rotation issues a new key and invalidates
the old one.

### Contract

```http
POST /api/v1/feed/ingest
X-Collector-Id: <collector identifier>
X-Collector-Key: <raw key>
Content-Type: application/json

{
  "format": "flow_json",
  "sent_at": "2026-10-30T12:00:00Z",
  "records": [
    {
      "ts": "2026-10-30T11:59:58Z",
      "src_ip": "10.0.4.18",
      "dst_ip": "198.51.100.42",
      "src_port": 51244,
      "dst_port": 443,
      "protocol": "TCP",
      "bytes_out": 1840,
      "bytes_in": 62012,
      "packets": 46,
      "duration": 1.42
    }
  ]
}
```

| Property | Value |
| --- | --- |
| Authentication | Header pair, fingerprint comparison |
| Max records per request | 5,000 |
| Rate limit | 120 requests/minute per collector |
| Environment | The collector's workspace environment (`LIVE`, `DEMO`, `REPLAY`) |
| Response | Accepted/rejected counts, rejection reasons, alerts created/updated, per-detector counts, coverage |
| Heartbeat | `GET /api/v1/feed/heartbeat`, returns contract version and expected interval |

Collectors that go quiet are marked `STALE` after five minutes; the UI shows `LIVE`, `STALE` or
`DISCONNECTED` from stored state, not from a client-side timer guess.

### Supported collector kinds

NetFlow v5/v9, IPFIX, sFlow v5, Zeek JSON streams and PCAP sensors. For each, the enclave
collector is responsible for converting its native output into the flow JSON contract before
forwarding. The platform does not open a listener for NetFlow or IPFIX datagrams itself; that
is deliberate, because accepting unauthenticated UDP on the application host would widen the
attack surface for no analytical gain.

---

## 4. Demo corpus

Seeded only when `SENTINEL_DEMO_ENABLED=true` (the development default). It lives in the `demo`
workspace, is tagged `DEMO` on every record and alert, and is never mixed with live telemetry.

| Scenario | Threat class | Ground truth | Duration |
| --- | --- | --- | --- |
| SYN flood — edge web tier | `Possible_DDoS` | `tcp_syn_flood` | 95 s |
| UDP amplification signature — NTP | `Possible_DDoS` | `udp_reflection_signature` | 58 s |
| Vertical port scan | `Possible_Port_Scan` | `vertical_port_scan` | 40 s |
| Horizontal SSH sweep | `Possible_Port_Scan` | `horizontal_host_sweep` | 30 s |
| C2 beacon — 60 second cadence | `Possible_C2_Beaconing` | `periodic_callback` | 14 min |
| Low-and-slow beacon — 5 minute cadence | `Possible_C2_Beaconing` | `sleep_callback` | 40 min |
| DGA burst | `Possible_DGA_or_DNS_Tunnelling` | `domain_generation_algorithm` | 6 min |
| DNS tunnelling | `Possible_DGA_or_DNS_Tunnelling` | `txt_record_tunnel` | 10 min |
| Low-volume DGA | `Possible_DGA_or_DNS_Tunnelling` | `domain_generation_algorithm` | 5 min |
| Rare TLS fingerprint | `Unusual_TLS_Metadata` | `rare_client_fingerprint` | 25 min |
| Bulk outbound transfer | `Possible_Data_Exfiltration` | `bulk_https_transfer` | 20 min |

Ground truth is retained for replay evaluation and comparison. It is never read by a detector.
Demo addresses use reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). Demo geolocation is configured fixture metadata, labelled
`demo_synthetic` or `demo_configured_asset`, not a real lookup.

---

## 5. Replay

Replay re-processes a demo scenario or a completed upload into the REPLAY workspace.

| Property | Value |
| --- | --- |
| Speeds | 0.5×, 1×, 2×, 5× |
| Timeline compression | Captures longer than 120 s of wall time are compressed; the factor is recorded |
| Max flows per session | 50,000 |
| Isolation | Replay alerts, evidence, features and flows are cleared before each session |
| Detector scope | Selectable categories map to specific detectors; no selection means all |
| Output | Progress events, alerts generated, processing latency, final completion event |
| Label | Every replay session carries a permanent REPLAY/DEMO label |

Pause, resume and stop act on a background control object; a stopped session cannot resume
silently. Failures mark the session `FAILED` and write a system event with the exception class,
never a fabricated success.

---

## 6. Retention and storage

| Artefact | Location | Lifecycle |
| --- | --- | --- |
| Flow records | SQLite `flow_records` | Retained until an administrator curates retention |
| Uploads | `data/uploads` | Retained with the job record |
| Model artefacts | `models/trained` | Superseded versions remain on disk but inactive |
| Evaluations | `model_evaluations` | Append-only per training run |
| Audit log | `audit_logs` | Append-only |
| System events | `system_events` | Operation and detection summaries |

There is no automatic purge job in this release. Retention policy is an operational decision,
and the schema keeps the provenance needed to implement one (hash, job reference, source id,
workspace, environment, timestamps).

---

## 7. Data-handling guarantees

- Uploads and feed records are validated before insertion. Rejected rows are counted with a
  reason and never inserted as zero-valued placeholders.
- Raw packets are not retained after flow extraction unless the original capture was uploaded;
  in that case the file is stored with its hash and job reference.
- PCAP contents, raw flows, internal hostnames and private addresses are never sent to an
  external service. External lookups accept only public IPs or bare hostnames and reject
  private, loopback, link-local, reserved and documentation ranges locally.
- TLS and QUIC payloads are never decrypted. Only handshake metadata is read.
- All persisted and returned timestamps are UTC.
