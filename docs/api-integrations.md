# API integrations

SENTINEL AI integrates with five external intelligence services plus a local offline
snapshot. All of them are **disabled by default**, all network calls originate server-side,
and none of them is required for detection, alerting, investigation or reporting.

This page describes the integration design, the exact guard rails, and what an administrator
must do to enable a provider.

---

## 1. Default posture

| Layer | Default |
| --- | --- |
| Global external switch | Off (`SENTINEL_ALLOW_EXTERNAL_ENRICHMENT=false`) |
| Per-provider enable | Off |
| Credentials | Read from the server environment; absent by default |
| Provider state in UI | `NOT_CONFIGURED` until credentials are present, then `DISABLED` |
| Core product behaviour | Fully functional without any provider |

The interface shows `NOT_CONFIGURED` rather than a fabricated "connected" state. It never
shows a credential value, only the environment-variable name and whether it is present.

---

## 2. Providers

| Provider | Purpose | Credential variables | Rate limit | Attribution |
| --- | --- | --- | --- | --- |
| ThreatFox (abuse.ch) | IOC search for public indicators | `THREATFOX_AUTH_KEY` | 60 rpm, retry-after aware | abuse.ch / ThreatFox |
| URLhaus (abuse.ch) | Malware URL/host reputation | `URLHAUS_AUTH_KEY` | 60 rpm | abuse.ch / URLhaus |
| AbuseIPDB | IP abuse reporting | `ABUSEIPDB_API_KEY` | 60 rpm, 1,000/day | AbuseIPDB |
| GreyNoise | Internet background-noise classification | `GREYNOISE_API_KEY` | 60 rpm | GreyNoise Intelligence |
| MaxMind GeoLite2 | IP geolocation | `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `MAXMIND_DB_PATH` | Local database, no per-request calls | MaxMind GeoLite2 |
| Offline TI snapshot | Air-gapped indicator import | None | Local only | Administrator-imported snapshot |

MaxMind is a local database read, not a network integration. It supplies country, city and
coordinates during ingestion for public addresses only.

---

## 3. Two-key enablement

External requests require **both**:

1. The deployment-level switch `SENTINEL_ALLOW_EXTERNAL_ENRICHMENT=true`, or the runtime
   setting `external_enrichment.enabled` set by a Security Administrator in Settings.
2. The per-provider toggle set to enabled by a user with `intel.manage`.

Credentials alone are not enough. A provider with valid credentials still refuses lookups
while the global switch is off. This prevents an accidental environment variable from
creating silent outbound traffic.

The per-provider toggle also fails with HTTP 409 if credentials are missing, so a provider
cannot be marked enabled in a state where it would always error.

---

## 4. Indicator policy

Before any external call, the indicator is validated locally:

| Input | Decision |
| --- | --- |
| Public IPv4/IPv6 | Accepted |
| Private, loopback, link-local, reserved, documentation range | **Refused locally**, never transmitted |
| Bare hostname or domain | Accepted, lower-cased, trailing dot removed |
| URL with a path, spaces, or `/` | Refused |
| Empty, over 255 characters | Refused |
| Single label without a dot | Refused as a domain |

The refusal message is explicit: private, reserved or loopback addresses are never sent to
external providers. This is the enforcement point for the rule that raw flows, internal
hostnames and private addresses never leave the environment.

What is sent is the indicator string and a fixed user agent only. No flow records, no alert
context, no workspace identifiers, no packet data.

---

## 5. Request behaviour

| Property | Value |
| --- | --- |
| Timeout | 10 s total, 6 s connect |
| Redirects | Not followed |
| Local rate limit | 25 requests/minute per provider (separate from the advertised upstream limit) |
| Cache TTL | 24 hours per (provider, indicator) |
| Cache scope | Successful (`OK`) results only; errors are not cached |
| Retry | None automatically; the operator may retry |
| Logging | Failures store a redacted message; known credential values are replaced with `[redacted]` |
| Response size | Provider payloads are trimmed to what the interface renders |

Cached results are returned with `cached: true` and the original retrieval time plus
`valid_until`. Fresh results carry `confidence_type: provider_reported`, because a provider's
score is not a platform-calibrated probability.

---

## 6. Guard rails against overclaiming

- Every lookup response carries a `context_notice`: external intelligence is contextual
  evidence, not proof of compromise or attribution.
- A provider listing never changes an alert's severity or status automatically. Enrichment is
  displayed next to the evidence; the analyst decides.
- Provider confidence is labelled as provider-reported where it exists (AbuseIPDB score,
  ThreatFox confidence level) and omitted where it does not (GreyNoise classification,
  MaxMind location).
- No enrichment result is written into detection features or model inputs.
- Missing or failed enrichment leaves the product usable and says the lookup failed. It does
  not substitute a plausible-looking value.

---

## 7. Audit and transparency

The following are recorded in the audit log:

| Action | Recorded metadata |
| --- | --- |
| `intel.provider_updated` | Provider, enabled state |
| `intel.lookup` | Providers used, indicator prefix (64 chars), optional alert id |
| Provider test | Stored on the provider config and in enrichment results |

Each lookup also writes an `enrichment_results` row with provider, indicator, status
(`OK`, `ERROR`, `TEST_OK`), payload or redacted error, and retrieval time. Positive verdicts
create a `threat_intel_indicators` row with source URL, licence/attribution and 24-hour
validity. The Intelligence page renders this history so an analyst can see what was queried,
when, and against which provider.

---

## 8. Endpoints

All endpoints are under `/api/v1` and require a session.

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/intel/providers` | `intel.view` | Masked provider states, limits, attribution |
| PATCH | `/intel/providers/{provider}` | `intel.manage` | Enable or disable a configured provider |
| POST | `/intel/providers/{provider}/test` | `intel.manage` | Narrowly scoped test lookup |
| POST | `/intel/lookup` | `intel.view` | Look up one public indicator across enabled providers |
| POST | `/intel/alerts/{id}/enrich` | `intel.view` | Enrich the alert's public indicators |
| GET | `/intel/indicators` | `intel.view` | Stored indicator records |
| GET | `/intel/enrichment` | `intel.view` | Enrichment history |
| POST | `/intel/snapshot` | `intel.manage` | Import an offline indicator snapshot |

### Test behaviour

The test endpoint performs one lookup against a public test indicator
(`SENTINEL_TEST_INDICATOR`, default `8.8.8.8`) and returns measured latency and a verdict.
It does not scan, probe or connect to the monitored estate. For the offline snapshot it
reports the imported indicator count instead of making a request.

### Offline snapshot import

```json
{
  "metadata": {
    "source": "internal CTI feed",
    "licence": "internal use only",
    "exported_at": "2026-10-30T00:00:00Z"
  },
  "indicators": [
    {
      "indicator": "203.0.113.50",
      "type": "ip",
      "verdict": "c2",
      "confidence": 80,
      "first_seen": "2026-10-01T00:00:00Z",
      "last_seen": "2026-10-20T00:00:00Z",
      "valid_until": "2026-12-01T00:00:00Z",
      "source_url": "https://intel.internal/example"
    }
  ]
}
```

Imported entries are served without any network access, which is the supported path for
air-gapped deployments. Each entry retains its source, licence and validity metadata. Invalid
or over-long indicators are counted as rejected rather than silently imported.

---

## 9. Failure modes

| Failure | Behaviour |
| --- | --- |
| Credentials absent | Provider shows `NOT_CONFIGURED`; toggle refused with 409 |
| Global switch off | Lookup refused with a clear policy message |
| Upstream timeout or HTTP error | 502 to the caller, redacted error stored, provider marked `ERROR` |
| Local rate limit reached | Explicit "try again shortly" message; no queue and no silent drop |
| Upstream returns no match | Honest `no_match` verdict, not an error and not a positive |
| MaxMind database absent | Geolocation is simply not populated; no invented coordinates |

None of these conditions blocks ingestion, detection, alerting or reporting.
