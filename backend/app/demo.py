"""Deterministic synthetic demo corpus.

Every record here is synthetic and confined to the DEMO workspace. Public
addresses use reserved documentation ranges (RFC 5737). Internal asset
coordinates are configured demo metadata, not IP-derived geolocation.
"""

from __future__ import annotations

import random
import string
from datetime import datetime, timedelta

from .models import utcnow
from .parsing import FlowIn

COMMON_JA3 = "cd08e31494f9531f560d64c695473da9"
SECOND_JA3 = "579ccef312d18482fc42e2b822ca2430"
RARE_JA3 = "8f1c3a6e9d0b7f42c5e1a8d3b6f9c204"

EXTERNAL_SITES = {
    "198.51.100.14": "Ashburn",
    "198.51.100.77": "San Jose",
    "198.51.100.201": "Sao Paulo",
    "203.0.113.10": "Frankfurt",
    "203.0.113.24": "Amsterdam",
    "203.0.113.51": "London",
    "192.0.2.33": "Singapore",
    "192.0.2.64": "Tokyo",
    "192.0.2.90": "Mumbai",
    "192.0.2.145": "Sydney",
    "192.0.2.210": "Dubai",
}

BENIGN_DOMAINS = [
    "api.github.com", "login.microsoftonline.com", "www.google.com", "cdn.cloudflare.com",
    "outlook.office365.com", "time.windows.com", "ocsp.digicert.com", "update.googleapis.com",
    "registry.npmjs.org", "docs.python.org", "api.stripe.com", "fonts.gstatic.com",
    "ntp.ubuntu.com", "sso.corp.example", "portal.example", "intranet.example",
]

INTERNAL_HOSTS = {
    "10.20.1": [f"10.20.1.{n}" for n in range(10, 46)],
    "10.20.2": [f"10.20.2.{n}" for n in range(10, 31)],
    "10.20.3": [f"10.20.3.{n}" for n in range(40, 61)],
    "10.20.4": [f"10.20.4.{n}" for n in range(20, 36)],
    "10.20.5": [f"10.20.5.{n}" for n in range(10, 21)],
    "10.20.6": [f"10.20.6.{n}" for n in range(10, 26)],
}


def _ts(base: datetime, offset_seconds: float) -> datetime:
    return (base + timedelta(seconds=offset_seconds)).replace(microsecond=0)


def _dga_domain(rng: random.Random) -> str:
    alphabet = rng.choice([string.ascii_lowercase + string.digits, string.ascii_lowercase])
    label = "".join(rng.choice(alphabet) for _ in range(rng.randint(10, 28)))
    if rng.random() < 0.3:
        label += "." + "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 16)))
    return label + "." + rng.choice(["top", "xyz", "biz", "info", "click", "live"])


def _tunnel_domain(rng: random.Random) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    label = "".join(rng.choice(alphabet) for _ in range(rng.randint(44, 60)))
    return f"{label}.tunnel.example"


def generate_demo_corpus(now: datetime | None = None) -> dict:
    rng = random.Random(20261030)
    now = (now or utcnow()).replace(second=0, microsecond=0)
    start = now - timedelta(hours=24)
    flows: list[FlowIn] = []

    def add(
        ts: datetime,
        src: str,
        dst: str,
        *,
        sport: int = 0,
        dport: int = 0,
        proto: str = "TCP",
        packets: int = 1,
        b_out: int = 0,
        b_in: int = 0,
        duration_ms: int = 0,
        flags: str | None = None,
        app: str | None = None,
        dns_query: str | None = None,
        dns_qtype: str | None = None,
        dns_rcode: str | None = None,
        tls_sni: str | None = None,
        tls_ja3: str | None = None,
        tls_version: str | None = None,
        tls_cipher: str | None = None,
        scenario: str | None = None,
        label: str | None = None,
        quic: bool = False,
    ) -> None:
        flows.append(
            FlowIn(
                ts=ts,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                app_proto=app,
                bytes_total=b_out + b_in,
                bytes_out=b_out,
                bytes_in=b_in,
                packets=packets,
                duration_ms=duration_ms,
                tcp_flags=flags,
                dns_query=dns_query,
                dns_qtype=dns_qtype,
                dns_rcode=dns_rcode,
                tls_sni=tls_sni,
                tls_ja3=tls_ja3,
                tls_version=tls_version,
                tls_cipher=tls_cipher,
                quic=quic,
                scenario_id=scenario,
                label=label,
                meta={"has_direction": True, "origin": "synthetic_demo"},
            )
        )

    # ------------------------------------------------------------------
    # Baseline enterprise traffic: 24 hours, five-minute buckets
    # ------------------------------------------------------------------
    sites = list(EXTERNAL_SITES.keys())
    for bucket in range(288):
        base = start + timedelta(minutes=5 * bucket)
        base_ts = _ts(base, rng.randint(0, 280))
        hour = (base.hour + 2) % 24
        activity = 0.6 + 0.7 * (0.5 + 0.5 * __import__("math").sin((hour - 6) / 24 * 6.283))

        # workstation egress to SaaS
        for _ in range(max(1, int(2 * activity))):
            src = rng.choice(INTERNAL_HOSTS["10.20.1"])
            dst = rng.choice(sites)
            add(
                _ts(base, rng.randint(0, 280)), src, dst, sport=rng.randint(49152, 65000), dport=443,
                packets=rng.randint(12, 70), b_out=rng.randint(4_000, 120_000),
                b_in=rng.randint(40_000, 900_000), duration_ms=rng.randint(2_000, 60_000),
                flags="SYN+ACK+PSH", app="tls", tls_sni=rng.choice(BENIGN_DOMAINS),
                tls_ja3=COMMON_JA3, tls_version="TLS1.3", tls_cipher="0x1301",
            )
        # inbound edge web traffic
        src = rng.choice(sites)
        add(
            base_ts, src, "10.20.5.10", sport=rng.randint(30000, 60000), dport=443,
            packets=rng.randint(10, 55), b_out=rng.randint(2_000, 30_000),
            b_in=rng.randint(30_000, 600_000), duration_ms=rng.randint(1_500, 40_000),
            flags="SYN+ACK+PSH", app="tls", tls_sni="portal.example", tls_ja3=SECOND_JA3,
            tls_version="TLS1.2", tls_cipher="0xc02f",
        )
        # internal file service
        add(
            _ts(base, rng.randint(0, 280)), rng.choice(INTERNAL_HOSTS["10.20.1"]), "10.20.2.20",
            sport=rng.randint(49152, 65000), dport=445, packets=rng.randint(8, 90),
            b_out=rng.randint(2_000, 80_000), b_in=rng.randint(2_000, 400_000),
            duration_ms=rng.randint(3_000, 120_000), flags="SYN+ACK+PSH", app="smb",
        )
        # DNS
        for _ in range(2):
            qname = rng.choice(BENIGN_DOMAINS)
            add(
                _ts(base, rng.randint(0, 280)), rng.choice(INTERNAL_HOSTS["10.20.4"]),
                "203.0.113.24", sport=rng.randint(49152, 65000), dport=53, proto="UDP",
                packets=2, b_out=rng.randint(70, 120), b_in=rng.randint(120, 600),
                duration_ms=rng.randint(10, 90), app="dns", dns_query=qname,
                dns_qtype=rng.choice(["A", "AAAA"]), dns_rcode="NOERROR",
            )
        # NTP
        add(
            _ts(base, rng.randint(0, 280)), rng.choice(INTERNAL_HOSTS["10.20.3"]),
            "192.0.2.145", sport=123, dport=123, proto="UDP",
            packets=2, b_out=76, b_in=76, duration_ms=40, app="ntp",
        )
        # Tokyo engineering egress
        add(
            _ts(base, rng.randint(0, 280)), rng.choice(INTERNAL_HOSTS["10.20.6"]),
            "198.51.100.77", sport=rng.randint(49152, 65000), dport=443,
            packets=rng.randint(8, 45), b_out=rng.randint(3_000, 60_000),
            b_in=rng.randint(20_000, 400_000), duration_ms=rng.randint(2_000, 30_000),
            flags="SYN+ACK+PSH", app="tls", tls_sni=rng.choice(BENIGN_DOMAINS),
            tls_ja3=COMMON_JA3, tls_version="TLS1.3", tls_cipher="0x1301",
        )
        # Ashburn backup host baseline egress (gives the exfiltration baseline a peer)
        if bucket % 3 == 0:
            add(
                _ts(base, rng.randint(0, 280)), "10.20.2.77", rng.choice(["198.51.100.14", "203.0.113.51"]),
                sport=rng.randint(49152, 65000), dport=443, packets=rng.randint(20, 80),
                b_out=rng.randint(300_000, 900_000), b_in=rng.randint(80_000, 260_000),
                duration_ms=rng.randint(10_000, 60_000), flags="SYN+ACK+PSH", app="tls",
                tls_sni="backup.vendor.example", tls_ja3=COMMON_JA3,
                tls_version="TLS1.3", tls_cipher="0x1301",
            )

    # ------------------------------------------------------------------
    # Scenario: SYN flood against the edge web tier
    # ------------------------------------------------------------------
    syn_base = now - timedelta(hours=6)
    attack_sources = list(EXTERNAL_SITES.keys())
    for i in range(96):
        src = attack_sources[i % len(attack_sources)]
        add(
            _ts(syn_base, rng.uniform(0, 95)), src, "10.20.5.10",
            sport=rng.randint(1024, 65000), dport=443, proto="TCP",
            packets=rng.randint(180, 380), b_out=rng.randint(14_000, 40_000), b_in=0,
            duration_ms=60_000, flags="SYN", app="https-syn", scenario="demo-ddos-syn",
            label="ddos_syn_flood",
        )

    # ------------------------------------------------------------------
    # Scenario: UDP reflection signature (NTP port)
    # ------------------------------------------------------------------
    udp_base = now - timedelta(hours=5, minutes=30)
    for i in range(46):
        add(
            _ts(udp_base, rng.uniform(0, 58)), "198.51.100.14", "10.20.5.11",
            sport=123, dport=123, proto="UDP", packets=rng.randint(420, 620),
            b_out=rng.randint(520_000, 720_000), b_in=0, duration_ms=60_000, app="ntp",
            scenario="demo-ddos-udp", label="udp_reflection_signature",
        )

    # ------------------------------------------------------------------
    # Scenario: vertical port scan
    # ------------------------------------------------------------------
    scan_base = now - timedelta(hours=2)
    ports = rng.sample(range(1, 1025), 220)
    for i, port in enumerate(ports):
        add(
            _ts(scan_base, i * 0.18), "198.51.100.201", "10.20.1.10",
            sport=rng.randint(1024, 65000), dport=port, proto="TCP", packets=1,
            b_out=60, b_in=0, duration_ms=0, flags="SYN", scenario="demo-scan-vertical",
            label="port_scan_vertical",
        )

    # ------------------------------------------------------------------
    # Scenario: horizontal SSH sweep
    # ------------------------------------------------------------------
    hscan_base = now - timedelta(hours=7)
    for i in range(60):
        host = 10 + (i % 15)
        add(
            _ts(hscan_base, i * 0.5), "203.0.113.24", f"10.20.6.{host}",
            sport=rng.randint(1024, 65000), dport=22, proto="TCP", packets=1,
            b_out=54, b_in=0, duration_ms=0, flags="SYN", scenario="demo-scan-horizontal",
            label="port_scan_horizontal",
        )

    # ------------------------------------------------------------------
    # Scenario: C2 beaconing
    # ------------------------------------------------------------------
    beacon_base = now - timedelta(hours=3)
    for i in range(14):
        jitter = rng.uniform(-1.5, 1.5)
        add(
            _ts(beacon_base, i * 60 + jitter), "10.20.3.44", "192.0.2.90",
            sport=51000 + i % 3, dport=443, proto="TCP", packets=3,
            b_out=rng.randint(700, 1100), b_in=rng.randint(300, 600),
            duration_ms=rng.randint(600, 1200), flags="SYN+ACK+PSH", app="tls-ish",
            scenario="demo-beacon-c2", label="c2_beacon",
        )

    # ------------------------------------------------------------------
    # Scenario: low-and-slow beacon
    # ------------------------------------------------------------------
    slow_base = now - timedelta(hours=9)
    for i in range(9):
        add(
            _ts(slow_base, i * 300 + rng.uniform(-4, 4)), "10.20.3.45", "198.51.100.14",
            sport=52000 + i, dport=8443, proto="TCP", packets=4,
            b_out=rng.randint(900, 1500), b_in=rng.randint(400, 900),
            duration_ms=rng.randint(800, 2000), flags="SYN+ACK+PSH", app="tls-ish",
            scenario="demo-beacon-sleep", label="c2_beacon_slow",
        )

    # ------------------------------------------------------------------
    # Scenario: DGA burst
    # ------------------------------------------------------------------
    dga_base = now - timedelta(hours=8)
    seen: set[str] = set()
    for i in range(48):
        domain = _dga_domain(rng)
        while domain in seen:
            domain = _dga_domain(rng)
        seen.add(domain)
        add(
            _ts(dga_base, rng.uniform(0, 360)), "10.20.4.21", "192.0.2.145",
            sport=rng.randint(49152, 65000), dport=53, proto="UDP", packets=2,
            b_out=rng.randint(70, 120), b_in=rng.randint(90, 240),
            duration_ms=rng.randint(20, 120), app="dns", dns_query=domain,
            dns_qtype="A", dns_rcode="NXDOMAIN" if i % 3 else "NOERROR",
            scenario="demo-dns-dga", label="dga_domains",
        )

    # ------------------------------------------------------------------
    # Scenario: DNS tunnelling
    # ------------------------------------------------------------------
    tunnel_base = now - timedelta(hours=8, minutes=25)
    for i in range(32):
        add(
            _ts(tunnel_base, rng.uniform(0, 600)), "10.20.4.22", "192.0.2.145",
            sport=rng.randint(49152, 65000), dport=53, proto="UDP", packets=2,
            b_out=rng.randint(240, 420), b_in=rng.randint(300, 520),
            duration_ms=rng.randint(30, 160), app="dns", dns_query=_tunnel_domain(rng),
            dns_qtype=rng.choice(["TXT", "NULL"]), dns_rcode="NOERROR",
            scenario="demo-dns-tunnel", label="dns_tunnelling",
        )

    # ------------------------------------------------------------------
    # Scenario: secondary DGA burst (lower volume)
    # ------------------------------------------------------------------
    dga2_base = now - timedelta(hours=11)
    for i in range(20):
        add(
            _ts(dga2_base, rng.uniform(0, 300)), "10.20.4.23", "192.0.2.145",
            sport=rng.randint(49152, 65000), dport=53, proto="UDP", packets=2,
            b_out=rng.randint(70, 110), b_in=rng.randint(90, 200),
            duration_ms=rng.randint(20, 100), app="dns", dns_query=_dga_domain(rng),
            dns_qtype="A", dns_rcode="NOERROR",
            scenario="demo-dns-dga-2", label="dga_domains",
        )

    # ------------------------------------------------------------------
    # Scenario: unusual TLS metadata
    # ------------------------------------------------------------------
    tls_base = now - timedelta(hours=5)
    for i in range(7):
        add(
            _ts(tls_base, i * 210 + rng.uniform(0, 12)), "10.20.6.18", "198.51.100.77",
            sport=53000 + i, dport=8443, proto="TCP", packets=rng.randint(4, 8),
            b_out=rng.randint(1_400, 2_600), b_in=rng.randint(600, 1_400),
            duration_ms=rng.randint(20_000, 60_000), flags="SYN+ACK+PSH", app="tls",
            tls_sni=None, tls_ja3=RARE_JA3, tls_version="TLS1.3", tls_cipher="0x1301",
            scenario="demo-tls-rare", label="unusual_tls_metadata",
        )

    # ------------------------------------------------------------------
    # Scenario: bulk outbound transfer
    # ------------------------------------------------------------------
    exfil_base = now - timedelta(hours=1)
    for i in range(55):
        add(
            _ts(exfil_base, i * 22 + rng.uniform(0, 6)), "10.20.2.77", "192.0.2.64",
            sport=54000 + i, dport=443, proto="TCP", packets=rng.randint(3_000, 6_500),
            b_out=rng.randint(28_000_000, 42_000_000), b_in=rng.randint(2_000, 9_000),
            duration_ms=rng.randint(80_000, 190_000), flags="SYN+ACK+PSH", app="tls",
            tls_sni="backup.vendor.example", tls_ja3=COMMON_JA3,
            tls_version="TLS1.3", tls_cipher="0x1301", scenario="demo-exfil-bulk",
            label="bulk_outbound_transfer",
        )

    datasets = [
        {
            "scenario_id": "demo-ddos-syn",
            "name": "SYN flood — edge web tier",
            "threat_class": "Possible_DDoS",
            "description": "96 high-packet-rate TCP SYN flows toward 10.20.5.10 over 95 seconds.",
            "expected_features": ["packets_per_second", "syn_ack_ratio", "unique_source_addresses"],
            "ground_truth": {"threat": "ddos", "technique": "tcp_syn_flood", "labeled": True},
            "timespan": "95 seconds",
        },
        {
            "scenario_id": "demo-ddos-udp",
            "name": "UDP amplification signature — NTP",
            "threat_class": "Possible_DDoS",
            "description": "46 high-volume UDP flows to port 123 with a reflection-compatible profile.",
            "expected_features": ["bits_per_second", "udp_share", "destination_port"],
            "ground_truth": {"threat": "ddos", "technique": "udp_reflection_signature", "labeled": True},
            "timespan": "58 seconds",
        },
        {
            "scenario_id": "demo-scan-vertical",
            "name": "Vertical port scan",
            "threat_class": "Possible_Port_Scan",
            "description": "220 unique destination ports probed on a single host.",
            "expected_features": ["unique_destination_ports", "syn_without_ack_ratio"],
            "ground_truth": {"threat": "scanning", "technique": "vertical_port_scan", "labeled": True},
            "timespan": "40 seconds",
        },
        {
            "scenario_id": "demo-scan-horizontal",
            "name": "Horizontal SSH sweep",
            "threat_class": "Possible_Port_Scan",
            "description": "Fifteen hosts probed on port 22 from one external address.",
            "expected_features": ["unique_destination_hosts", "connection_attempts"],
            "ground_truth": {"threat": "scanning", "technique": "horizontal_host_sweep", "labeled": True},
            "timespan": "30 seconds",
        },
        {
            "scenario_id": "demo-beacon-c2",
            "name": "C2 beacon — 60 second cadence",
            "threat_class": "Possible_C2_Beaconing",
            "description": "Fourteen periodic connections with low timing variance.",
            "expected_features": ["observed_interval", "timing_variation_cv"],
            "ground_truth": {"threat": "beaconing", "technique": "periodic_callback", "labeled": True},
            "timespan": "14 minutes",
        },
        {
            "scenario_id": "demo-beacon-sleep",
            "name": "Low-and-slow beacon — 5 minute cadence",
            "threat_class": "Possible_C2_Beaconing",
            "description": "Nine callbacks at five-minute intervals with small jitter.",
            "expected_features": ["observed_interval", "repeated_connections"],
            "ground_truth": {"threat": "beaconing", "technique": "sleep_callback", "labeled": True},
            "timespan": "40 minutes",
        },
        {
            "scenario_id": "demo-dns-dga",
            "name": "DGA burst",
            "threat_class": "Possible_DGA_or_DNS_Tunnelling",
            "description": "48 unique high-entropy domains with a majority NXDOMAIN ratio.",
            "expected_features": ["mean_domain_entropy", "nxdomain_ratio"],
            "ground_truth": {"threat": "dga", "technique": "domain_generation_algorithm", "labeled": True},
            "timespan": "6 minutes",
        },
        {
            "scenario_id": "demo-dns-tunnel",
            "name": "DNS tunnelling",
            "threat_class": "Possible_DGA_or_DNS_Tunnelling",
            "description": "Long base32 labels carried over TXT queries to one domain.",
            "expected_features": ["max_query_label_length", "record_type_share"],
            "ground_truth": {"threat": "dns_tunnelling", "technique": "txt_record_tunnel", "labeled": True},
            "timespan": "10 minutes",
        },
        {
            "scenario_id": "demo-dns-dga-2",
            "name": "Low-volume DGA",
            "threat_class": "Possible_DGA_or_DNS_Tunnelling",
            "description": "Twenty generated domains in five minutes.",
            "expected_features": ["mean_domain_entropy", "queries_per_minute"],
            "ground_truth": {"threat": "dga", "technique": "domain_generation_algorithm", "labeled": True},
            "timespan": "5 minutes",
        },
        {
            "scenario_id": "demo-tls-rare",
            "name": "Rare TLS fingerprint",
            "threat_class": "Unusual_TLS_Metadata",
            "description": "Repeated sessions on a non-standard port without SNI using an uncommon JA3.",
            "expected_features": ["tls_ja3_fingerprint", "fingerprint_rarity", "sni_observed"],
            "ground_truth": {"threat": "tls_metadata_anomaly", "technique": "rare_client_fingerprint", "labeled": True},
            "timespan": "25 minutes",
        },
        {
            "scenario_id": "demo-exfil-bulk",
            "name": "Bulk outbound transfer",
            "threat_class": "Possible_Data_Exfiltration",
            "description": "1.9 GB outbound in 55 flows with a very high outbound/inbound ratio.",
            "expected_features": ["outbound_bytes", "outbound_inbound_ratio", "baseline_destination_volume"],
            "ground_truth": {"threat": "exfiltration", "technique": "bulk_https_transfer", "labeled": True},
            "timespan": "20 minutes",
        },
    ]

    return {"flows": flows, "datasets": datasets, "generated_at": now, "window_start": start}
