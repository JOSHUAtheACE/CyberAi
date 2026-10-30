from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import math
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    64: "SVCB", 65: "HTTPS", 255: "ANY",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A,
    0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def utc_from_epoch(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)


def parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1e14:  # nanoseconds
            number /= 1e9
        elif number > 1e11:  # milliseconds
            number /= 1e3
        try:
            return utc_from_epoch(number)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.isdigit():
        return parse_timestamp(int(text))
    try:
        cleaned = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("ts", "timestamp", "time", "first_seen", "datetime", "start_time", "@timestamp", "event_time"),
    "src_ip": ("src_ip", "source_ip", "src", "id.orig_h", "srcaddr", "client_ip", "ip_src", "src_addr"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "dst", "id.resp_h", "dstaddr", "server_ip", "ip_dst", "dst_addr"),
    "src_port": ("src_port", "source_port", "sport", "id.orig_p", "srcport", "client_port"),
    "dst_port": ("dst_port", "dest_port", "destination_port", "dport", "id.resp_p", "dstport", "server_port"),
    "protocol": ("protocol", "proto", "transport", "ip_proto"),
    "bytes_total": ("bytes", "bytes_total", "total_bytes", "octets", "total_bytes_fwd"),
    "bytes_out": ("bytes_out", "orig_bytes", "out_bytes", "client_bytes", "bytes_sent", "fwd_bytes"),
    "bytes_in": ("bytes_in", "resp_bytes", "in_bytes", "server_bytes", "bytes_received", "bwd_bytes"),
    "packets": ("packets", "pkts", "packets_total", "total_pkts"),
    "packets_out": ("orig_pkts", "packets_out"),
    "packets_in": ("resp_pkts", "packets_in"),
    "duration": ("duration", "duration_seconds", "duration_s", "flow_duration"),
    "duration_ms": ("duration_ms",),
    "tcp_flags": ("tcp_flags", "flags", "conn_state"),
    "dns_query": ("dns_query", "query", "qname", "dns_question"),
    "dns_qtype": ("dns_qtype", "qtype", "qtype_name"),
    "dns_rcode": ("dns_rcode", "rcode", "rcode_name"),
    "tls_sni": ("tls_sni", "sni", "server_name"),
    "tls_ja3": ("tls_ja3", "ja3", "ja3_hash"),
    "tls_version": ("tls_version", "tls_ver"),
    "tls_cipher": ("tls_cipher", "cipher", "cipher_suite"),
    "app_proto": ("app_proto", "service", "application", "app"),
    "scenario_id": ("scenario_id", "scenario"),
    "label": ("label", "ground_truth", "class"),
    "direction": ("direction", "flow_direction"),
}

REQUIRED_FIELDS = ("ts", "src_ip", "dst_ip")
DETECTOR_INPUTS = {
    "ddos": ["ts", "dst_ip", "protocol", "packets", "bytes_out", "tcp_flags", "src_ip"],
    "beaconing": ["ts", "src_ip", "dst_ip", "packets"],
    "dns": ["dns_query", "ts", "src_ip"],
    "encrypted": ["tls_ja3", "tls_sni", "tls_version", "tls_cipher", "app_proto", "duration", "bytes_total"],
    "scanning": ["dst_port", "dst_ip", "ts", "src_ip"],
    "exfiltration": ["bytes_out", "bytes_in", "duration", "ts", "dst_ip", "src_ip"],
}


@dataclass
class FlowIn:
    ts: datetime
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    app_proto: str | None = None
    bytes_total: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 0
    duration_ms: int = 0
    tcp_flags: str | None = None
    dns_query: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    tls_sni: str | None = None
    tls_ja3: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    quic: bool = False
    scenario_id: str | None = None
    label: str | None = None
    meta: dict = field(default_factory=dict)


def _first(row: dict, keys: tuple[str, ...]) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key in lowered and lowered[key] not in (None, ""):
            return lowered[key]
    return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        number = int(float(value))
        return number if number >= 0 else default
    except (TypeError, ValueError):
        return default


def normalize_row(row: dict, *, default_direction: str | None = None) -> tuple[FlowIn | None, str | None]:
    ts = parse_timestamp(_first(row, FIELD_ALIASES["ts"]))
    if ts is None:
        return None, "invalid_or_missing_timestamp"
    src_raw = _first(row, FIELD_ALIASES["src_ip"])
    dst_raw = _first(row, FIELD_ALIASES["dst_ip"])
    if not src_raw or not dst_raw:
        return None, "missing_source_or_destination"
    try:
        src_ip = str(ipaddress.ip_address(str(src_raw).strip()))
        dst_ip = str(ipaddress.ip_address(str(dst_raw).strip()))
    except ValueError:
        return None, "invalid_ip_address"
    src_port = _safe_int(_first(row, FIELD_ALIASES["src_port"]))
    dst_port = _safe_int(_first(row, FIELD_ALIASES["dst_port"]))
    if src_port > 65535 or dst_port > 65535:
        return None, "invalid_port"
    proto_raw = _first(row, FIELD_ALIASES["protocol"])
    proto = str(proto_raw or "TCP").strip().upper()
    proto = {"6": "TCP", "17": "UDP", "1": "ICMP", "IPV6-ICMP": "ICMP", "ICMPV6": "ICMP"}.get(proto, proto)
    if proto not in {"TCP", "UDP", "ICMP", "SCTP", "OTHER"}:
        proto = "OTHER"

    bytes_out = _safe_int(_first(row, FIELD_ALIASES["bytes_out"]))
    bytes_in = _safe_int(_first(row, FIELD_ALIASES["bytes_in"]))
    bytes_total = _safe_int(_first(row, FIELD_ALIASES["bytes_total"]))
    has_direction = bytes_out > 0 or bytes_in > 0
    if bytes_total == 0:
        bytes_total = bytes_out + bytes_in
    if bytes_total and not has_direction:
        bytes_in = bytes_total
        bytes_out = 0

    duration_ms = _safe_int(_first(row, FIELD_ALIASES["duration_ms"]))
    if duration_ms == 0:
        raw_duration = _first(row, FIELD_ALIASES["duration"])
        try:
            duration_ms = int(float(raw_duration) * 1000) if raw_duration is not None else 0
        except (TypeError, ValueError):
            duration_ms = 0

    packets = _safe_int(_first(row, FIELD_ALIASES["packets"]))
    if not packets:
        packets = _safe_int(_first(row, FIELD_ALIASES["packets_out"])) + _safe_int(
            _first(row, FIELD_ALIASES["packets_in"])
        )

    meta = {
        "has_direction": has_direction,
        "origin": "upload",
        "columns": sorted({str(k).strip().lower() for k in row.keys()})[:64],
    }
    if default_direction:
        meta["declared_direction"] = default_direction
    declared = _first(row, FIELD_ALIASES["direction"])
    if declared:
        meta["declared_direction"] = str(declared)

    return (
        FlowIn(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            app_proto=(str(_first(row, FIELD_ALIASES["app_proto"]) or "")[:32] or None),
            bytes_total=bytes_total,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            packets=packets,
            duration_ms=duration_ms,
            tcp_flags=(str(_first(row, FIELD_ALIASES["tcp_flags"]) or "")[:32] or None),
            dns_query=(str(_first(row, FIELD_ALIASES["dns_query"]) or "")[:255].lower().rstrip(".") or None),
            dns_qtype=(str(_first(row, FIELD_ALIASES["dns_qtype"]) or "")[:16] or None),
            dns_rcode=(str(_first(row, FIELD_ALIASES["dns_rcode"]) or "")[:16] or None),
            tls_sni=(str(_first(row, FIELD_ALIASES["tls_sni"]) or "")[:255] or None),
            tls_ja3=(str(_first(row, FIELD_ALIASES["tls_ja3"]) or "")[:64] or None),
            tls_version=(str(_first(row, FIELD_ALIASES["tls_version"]) or "")[:24] or None),
            tls_cipher=(str(_first(row, FIELD_ALIASES["tls_cipher"]) or "")[:64] or None),
            scenario_id=(str(_first(row, FIELD_ALIASES["scenario_id"]) or "")[:64] or None),
            label=(str(_first(row, FIELD_ALIASES["label"]) or "")[:48] or None),
            meta=meta,
        ),
        None,
    )


def _detect_mapping(columns: list[str]) -> dict[str, str | None]:
    lowered = {c.lower() for c in columns}
    mapping: dict[str, str | None] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        mapping[canonical] = next((a for a in aliases if a in lowered), None)
    return mapping


def _supported_modules(columns: list[str]) -> dict[str, bool]:
    lowered = {c.lower() for c in columns}
    result = {}
    for module, required in DETECTOR_INPUTS.items():
        present = []
        for field_name in required:
            aliases = FIELD_ALIASES.get(field_name, (field_name,))
            present.append(any(alias in lowered for alias in aliases))
        result[module] = len(present) >= max(2, math.ceil(len(required) * 0.5))
    return result


def parse_flow_records(
    filename: str,
    content: bytes,
    *,
    max_records: int = 500_000,
    preview_limit: int = 20,
) -> dict:
    """Parse CSV / JSON / JSONL / Zeek TSV flow exports into normalised flows."""
    name = filename.lower()
    text = content.decode("utf-8", errors="replace").lstrip("\ufeff")
    rows: list[dict] = []
    fmt = "csv"
    parse_notes: list[str] = []

    if name.endswith((".jsonl", ".ndjson")) or (name.endswith(".json") is False and _looks_like_jsonl(text)):
        fmt = "jsonl"
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    elif name.endswith(".json"):
        fmt = "json"
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, list):
            rows = [r for r in obj if isinstance(r, dict)]
        elif isinstance(obj, dict):
            for key in ("records", "flows", "data", "events"):
                if isinstance(obj.get(key), list):
                    rows = [r for r in obj[key] if isinstance(r, dict)]
                    break
            else:
                rows = [obj]
    else:
        rows, fmt = _parse_tabular(text, name)

    columns: list[str] = []
    for row in rows[:500]:
        for key in row.keys():
            if key not in columns:
                columns.append(str(key))

    flows: list[FlowIn] = []
    rejected = 0
    rejection_reasons: dict[str, int] = {}
    for row in rows[:max_records]:
        flow, error = normalize_row(row)
        if flow is None:
            rejected += 1
            rejection_reasons[error or "unknown"] = rejection_reasons.get(error or "unknown", 0) + 1
        else:
            flows.append(flow)

    if len(rows) > max_records:
        parse_notes.append(
            f"Record limit reached: only the first {max_records:,} of {len(rows):,} rows were processed."
        )

    supported = _supported_modules(columns)
    total = len(rows[:max_records])
    quality = {
        "total_rows": total,
        "valid_records": len(flows),
        "rejected_records": rejected,
        "rejection_reasons": rejection_reasons,
        "columns_detected": columns,
        "column_mapping": _detect_mapping(columns),
        "supported_modules": supported,
        "log_records": 0,
        "absence_report": _absence_report(flows),
        "notes": parse_notes,
        "direction_available": any(f.meta.get("has_direction") for f in flows[:1000]),
    }
    preview = [
        {
            "ts": f.ts.isoformat() + "Z",
            "src": f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip,
            "dst": f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip,
            "protocol": f.protocol,
            "bytes": f.bytes_total,
            "packets": f.packets,
            "dns_query": f.dns_query,
            "tls_sni": f.tls_sni,
        }
        for f in flows[:preview_limit]
    ]
    return {
        "format": fmt,
        "flows": flows,
        "quality": quality,
        "preview": preview,
        "record_count": len(flows),
        "timestamp_range": _timestamp_range(flows),
    }


def _looks_like_jsonl(text: str) -> bool:
    head = text.lstrip()[:200]
    if not head.startswith("{"):
        return False
    try:
        json.loads(head.splitlines()[0])
        return head.count("{") >= 1
    except json.JSONDecodeError:
        return False


def _parse_tabular(text: str, name: str) -> tuple[list[dict], str]:
    if name.endswith((".log", ".tsv")) and "#fields" in text[:4000]:
        return _parse_zeek(text), "zeek"
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    rows = [row for row in reader]
    fmt = "tsv" if getattr(dialect, "delimiter", ",") == "\t" else "csv"
    return rows, fmt


def _parse_zeek(text: str) -> list[dict]:
    separator = "\t"
    fields: list[str] = []
    rows: list[dict] = []
    for line in text.splitlines():
        if line.startswith("#separator"):
            raw = line.split(" ", 1)[1] if " " in line else "\\x09"
            separator = raw.encode().decode("unicode_escape")
        elif line.startswith("#fields"):
            fields = line.split(separator)[1:]
        elif line.startswith("#types"):
            continue
        elif line.startswith("#") or not line.strip():
            continue
        else:
            values = line.split(separator)
            if not fields:
                continue
            row = {field_name: values[i] for i, field_name in enumerate(fields) if i < len(values)}
            for placeholder in ("-", "(empty)"):
                for key, val in list(row.items()):
                    if val == placeholder:
                        row[key] = ""
            row["_zeek_log"] = True
            rows.append(row)
    return rows


def _absence_report(flows: list[FlowIn]) -> dict:
    sample = flows[:2000]
    if not sample:
        return {}
    return {
        "timestamps": all(f.ts for f in sample),
        "source_and_destination": True,
        "ports": any(f.dst_port for f in sample),
        "byte_counts": any(f.bytes_total for f in sample),
        "directional_bytes": any(f.meta.get("has_direction") for f in sample),
        "packets": any(f.packets for f in sample),
        "tcp_flags": any(f.tcp_flags for f in sample),
        "dns_names": any(f.dns_query for f in sample),
        "tls_metadata": any(f.tls_ja3 or f.tls_sni for f in sample),
        "durations": any(f.duration_ms for f in sample),
    }


def _timestamp_range(flows: list[FlowIn]) -> dict:
    if not flows:
        return {}
    timestamps = [f.ts for f in flows]
    return {"start": min(timestamps).isoformat() + "Z", "end": max(timestamps).isoformat() + "Z"}


# ---------------------------------------------------------------------------
# PCAP / PCAPNG parsing
# ---------------------------------------------------------------------------


@dataclass
class PcapResult:
    flows: list[FlowIn]
    packet_count: int
    byte_count: int
    capture_start: datetime | None
    capture_end: datetime | None
    link_types: list[int]
    notes: list[str]
    truncated: bool = False


class PcapError(ValueError):
    pass


def _parse_dns(payload: bytes) -> dict:
    if len(payload) < 12:
        return {}
    try:
        flags, qdcount = struct.unpack("!HH", payload[2:6])
        labels: list[str] = []
        offset = 12
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                break
            label = payload[offset + 1 : offset + 1 + length].decode("ascii", errors="ignore")
            labels.append(label)
            offset += 1 + length
            if len(labels) > 20:
                break
        qtype = 0
        if offset + 4 <= len(payload):
            qtype = struct.unpack("!H", payload[offset : offset + 2])[0]
        if not labels or qdcount == 0:
            return {}
        return {
            "dns_query": ".".join(labels)[:255].lower(),
            "dns_qtype": DNS_QTYPES.get(qtype, str(qtype)),
            "dns_rcode": DNS_RCODES.get(flags & 0xF, str(flags & 0xF)),
        }
    except Exception:
        return {}


def _parse_tls_client_hello(payload: bytes) -> dict:
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return {}
        handshake = payload[5:]
        if len(handshake) < 4 or handshake[0] != 0x01:
            return {}
        hs_len = int.from_bytes(handshake[1:4], "big")
        body = handshake[4 : 4 + hs_len]
        if len(body) < 38:
            return {}
        client_version = int.from_bytes(body[0:2], "big")
        pos = 2 + 32
        session_len = body[pos]
        pos += 1 + session_len
        if pos + 2 > len(body):
            return {}
        cipher_len = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        ciphers = [
            int.from_bytes(body[i : i + 2], "big")
            for i in range(pos, min(pos + cipher_len, len(body) - 1), 2)
        ]
        pos += cipher_len
        if pos >= len(body):
            return {}
        comp_len = body[pos]
        pos += 1 + comp_len

        ext_ids: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        sni = None
        negotiated_version = None
        while pos + 4 <= len(body):
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
            ext_data = body[pos + 4 : pos + 4 + ext_len]
            ext_ids.append(ext_type)
            if ext_type == 0 and len(ext_data) >= 5:  # server_name
                list_len = int.from_bytes(ext_data[0:2], "big")
                if len(ext_data) >= 5:
                    name_len = int.from_bytes(ext_data[3:5], "big")
                    sni = ext_data[5 : 5 + name_len].decode("ascii", errors="ignore").lower()
            elif ext_type == 10 and len(ext_data) >= 2:  # supported groups
                group_len = int.from_bytes(ext_data[0:2], "big")
                curves = [
                    int.from_bytes(ext_data[i : i + 2], "big")
                    for i in range(2, min(2 + group_len, len(ext_data) - 1), 2)
                ]
            elif ext_type == 11 and len(ext_data) >= 1:  # ec point formats
                formats_len = ext_data[0]
                point_formats = list(ext_data[1 : 1 + formats_len])
            elif ext_type == 43 and len(ext_data) >= 2:  # supported_versions
                versions = [
                    int.from_bytes(ext_data[i : i + 2], "big")
                    for i in range(1, len(ext_data) - 1, 2)
                ]
                if versions:
                    negotiated_version = max(versions)
            pos += 4 + ext_len

        clean_ciphers = [c for c in ciphers if c not in GREASE]
        clean_ext = [e for e in ext_ids if e not in GREASE]
        clean_curves = [c for c in curves if c not in GREASE]
        version_used = negotiated_version or client_version
        ja3_string = "{},{},{},{},{}".format(
            version_used,
            "-".join(str(c) for c in clean_ciphers),
            "-".join(str(e) for e in clean_ext),
            "-".join(str(c) for c in clean_curves),
            "-".join(str(p) for p in point_formats),
        )
        ja3 = hashlib.md5(ja3_string.encode()).hexdigest()
        version_label = {
            0x0304: "TLS1.3",
            0x0303: "TLS1.2",
            0x0302: "TLS1.1",
            0x0301: "TLS1.0",
        }.get(version_used, f"0x{version_used:04x}")
        return {
            "tls_sni": (sni or "")[:255] or None,
            "tls_ja3": ja3,
            "tls_version": version_label,
            "tls_cipher": f"0x{clean_ciphers[0]:04x}" if clean_ciphers else None,
            "tls_ja3_string": ja3_string,
        }
    except Exception:
        return {}


class FlowAccumulator:
    """Aggregates parsed packets into bidirectional 5-tuple flow records."""

    def __init__(self, max_flows: int = 250_000) -> None:
        self.flows: dict[tuple, dict] = {}
        self.max_flows = max_flows
        self.truncated = False

    def add(
        self,
        *,
        ts: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        size: int,
        flags: int | None = None,
        payload: bytes = b"",
    ) -> None:
        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
            forward = True
        else:
            key = (dst_ip, dst_port, src_ip, src_port, protocol)
            forward = False
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.truncated = True
                return
            flow = {
                "first": ts,
                "last": ts,
                "src_ip": key[0],
                "src_port": key[1],
                "dst_ip": key[2],
                "dst_port": key[3],
                "protocol": protocol,
                "packets_out": 0,
                "packets_in": 0,
                "bytes_out": 0,
                "bytes_in": 0,
                "flags": 0,
                "app": None,
                "dns": {},
                "tls": {},
                "sizes": [],
                "times": [],
            }
            self.flows[key] = flow
        flow["last"] = max(flow["last"], ts)
        if forward:
            flow["bytes_out"] += size
            flow["packets_out"] += 1
        else:
            flow["bytes_in"] += size
            flow["packets_in"] += 1
        if flags is not None:
            flow["flags"] |= flags
        if len(flow["sizes"]) < 80:
            flow["sizes"].append(size)
            flow["times"].append(round(ts - flow["first"], 6))

        if payload and len(payload) > 5:
            if (src_port == 53 or dst_port == 53) and not flow["dns"]:
                parsed = _parse_dns(payload)
                if parsed:
                    flow["dns"] = parsed
                    flow["app"] = "dns"
            elif payload[0] == 0x16 and (dst_port == 443 or src_port == 443 or dst_port not in (53, 80)) and not flow["tls"]:
                parsed = _parse_tls_client_hello(payload)
                if parsed:
                    flow["tls"] = parsed
                    flow["app"] = parsed.get("tls_sni") and "tls" or "tls"
            elif dst_port in (80, 8080) and payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                flow["app"] = flow["app"] or "http"
            elif dst_port == 443 and len(payload) >= 2 and payload[0] & 0x80 and (payload[0] & 0x40):
                flow["app"] = "quic_udp443"

    def results(self, link_notes: list[str]) -> list[FlowIn]:
        out: list[FlowIn] = []
        for flow in self.flows.values():
            tls = flow["tls"] or {}
            dns = flow["dns"] or {}
            flags = flow["flags"]
            flag_text = "+".join(
                name for bit, name in (
                    (0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"),
                    (0x08, "PSH"), (0x20, "URG"),
                ) if flags & bit
            )
            meta: dict = {
                "has_direction": True,
                "origin": "pcap",
                "packet_sizes": flow["sizes"],
                "packet_times": flow["times"],
            }
            if tls.get("tls_ja3_string"):
                meta["ja3_string"] = tls["tls_ja3_string"]
            if flow["app"] == "quic_udp443":
                meta["app_note"] = "UDP/443 observed; QUIC handshake metadata is not decrypted."
            out.append(
                FlowIn(
                    ts=utc_from_epoch(flow["first"]),
                    src_ip=flow["src_ip"],
                    dst_ip=flow["dst_ip"],
                    src_port=flow["src_port"],
                    dst_port=flow["dst_port"],
                    protocol=flow["protocol"],
                    app_proto=flow["app"],
                    bytes_total=flow["bytes_out"] + flow["bytes_in"],
                    bytes_out=flow["bytes_out"],
                    bytes_in=flow["bytes_in"],
                    packets=flow["packets_out"] + flow["packets_in"],
                    duration_ms=int(round((flow["last"] - flow["first"]) * 1000)),
                    tcp_flags=flag_text or None,
                    dns_query=dns.get("dns_query"),
                    dns_qtype=dns.get("dns_qtype"),
                    dns_rcode=dns.get("dns_rcode"),
                    tls_sni=tls.get("tls_sni"),
                    tls_ja3=tls.get("tls_ja3"),
                    tls_version=tls.get("tls_version"),
                    tls_cipher=tls.get("tls_cipher"),
                    quic=flow["app"] == "quic_udp443",
                    meta=meta,
                )
            )
        return out


def _ip_packet(
    data: bytes, offset: int, ts: float, accumulator: FlowAccumulator, link_note: list[str]
) -> None:
    if len(data) < offset + 1:
        return
    version = data[offset] >> 4
    if version == 4:
        if len(data) < offset + 20:
            return
        ihl = (data[offset] & 0x0F) * 4
        if ihl < 20 or len(data) < offset + ihl:
            return
        frag = struct.unpack("!H", data[offset + 6 : offset + 8])[0]
        if frag & 0x1FFF:
            return  # non-first fragment, no transport header
        proto = data[offset + 9]
        total_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        src = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
        dst = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
        transport = data[offset + ihl : offset + total_len] if total_len else data[offset + ihl :]
    elif version == 6:
        if len(data) < offset + 40:
            return
        next_header = data[offset + 6]
        payload_len = struct.unpack("!H", data[offset + 4 : offset + 6])[0]
        src = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
        dst = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
        transport = data[offset + 40 : offset + 40 + payload_len]
        proto = next_header
        guard = 0
        while proto in (0, 43, 44, 60) and len(transport) >= 8 and guard < 8:
            proto = transport[0]
            ext_len = (transport[1] + 1) * 8 if proto != 44 else 8
            transport = transport[ext_len:]
            guard += 1
    else:
        return

    if proto == 6 and len(transport) >= 20:
        src_port, dst_port = struct.unpack("!HH", transport[0:4])
        data_offset = (transport[12] >> 4) * 4
        flags = transport[13]
        payload = transport[data_offset:] if data_offset >= 20 else b""
        accumulator.add(
            ts=ts, src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port,
            protocol="TCP", size=len(data), flags=flags, payload=payload,
        )
    elif proto == 17 and len(transport) >= 8:
        src_port, dst_port = struct.unpack("!HH", transport[0:4])
        length = struct.unpack("!H", transport[4:6])[0]
        payload = transport[8 : max(8, length)] if length >= 8 else transport[8:]
        accumulator.add(
            ts=ts, src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port,
            protocol="UDP", size=len(data), payload=payload,
        )
    elif proto == 1:
        accumulator.add(
            ts=ts, src_ip=src, dst_ip=dst, src_port=0, dst_port=0,
            protocol="ICMP", size=len(data),
        )


def _link_packet(
    data: bytes, link_type: int, ts: float, accumulator: FlowAccumulator, notes: list[str]
) -> None:
    if link_type == 1:  # Ethernet
        if len(data) < 14:
            return
        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14
        guard = 0
        while ether_type in (0x8100, 0x88A8, 0x9100) and len(data) >= offset + 4 and guard < 3:
            ether_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
            guard += 1
        if ether_type in (0x0800, 0x86DD):
            _ip_packet(data, offset, ts, accumulator, notes)
    elif link_type == 113:  # Linux cooked capture
        if len(data) < 16:
            return
        _ip_packet(data, 16, ts, accumulator, notes)
    elif link_type in (101, 12, 228, 229):  # raw IP
        _ip_packet(data, 0, ts, accumulator, notes)
    else:
        if "unsupported_link_type" not in notes:
            notes.append("unsupported_link_type")


def parse_pcap(content: bytes, *, max_packets: int = 2_000_000) -> PcapResult:
    if len(content) < 24:
        raise PcapError("File is too small to be a capture.")
    magic = content[:4]
    flows = FlowAccumulator()
    notes: list[str] = []
    link_types: set[int] = set()
    first_ts: float | None = None
    last_ts: float | None = None
    packet_count = 0
    byte_count = len(content)

    if magic == b"\x0a\x0d\x0d\x0a":
        # pcapng
        offset = 0
        endian = "<"
        interfaces: list[dict] = []
        while offset + 12 <= len(content):
            block_type = struct.unpack(endian + "I", content[offset : offset + 4])[0]
            if block_type == 0x0A0D0D0A:
                bom = content[offset + 8 : offset + 12]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                block_type = struct.unpack(endian + "I", content[offset : offset + 4])[0]
            if block_type == 0x0A0D0D0A:
                block_len = struct.unpack(endian + "I", content[offset + 4 : offset + 8])[0]
                interfaces = []
            else:
                block_len = struct.unpack(endian + "I", content[offset + 4 : offset + 8])[0]
            if block_len < 12 or offset + block_len > len(content):
                notes.append("truncated_block")
                break
            if block_type == 1:  # IDB
                link_type = struct.unpack(endian + "H", content[offset + 8 : offset + 10])[0]
                interfaces.append({"link": link_type})
                link_types.add(link_type)
            elif block_type == 6:  # Enhanced Packet Block
                iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(
                    endian + "IIIII", content[offset + 8 : offset + 28]
                )
                if iface_id < len(interfaces):
                    ts = (ts_high << 32 | ts_low) / 1_000_000
                    pkt = content[offset + 28 : offset + 28 + cap_len]
                    _link_packet(pkt, interfaces[iface_id]["link"], ts, flows, notes)
                    packet_count += 1
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
            elif block_type == 3:  # Simple Packet Block
                orig_len = struct.unpack(endian + "I", content[offset + 8 : offset + 12])[0]
                if interfaces:
                    cap_len = block_len - 16
                    pkt = content[offset + 12 : offset + 12 + cap_len]
                    _link_packet(pkt, interfaces[0]["link"], 0.0, flows, notes)
                    packet_count += 1
                notes.append("simple_packet_block_without_timestamp")
            elif block_type == 2:  # obsolete packet block
                iface_id, _drops, ts_high, ts_low, cap_len, _orig = struct.unpack(
                    endian + "HHIIII", content[offset + 8 : offset + 28]
                )
                if iface_id < len(interfaces):
                    ts = (ts_high << 32 | ts_low) / 1_000_000
                    pkt = content[offset + 28 : offset + 28 + cap_len]
                    _link_packet(pkt, interfaces[iface_id]["link"], ts, flows, notes)
                    packet_count += 1
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
            offset += block_len
        if packet_count == 0 and "unsupported_link_type" not in notes:
            notes.append("no_supported_packets")
    else:
        endian = "<"
        nano = False
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise PcapError("Unrecognised capture format. Expected pcap or pcapng.")
        _, _, _, _, _, snaplen, link_type = struct.unpack(endian + "IHHiIII", content[:24])
        link_types.add(link_type)
        offset = 24
        while offset + 16 <= len(content) and packet_count < max_packets:
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                endian + "IIII", content[offset : offset + 16]
            )
            offset += 16
            if incl_len > len(content) - offset:
                notes.append("truncated_packet")
                break
            ts = ts_sec + ts_frac / (1_000_000_000 if nano else 1_000_000)
            _link_packet(content[offset : offset + incl_len], link_type, ts, flows, notes)
            offset += incl_len
            packet_count += 1
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        if not link_type:
            notes.append("unknown_link_type")

    if packet_count >= max_packets:
        notes.append(f"packet_limit_reached:{max_packets}")
    if flows.truncated:
        notes.append("flow_cardinality_limit_reached")
    return PcapResult(
        flows=flows.results(notes),
        packet_count=packet_count,
        byte_count=byte_count,
        capture_start=utc_from_epoch(first_ts) if first_ts else None,
        capture_end=utc_from_epoch(last_ts) if last_ts else None,
        link_types=sorted(link_types),
        notes=notes,
        truncated=flows.truncated,
    )
