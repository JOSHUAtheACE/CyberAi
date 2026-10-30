from __future__ import annotations

import ipaddress
from functools import lru_cache

from .config import MAXMIND_DB_PATH

try:  # optional dependency, only required for real GeoIP enrichment
    import maxminddb  # type: ignore
except Exception:  # pragma: no cover
    maxminddb = None


# Synthetic demo topology. Coordinates are configured demo metadata, NOT IP-derived
# geolocation. All addresses use reserved documentation ranges.
DEMO_SITES: dict[str, dict] = {
    "203.0.113.10": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    "203.0.113.24": {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
    "203.0.113.51": {"city": "London", "country": "GB", "lat": 51.5072, "lon": -0.1276},
    "198.51.100.14": {"city": "Ashburn", "country": "US", "lat": 39.0438, "lon": -77.4874},
    "198.51.100.77": {"city": "San Jose", "country": "US", "lat": 37.3382, "lon": -121.8863},
    "198.51.100.201": {"city": "Sao Paulo", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    "192.0.2.33": {"city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    "192.0.2.64": {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    "192.0.2.90": {"city": "Mumbai", "country": "IN", "lat": 19.076, "lon": 72.8777},
    "192.0.2.145": {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    "192.0.2.210": {"city": "Dubai", "country": "AE", "lat": 25.2048, "lon": 55.2708},
}

# Demo workspace "configured asset metadata" for internal subnets. These are
# administrative demo labels, not IP-derived geolocation.
DEMO_ASSET_LOCATIONS = [
    {"cidr": "10.20.1.0/24", "city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    {"cidr": "10.20.2.0/24", "city": "Ashburn", "country": "US", "lat": 39.0438, "lon": -77.4874},
    {"cidr": "10.20.3.0/24", "city": "London", "country": "GB", "lat": 51.5072, "lon": -0.1276},
    {"cidr": "10.20.4.0/24", "city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    {"cidr": "10.20.5.0/24", "city": "Amsterdam", "country": "NL", "lat": 52.3676, "lon": 4.9041},
    {"cidr": "10.20.6.0/24", "city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
]


def _demo_asset_location(ip: str) -> dict | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for site in DEMO_ASSET_LOCATIONS:
        if address in ipaddress.ip_network(site["cidr"], strict=False):
            return {
                "country": site["country"],
                "city": site["city"],
                "lat": site["lat"],
                "lon": site["lon"],
                "geo_source": "demo_configured_asset",
            }
    return None


_GEO_READER = None
if maxminddb is not None and MAXMIND_DB_PATH:
    try:  # pragma: no cover - depends on deployment artefacts
        _GEO_READER = maxminddb.open_database(MAXMIND_DB_PATH)
    except Exception:
        _GEO_READER = None


def geo_status() -> dict:
    return {
        "provider": "MaxMind GeoLite2",
        "configured": _GEO_READER is not None,
        "database_path": MAXMIND_DB_PATH or None,
        "accuracy_notice": (
            "IP geolocation approximates network registration, not the physical location "
            "of a device or person. Private and reserved addresses are never assigned "
            "invented coordinates."
        ),
    }


def parse_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_reserved)


def is_internal(value: str, cidrs: list[str]) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    for cidr in cidrs or []:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def classify_direction(src: str, dst: str, cidrs: list[str]) -> str:
    src_internal = is_internal(src, cidrs)
    dst_internal = is_internal(dst, cidrs)
    if src_internal and dst_internal:
        return "internal"
    if src_internal and not dst_internal:
        return "outbound"
    if dst_internal and not src_internal:
        return "inbound"
    return "transit"


def lookup_geo(ip: str, *, demo: bool = False) -> dict:
    """Return geo metadata with an explicit source label."""
    if demo:
        site = DEMO_SITES.get(ip)
        if site:
            return {
                "country": site["country"],
                "city": site["city"],
                "lat": site["lat"],
                "lon": site["lon"],
                "geo_source": "demo_synthetic",
            }
        asset = _demo_asset_location(ip)
        if asset:
            return asset
        return {}
    if not is_public_ip(ip):
        return {}
    if _GEO_READER is not None:  # pragma: no cover
        try:
            record = _GEO_READER.get(ip)
            if record:
                city = record.get("city", {}) or {}
                return {
                    "country": (record.get("country", {}) or {}).get("iso_code"),
                    "city": city.get("names", {}).get("en"),
                    "lat": (record.get("location", {}) or {}).get("latitude"),
                    "lon": (record.get("location", {}) or {}).get("longitude"),
                    "geo_source": "maxmind_geolite2",
                }
        except Exception:
            return {}
    return {}


@lru_cache(maxsize=1)
def demo_sites_payload() -> list[dict]:
    return [
        {"ip": ip, **site, "label": "synthetic demo site"}
        for ip, site in DEMO_SITES.items()
    ]
