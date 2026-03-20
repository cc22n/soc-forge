"""
Transform functions for normalizing API response data.

These are referenced by AvailableField.transform_function and called
during response parsing to normalize values across different APIs.
"""

from datetime import datetime, timezone


def transform_vt_detection_ratio(stats: dict) -> str:
    """VirusTotal: Convert last_analysis_stats to 'malicious/total' ratio string."""
    if not isinstance(stats, dict):
        return None
    malicious = stats.get("malicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "undetected", "suspicious", "harmless", "timeout", "failure"))
    if total == 0:
        return None
    return f"{malicious}/{total}"


def transform_epoch_to_iso(epoch) -> str:
    """Convert Unix epoch timestamp to ISO 8601 string."""
    if epoch is None:
        return None
    try:
        epoch = int(epoch)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(epoch)


def transform_safebrowsing_verdict(matches) -> str:
    """Google Safe Browsing: matches exist → malicious, else clean."""
    if matches:
        return "malicious"
    return "clean"


def transform_shodan_services(data: list) -> list:
    """Shodan: Extract service summaries from banner data."""
    if not isinstance(data, list):
        return None
    services = []
    for entry in data[:20]:  # Limit to 20 services
        svc = {
            "port": entry.get("port"),
            "transport": entry.get("transport"),
            "product": entry.get("product", ""),
            "version": entry.get("version", ""),
        }
        services.append(svc)
    return services


def transform_ipinfo_asn(org_string: str) -> str:
    """ipinfo.io: Extract ASN from org string like 'AS13335 Cloudflare, Inc.'."""
    if not org_string:
        return None
    parts = org_string.split(" ", 1)
    if parts and parts[0].startswith("AS"):
        return parts[0]
    return org_string


def transform_ipinfo_loc_lat(loc: str) -> float:
    """ipinfo.io: Extract latitude from 'lat,lng' string."""
    if not loc or "," not in loc:
        return None
    try:
        return float(loc.split(",")[0])
    except (ValueError, IndexError):
        return None


def transform_ipinfo_loc_lng(loc: str) -> float:
    """ipinfo.io: Extract longitude from 'lat,lng' string."""
    if not loc or "," not in loc:
        return None
    try:
        return float(loc.split(",")[1])
    except (ValueError, IndexError):
        return None


# Registry of all transform functions by name
TRANSFORMS = {
    "transform_vt_detection_ratio": transform_vt_detection_ratio,
    "transform_epoch_to_iso": transform_epoch_to_iso,
    "transform_safebrowsing_verdict": transform_safebrowsing_verdict,
    "transform_shodan_services": transform_shodan_services,
    "transform_ipinfo_asn": transform_ipinfo_asn,
    "transform_ipinfo_loc_lat": transform_ipinfo_loc_lat,
    "transform_ipinfo_loc_lng": transform_ipinfo_loc_lng,
}


def apply_transform(transform_name: str, value):
    """Apply a named transform function to a value."""
    if not transform_name:
        return value
    fn = TRANSFORMS.get(transform_name)
    if fn is None:
        return value
    try:
        return fn(value)
    except Exception:
        return value
