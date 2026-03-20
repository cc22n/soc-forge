"""
Seed the database with all 17 threat intelligence sources and their available fields.

Usage:
    python manage.py seed_sources          # Create sources (skip existing)
    python manage.py seed_sources --reset  # Delete all and recreate
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.sources.models import AvailableField, Source


def _f(ioc, name, path, cls, dtype="str", transform="", desc=""):
    """Shorthand field builder."""
    return {
        "ioc_type": ioc, "normalized_name": name, "api_field_path": path,
        "classification": cls, "data_type": dtype,
        "transform_function": transform, "description": desc,
    }


# ============================================================================
# 1. VirusTotal
# ============================================================================
VT = {
    "name": "VirusTotal", "slug": "virustotal",
    "base_url": "https://www.virustotal.com/api/v3",
    "auth_type": "header", "env_var_name": "VIRUSTOTAL_API_KEY",
    "supported_ioc_types": ["hash", "ip", "domain", "url"],
    "rate_limit_per_minute": 4, "default_ttl_seconds": 86400, "priority": 1,
    "description": "Multi-engine AV scanner. 70+ engines for hashes, IPs, domains, URLs.",
    "fields": [
        # HASH
        _f("hash_sha256", "detection_ratio", "last_analysis_stats", "required", transform="transform_vt_detection_ratio"),
        _f("hash_sha256", "malware_family", "popular_threat_classification.suggested_threat_label", "required"),
        _f("hash_sha256", "threat_label", "popular_threat_classification.popular_threat_name", "required"),
        _f("hash_sha256", "file_type", "type_description", "core"),
        _f("hash_sha256", "file_size", "size", "optional", "int"),
        _f("hash_sha256", "file_name", "meaningful_name", "core"),
        _f("hash_sha256", "first_seen", "first_submission_date", "core", transform="transform_epoch_to_iso"),
        _f("hash_sha256", "last_seen", "last_analysis_date", "core", transform="transform_epoch_to_iso"),
        _f("hash_sha256", "tags", "tags", "optional", "list"),
        _f("hash_sha256", "sandbox_verdicts", "sandbox_verdicts", "optional", "dict"),
        _f("hash_sha256", "yara_rules", "crowdsourced_yara_results", "optional", "list"),
        _f("hash_sha256", "related_ips", "relationships.contacted_ips", "optional", "list"),
        _f("hash_sha256", "related_domains", "relationships.contacted_domains", "optional", "list"),
        # IP
        _f("ip", "detection_ratio", "last_analysis_stats", "required", transform="transform_vt_detection_ratio"),
        _f("ip", "country", "country", "core"),
        _f("ip", "asn", "asn", "core"),
        _f("ip", "as_owner", "as_owner", "core"),
        _f("ip", "last_seen", "last_analysis_date", "core", transform="transform_epoch_to_iso"),
        _f("ip", "tags", "tags", "optional", "list"),
        # DOMAIN
        _f("domain", "detection_ratio", "last_analysis_stats", "required", transform="transform_vt_detection_ratio"),
        _f("domain", "whois_creation_date", "creation_date", "core", transform="transform_epoch_to_iso"),
        _f("domain", "whois_registrar", "registrar", "core"),
        _f("domain", "dns_records", "last_dns_records", "core", "list"),
        _f("domain", "categories", "categories", "core", "dict"),
        _f("domain", "popularity_rank", "popularity_ranks", "optional", "dict"),
        _f("domain", "last_seen", "last_analysis_date", "core", transform="transform_epoch_to_iso"),
        # URL
        _f("url", "detection_ratio", "last_analysis_stats", "required", transform="transform_vt_detection_ratio"),
        _f("url", "final_url", "last_final_url", "core"),
        _f("url", "http_status", "last_http_response_code", "core", "int"),
        _f("url", "page_title", "title", "optional"),
        _f("url", "first_seen", "first_submission_date", "core", transform="transform_epoch_to_iso"),
        _f("url", "last_seen", "last_analysis_date", "core", transform="transform_epoch_to_iso"),
    ],
}

# ============================================================================
# 2. AbuseIPDB
# ============================================================================
ABUSEIPDB = {
    "name": "AbuseIPDB", "slug": "abuseipdb",
    "base_url": "https://api.abuseipdb.com/api/v2",
    "auth_type": "header", "env_var_name": "ABUSEIPDB_API_KEY",
    "supported_ioc_types": ["ip"],
    "rate_limit_per_minute": 17, "default_ttl_seconds": 43200, "priority": 2,
    "description": "Community-driven IP abuse reporting with confidence scoring.",
    "fields": [
        _f("ip", "abuse_confidence", "data.abuseConfidenceScore", "required", "int"),
        _f("ip", "country_code", "data.countryCode", "core"),
        _f("ip", "country", "data.countryName", "core"),
        _f("ip", "isp", "data.isp", "core"),
        _f("ip", "usage_type", "data.usageType", "optional"),
        _f("ip", "domains", "data.domain", "core"),
        _f("ip", "hostnames", "data.hostnames", "core", "list"),
        _f("ip", "is_tor", "data.isTor", "core", "bool"),
        _f("ip", "total_reports", "data.totalReports", "core", "int"),
        _f("ip", "last_reported", "data.lastReportedAt", "core"),
        _f("ip", "is_whitelisted", "data.isWhitelisted", "optional", "bool"),
    ],
}

# ============================================================================
# 3. Shodan
# ============================================================================
SHODAN = {
    "name": "Shodan", "slug": "shodan",
    "base_url": "https://api.shodan.io",
    "auth_type": "query_param", "env_var_name": "SHODAN_API_KEY",
    "supported_ioc_types": ["ip"],
    "rate_limit_per_minute": 1, "default_ttl_seconds": 604800, "priority": 3,
    "description": "Internet-wide scanner for open ports, services, and vulnerabilities.",
    "fields": [
        _f("ip", "open_ports", "ports", "required", "list"),
        _f("ip", "vulns", "vulns", "required", "list"),
        _f("ip", "country", "country_name", "core"),
        _f("ip", "country_code", "country_code", "core"),
        _f("ip", "city", "city", "optional"),
        _f("ip", "asn", "asn", "core"),
        _f("ip", "org", "org", "core"),
        _f("ip", "isp", "isp", "core"),
        _f("ip", "os", "os", "optional"),
        _f("ip", "hostnames", "hostnames", "core", "list"),
        _f("ip", "domains", "domains", "core", "list"),
        _f("ip", "last_seen", "last_update", "core"),
        _f("ip", "services", "data", "optional", "list", transform="transform_shodan_services"),
        _f("ip", "tags", "tags", "optional", "list"),
        _f("ip", "latitude", "latitude", "optional", "float"),
        _f("ip", "longitude", "longitude", "optional", "float"),
    ],
}

# ============================================================================
# 4. AlienVault OTX
# ============================================================================
OTX = {
    "name": "AlienVault OTX", "slug": "otx",
    "base_url": "https://otx.alienvault.com/api/v1",
    "auth_type": "header", "env_var_name": "OTX_API_KEY",
    "supported_ioc_types": ["hash", "ip", "domain", "url"],
    "rate_limit_per_minute": 167, "default_ttl_seconds": 86400, "priority": 5,
    "description": "Open Threat Exchange. Community-driven pulse-based IOC sharing.",
    "fields": [
        # HASH
        _f("hash_sha256", "malware_family", "pulse_info.pulses[].tags", "core", "list"),
        _f("hash_sha256", "confidence_score", "pulse_info.count", "core", "int"),
        _f("hash_sha256", "tags", "pulse_info.pulses[].tags", "optional", "list"),
        _f("hash_sha256", "file_type", "type_title", "core"),
        # IP
        _f("ip", "country", "country_name", "core"),
        _f("ip", "country_code", "country_code", "core"),
        _f("ip", "asn", "asn", "core"),
        _f("ip", "confidence_score", "pulse_info.count", "core", "int"),
        _f("ip", "tags", "pulse_info.pulses[].tags", "optional", "list"),
        # DOMAIN
        _f("domain", "confidence_score", "pulse_info.count", "core", "int"),
        _f("domain", "whois_registrar", "whois.registrar", "core"),
        _f("domain", "dns_records", "passive_dns", "core", "list"),
        _f("domain", "resolved_ips", "passive_dns[].address", "core", "list"),
        _f("domain", "tags", "pulse_info.pulses[].tags", "optional", "list"),
        # URL
        _f("url", "confidence_score", "pulse_info.count", "core", "int"),
        _f("url", "tags", "pulse_info.pulses[].tags", "optional", "list"),
        _f("url", "hosting_ip", "url_list.result.urlworker.ip", "core"),
        _f("url", "http_status", "url_list.result.httpcode", "core", "int"),
    ],
}

# ============================================================================
# 5. GreyNoise
# ============================================================================
GREYNOISE = {
    "name": "GreyNoise", "slug": "greynoise",
    "base_url": "https://api.greynoise.io/v3",
    "auth_type": "header", "env_var_name": "GREYNOISE_API_KEY",
    "supported_ioc_types": ["ip"],
    "rate_limit_per_minute": 1, "default_ttl_seconds": 86400, "priority": 4,
    "description": "Internet noise analyzer. Identifies mass scanners and known benign services (RIOT).",
    "fields": [
        _f("ip", "classification", "classification", "required"),
        _f("ip", "is_noise", "noise", "required", "bool"),
        _f("ip", "is_riot", "riot", "core", "bool"),
        _f("ip", "org", "name", "core"),
        _f("ip", "last_seen", "last_seen", "core"),
        _f("ip", "first_seen", "first_seen", "core"),
        _f("ip", "tags", "tags[].name", "optional", "list"),
        _f("ip", "country", "metadata.source_country", "core"),
        _f("ip", "asn", "metadata.asn", "core"),
        _f("ip", "is_tor", "metadata.tor", "core", "bool"),
        _f("ip", "is_vpn", "vpn", "core", "bool"),
        _f("ip", "os", "metadata.os", "optional"),
    ],
}

# ============================================================================
# 6. Google Safe Browsing
# ============================================================================
SAFEBROWSING = {
    "name": "Google Safe Browsing", "slug": "google_safebrowsing",
    "base_url": "https://safebrowsing.googleapis.com/v4",
    "auth_type": "query_param", "env_var_name": "GOOGLE_SAFEBROWSING_API_KEY",
    "supported_ioc_types": ["url", "domain"],
    "rate_limit_per_minute": 167, "default_ttl_seconds": 21600, "priority": 6,
    "description": "Google threat detection for URLs and domains.",
    "fields": [
        _f("url", "classification", "matches", "required", transform="transform_safebrowsing_verdict"),
        _f("url", "threat_type", "matches[].threatType", "required"),
        _f("domain", "classification", "matches", "required", transform="transform_safebrowsing_verdict"),
        _f("domain", "threat_type", "matches[].threatType", "required"),
    ],
}


# ============================================================================
# SOURCES LIST PART 1 (APIs 1-6)
# Continued in _sources_part2.py and _sources_part3.py
# ============================================================================

SOURCES_PART1 = [VT, ABUSEIPDB, SHODAN, OTX, GREYNOISE, SAFEBROWSING]
