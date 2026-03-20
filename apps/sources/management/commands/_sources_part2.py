"""Sources Part 2: APIs 7-12."""

from ._sources_part1 import _f

# ============================================================================
# 7. Hybrid Analysis
# ============================================================================
HYBRID_ANALYSIS = {
    "name": "Hybrid Analysis", "slug": "hybrid_analysis",
    "base_url": "https://www.hybrid-analysis.com/api/v2",
    "auth_type": "header", "env_var_name": "HYBRID_ANALYSIS_API_KEY",
    "supported_ioc_types": ["hash", "url"],
    "rate_limit_per_minute": 3, "default_ttl_seconds": 604800, "priority": 7,
    "description": "Free malware sandbox with AV detection and MITRE ATT&CK mapping.",
    "fields": [
        _f("hash_sha256", "detection_ratio", "av_detect", "required"),
        _f("hash_sha256", "malware_family", "vx_family", "required"),
        _f("hash_sha256", "classification", "threat_level_human", "required"),
        _f("hash_sha256", "file_type", "type", "core"),
        _f("hash_sha256", "file_size", "size", "optional", "int"),
        _f("hash_sha256", "file_name", "submit_name", "core"),
        _f("hash_sha256", "tags", "classification_tags", "optional", "list"),
        _f("hash_sha256", "mitre_techniques", "mitre_attcks", "optional", "list"),
        _f("hash_sha256", "sandbox_verdicts", "verdict", "core"),
        _f("hash_sha256", "first_seen", "analysis_start_time", "core"),
        _f("url", "classification", "threat_level_human", "required"),
    ],
}

# ============================================================================
# 8. SecurityTrails
# ============================================================================
SECURITYTRAILS = {
    "name": "SecurityTrails", "slug": "securitytrails",
    "base_url": "https://api.securitytrails.com/v1",
    "auth_type": "header", "env_var_name": "SECURITYTRAILS_API_KEY",
    "supported_ioc_types": ["domain", "ip"],
    "rate_limit_per_minute": 1, "default_ttl_seconds": 604800, "priority": 8,
    "description": "Historical DNS data, WHOIS, and subdomain enumeration.",
    "fields": [
        _f("domain", "dns_records", "current_dns", "required", "dict"),
        _f("domain", "subdomains", "subdomains.subdomains", "core", "list"),
        _f("domain", "whois_registrar", "current_dns.registrar", "core"),
        _f("domain", "resolved_ips", "current_dns.a.values[].ip", "core", "list"),
        _f("domain", "hosting_provider", "current_dns.a.values[].ip_organization", "optional"),
        _f("ip", "domains", "records[].hostname", "core", "list"),
    ],
}

# ============================================================================
# 9. ThreatFox (abuse.ch)
# ============================================================================
THREATFOX = {
    "name": "ThreatFox", "slug": "threatfox",
    "base_url": "https://threatfox-api.abuse.ch/api/v1/",
    "auth_type": "body_param", "env_var_name": "ABUSECH_AUTH_KEY",
    "supported_ioc_types": ["hash", "ip", "domain"],
    "rate_limit_per_minute": 10, "default_ttl_seconds": 86400, "priority": 9,
    "description": "Community IOC sharing for malware and botnet C2 indicators (abuse.ch).",
    "fields": [
        # HASH
        _f("hash_sha256", "threat_type", "data[].threat_type", "required"),
        _f("hash_sha256", "malware_family", "data[].malware", "required"),
        _f("hash_sha256", "confidence_score", "data[].confidence_level", "core", "int"),
        _f("hash_sha256", "first_seen", "data[].first_seen", "core"),
        _f("hash_sha256", "last_seen", "data[].last_seen", "core"),
        _f("hash_sha256", "tags", "data[].tags", "optional", "list"),
        _f("hash_sha256", "reporter", "data[].reporter", "optional"),
        # IP
        _f("ip", "threat_type", "data[].threat_type", "required"),
        _f("ip", "malware_family", "data[].malware", "core"),
        _f("ip", "confidence_score", "data[].confidence_level", "core", "int"),
        _f("ip", "first_seen", "data[].first_seen", "core"),
        _f("ip", "tags", "data[].tags", "optional", "list"),
        # DOMAIN
        _f("domain", "threat_type", "data[].threat_type", "required"),
        _f("domain", "malware_family", "data[].malware", "core"),
        _f("domain", "confidence_score", "data[].confidence_level", "core", "int"),
        _f("domain", "first_seen", "data[].first_seen", "core"),
        _f("domain", "tags", "data[].tags", "optional", "list"),
    ],
}

# ============================================================================
# 10. URLhaus (abuse.ch)
# ============================================================================
URLHAUS = {
    "name": "URLhaus", "slug": "urlhaus",
    "base_url": "https://urlhaus-api.abuse.ch/v1/",
    "auth_type": "none", "env_var_name": "",
    "supported_ioc_types": ["url", "domain", "hash"],
    "rate_limit_per_minute": 10, "default_ttl_seconds": 43200, "priority": 10,
    "description": "Malicious URL tracker focused on malware distribution sites (abuse.ch). Free, no API key.",
    "fields": [
        # URL
        _f("url", "classification", "url_status", "required"),
        _f("url", "threat_type", "threat", "required"),
        _f("url", "tags", "tags", "optional", "list"),
        _f("url", "first_seen", "date_added", "core"),
        _f("url", "last_seen", "last_online", "core"),
        _f("url", "hosting_ip", "host", "core"),
        _f("url", "hosting_country", "country", "optional"),
        # DOMAIN
        _f("domain", "classification", "urls_online", "core", "int"),
        _f("domain", "threat_type", "urls[].threat", "core"),
        _f("domain", "tags", "urls[].tags", "optional", "list"),
        _f("domain", "first_seen", "firstseen", "core"),
        # HASH
        _f("hash_sha256", "classification", "md5_count", "core", "int"),
        _f("hash_sha256", "first_seen", "firstseen", "core"),
        _f("hash_sha256", "file_type", "file_type", "core"),
        _f("hash_sha256", "file_size", "file_size", "optional", "int"),
        _f("hash_sha256", "delivery_method", "urls[].url_status", "core"),
        _f("hash_sha256", "related_urls", "urls[].url", "optional", "list"),
    ],
}

# ============================================================================
# 11. URLScan.io
# ============================================================================
URLSCAN = {
    "name": "URLScan.io", "slug": "urlscan",
    "base_url": "https://urlscan.io/api/v1",
    "auth_type": "header", "env_var_name": "URLSCAN_API_KEY",
    "supported_ioc_types": ["url", "domain"],
    "rate_limit_per_minute": 2, "default_ttl_seconds": 86400, "priority": 11,
    "description": "Website scanner providing screenshots, DOM analysis, and technology detection.",
    "fields": [
        # URL
        _f("url", "classification", "verdicts.overall.malicious", "required", "bool"),
        _f("url", "threat_type", "verdicts.overall.categories", "core", "list"),
        _f("url", "final_url", "page.url", "core"),
        _f("url", "http_status", "page.status", "core", "int"),
        _f("url", "server", "page.server", "optional"),
        _f("url", "page_title", "page.title", "optional"),
        _f("url", "hosting_ip", "page.ip", "core"),
        _f("url", "hosting_country", "page.country", "optional"),
        _f("url", "screenshot", "task.screenshotURL", "optional"),
        _f("url", "certificates", "lists.certificates", "optional", "list"),
        _f("url", "technologies", "meta.processors.technologies", "optional", "list"),
        _f("url", "dom_analysis", "lists.urls", "optional", "list"),
        # DOMAIN
        _f("domain", "classification", "verdicts.overall.malicious", "core", "bool"),
        _f("domain", "resolved_ips", "lists.ips", "core", "list"),
        _f("domain", "technologies", "meta.processors.technologies", "optional", "list"),
        _f("domain", "ssl_cert", "lists.certificates", "optional", "list"),
        _f("domain", "categories", "verdicts.overall.categories", "core", "list"),
    ],
}

# ============================================================================
# 12. Pulsedive
# ============================================================================
PULSEDIVE = {
    "name": "Pulsedive", "slug": "pulsedive",
    "base_url": "https://pulsedive.com/api",
    "auth_type": "query_param", "env_var_name": "PULSEDIVE_API_KEY",
    "supported_ioc_types": ["ip", "domain", "hash", "url"],
    "rate_limit_per_minute": 1, "default_ttl_seconds": 86400, "priority": 12,
    "description": "Community threat intelligence with risk scoring and feed aggregation.",
    "fields": [
        # IP
        _f("ip", "classification", "risk", "required"),
        _f("ip", "country", "properties.geo.country", "core"),
        _f("ip", "org", "properties.geo.org", "core"),
        _f("ip", "tags", "attributes.technology", "optional", "list"),
        _f("ip", "threat_type", "threats[].name", "core", "list"),
        _f("ip", "first_seen", "stamp_added", "core"),
        _f("ip", "last_seen", "stamp_updated", "core"),
        # DOMAIN
        _f("domain", "classification", "risk", "required"),
        _f("domain", "tags", "attributes.technology", "optional", "list"),
        _f("domain", "threat_type", "threats[].name", "core", "list"),
        _f("domain", "resolved_ips", "properties.dns.A", "core", "list"),
        _f("domain", "first_seen", "stamp_added", "core"),
        _f("domain", "last_seen", "stamp_updated", "core"),
        # HASH
        _f("hash_sha256", "classification", "risk", "required"),
        _f("hash_sha256", "threat_type", "threats[].name", "core", "list"),
        _f("hash_sha256", "tags", "attributes.technology", "optional", "list"),
        _f("hash_sha256", "first_seen", "stamp_added", "core"),
        # URL
        _f("url", "classification", "risk", "required"),
        _f("url", "threat_type", "threats[].name", "core", "list"),
        _f("url", "hosting_ip", "properties.dns.A", "core"),
        _f("url", "first_seen", "stamp_added", "core"),
    ],
}


SOURCES_PART2 = [HYBRID_ANALYSIS, SECURITYTRAILS, THREATFOX, URLHAUS, URLSCAN, PULSEDIVE]
