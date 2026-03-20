"""Sources Part 3: APIs 13-17 + Default profiles."""

from ._sources_part1 import _f

# ============================================================================
# 13. Criminal IP
# ============================================================================
CRIMINAL_IP = {
    "name": "Criminal IP", "slug": "criminal_ip",
    "base_url": "https://api.criminalip.io/v1",
    "auth_type": "header", "env_var_name": "CRIMINAL_IP_API_KEY",
    "supported_ioc_types": ["ip"],
    "rate_limit_per_minute": 1, "default_ttl_seconds": 604800, "priority": 13,
    "description": "IP intelligence with open port scanning, vulnerability detection, and abuse scoring.",
    "fields": [
        _f("ip", "classification", "score.inbound", "required"),
        _f("ip", "open_ports", "port.data[].open_port_no", "required", "list"),
        _f("ip", "vulns", "port.data[].vulns", "required", "list"),
        _f("ip", "country", "whois.data.country", "core"),
        _f("ip", "city", "whois.data.city", "optional"),
        _f("ip", "asn", "whois.data.as_no", "core"),
        _f("ip", "org", "whois.data.org_name", "core"),
        _f("ip", "hostnames", "dns.data[].domain", "core", "list"),
        _f("ip", "is_vpn", "score.is_vpn", "core", "bool"),
        _f("ip", "is_tor", "score.is_tor", "core", "bool"),
        _f("ip", "is_proxy", "score.is_proxy", "core", "bool"),
        _f("ip", "services", "port.data", "optional", "list"),
    ],
}

# ============================================================================
# 14. IPQualityScore
# ============================================================================
IPQUALITYSCORE = {
    "name": "IPQualityScore", "slug": "ipqualityscore",
    "base_url": "https://ipqualityscore.com/api/json",
    "auth_type": "query_param", "env_var_name": "IPQUALITYSCORE_API_KEY",
    "supported_ioc_types": ["ip", "url"],
    "rate_limit_per_minute": 3, "default_ttl_seconds": 86400, "priority": 14,
    "description": "Fraud detection and risk scoring for IPs and URLs.",
    "fields": [
        # IP
        _f("ip", "abuse_confidence", "fraud_score", "required", "int"),
        _f("ip", "country_code", "country_code", "core"),
        _f("ip", "city", "city", "optional"),
        _f("ip", "isp", "ISP", "core"),
        _f("ip", "org", "organization", "core"),
        _f("ip", "is_vpn", "vpn", "core", "bool"),
        _f("ip", "is_tor", "tor", "core", "bool"),
        _f("ip", "is_proxy", "proxy", "core", "bool"),
        _f("ip", "is_crawler", "is_crawler", "optional", "bool"),
        _f("ip", "classification", "recent_abuse", "required", "bool"),
        # URL
        _f("url", "classification", "unsafe", "required", "bool"),
        _f("url", "threat_type", "category", "core"),
        _f("url", "hosting_ip", "ip_address", "core"),
        _f("url", "hosting_country", "country_code", "optional"),
        _f("url", "content_type", "content_type", "optional"),
    ],
}

# ============================================================================
# 15. Censys
# ============================================================================
CENSYS = {
    "name": "Censys", "slug": "censys",
    "base_url": "https://search.censys.io/api/v2",
    "auth_type": "basic_auth", "env_var_name": "CENSYS_API_ID",
    "supported_ioc_types": ["ip", "domain"],
    "rate_limit_per_minute": 4, "default_ttl_seconds": 604800, "priority": 15,
    "description": "Internet-wide host and certificate scanning with detailed service identification.",
    "fields": [
        # IP
        _f("ip", "open_ports", "result.services[].port", "required", "list"),
        _f("ip", "services", "result.services", "core", "list"),
        _f("ip", "country", "result.location.country", "core"),
        _f("ip", "city", "result.location.city", "optional"),
        _f("ip", "asn", "result.autonomous_system.asn", "core"),
        _f("ip", "as_owner", "result.autonomous_system.name", "core"),
        _f("ip", "os", "result.operating_system.product", "optional"),
        _f("ip", "last_seen", "result.last_updated_at", "core"),
        # DOMAIN
        _f("domain", "dns_records", "result.dns.records", "core", "list"),
        _f("domain", "ssl_cert", "result.certificates", "optional", "list"),
        _f("domain", "resolved_ips", "result.dns.records[].value", "core", "list"),
    ],
}

# ============================================================================
# 16. Malware Bazaar (abuse.ch)
# ============================================================================
MALWARE_BAZAAR = {
    "name": "Malware Bazaar", "slug": "malware_bazaar",
    "base_url": "https://mb-api.abuse.ch/api/v1/",
    "auth_type": "none", "env_var_name": "",
    "supported_ioc_types": ["hash"],
    "rate_limit_per_minute": 10, "default_ttl_seconds": 2592000, "priority": 16,
    "description": "Malware sample sharing and repository. Free, no API key (abuse.ch).",
    "fields": [
        _f("hash_sha256", "malware_family", "data[].signature", "required"),
        _f("hash_sha256", "file_type", "data[].file_type", "core"),
        _f("hash_sha256", "file_size", "data[].file_size", "optional", "int"),
        _f("hash_sha256", "file_name", "data[].file_name", "core"),
        _f("hash_sha256", "first_seen", "data[].first_seen", "core"),
        _f("hash_sha256", "last_seen", "data[].last_seen", "core"),
        _f("hash_sha256", "delivery_method", "data[].delivery_method", "core"),
        _f("hash_sha256", "tags", "data[].tags", "optional", "list"),
        _f("hash_sha256", "yara_rules", "data[].yara_rules", "optional", "list"),
        _f("hash_sha256", "reporter", "data[].reporter", "optional"),
        _f("hash_sha256", "threat_type", "data[].intelligence.clamav", "core", "list"),
        _f("hash_sha256", "campaign", "data[].intelligence.mail", "optional"),
    ],
}

# ============================================================================
# 17. ipinfo.io
# ============================================================================
IPINFO = {
    "name": "ipinfo.io", "slug": "ipinfo",
    "base_url": "https://ipinfo.io",
    "auth_type": "header", "env_var_name": "IPINFO_API_KEY",
    "supported_ioc_types": ["ip"],
    "rate_limit_per_minute": 833, "default_ttl_seconds": 604800, "priority": 17,
    "description": "IP geolocation and network data. High rate limit, lightweight enrichment.",
    "fields": [
        _f("ip", "country", "country", "core"),
        _f("ip", "country_code", "country", "core"),
        _f("ip", "city", "city", "optional"),
        _f("ip", "region", "region", "optional"),
        _f("ip", "org", "org", "core"),
        _f("ip", "asn", "org", "core", transform="transform_ipinfo_asn"),
        _f("ip", "hostnames", "hostname", "core"),
        _f("ip", "latitude", "loc", "optional", "float", transform="transform_ipinfo_loc_lat"),
        _f("ip", "longitude", "loc", "optional", "float", transform="transform_ipinfo_loc_lng"),
        _f("ip", "is_vpn", "privacy.vpn", "core", "bool"),
        _f("ip", "is_proxy", "privacy.proxy", "core", "bool"),
        _f("ip", "is_tor", "privacy.tor", "core", "bool"),
    ],
}


SOURCES_PART3 = [CRIMINAL_IP, IPQUALITYSCORE, CENSYS, MALWARE_BAZAAR, IPINFO]


# ============================================================================
# DEFAULT INVESTIGATION PROFILES
# ============================================================================
DEFAULT_PROFILES = [
    {
        "name": "Quick Hash Lookup",
        "ioc_type": "hash_sha256",
        "description": "Fast hash check against VirusTotal and Malware Bazaar.",
        "sources": ["virustotal", "malware_bazaar"],
    },
    {
        "name": "Full Malware Analysis",
        "ioc_type": "hash_sha256",
        "description": "Comprehensive hash investigation: AV detection, sandbox, YARA, threat feeds.",
        "sources": ["virustotal", "malware_bazaar", "hybrid_analysis", "threatfox", "otx"],
    },
    {
        "name": "IP Reputation Check",
        "ioc_type": "ip",
        "description": "Quick IP reputation using abuse scoring, noise detection, and geolocation.",
        "sources": ["abuseipdb", "greynoise", "ipinfo"],
    },
    {
        "name": "Infrastructure Recon",
        "ioc_type": "ip",
        "description": "Deep infrastructure analysis: open ports, services, vulnerabilities.",
        "sources": ["shodan", "censys", "criminal_ip"],
    },
    {
        "name": "Full IP Investigation",
        "ioc_type": "ip",
        "description": "Complete IP analysis across all available sources.",
        "sources": ["abuseipdb", "greynoise", "shodan", "virustotal", "otx", "censys", "criminal_ip", "ipqualityscore", "ipinfo"],
    },
    {
        "name": "Domain Investigation",
        "ioc_type": "domain",
        "description": "Domain analysis: DNS, WHOIS, reputation, subdomains.",
        "sources": ["virustotal", "securitytrails", "otx", "urlscan", "google_safebrowsing"],
    },
    {
        "name": "Phishing URL Analysis",
        "ioc_type": "url",
        "description": "URL reputation check for suspected phishing or social engineering.",
        "sources": ["virustotal", "urlscan", "google_safebrowsing", "ipqualityscore", "otx"],
    },
    {
        "name": "Malware Delivery URL",
        "ioc_type": "url",
        "description": "Investigate URLs suspected of delivering malware payloads.",
        "sources": ["urlhaus", "virustotal", "urlscan", "hybrid_analysis"],
    },
]
