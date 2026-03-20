"""
Remaining API adapters: SecurityTrails, Google Safe Browsing, Hybrid Analysis,
URLScan.io, Pulsedive, Criminal IP, IPQualityScore, Censys, ipinfo.
"""

import base64

from apps.core.enums import IOCType
from ..base_adapter import BaseAdapter
from ..transforms import transform_ipinfo_asn, transform_ipinfo_loc_lat, transform_ipinfo_loc_lng


class SecurityTrailsAdapter(BaseAdapter):
    SOURCE_SLUG = "securitytrails"
    SUPPORTED_IOC_TYPES = ["domain", "ip"]

    def _build_request(self, ioc_value, ioc_type):
        headers = {"APIKEY": self.api_key, "Accept": "application/json"}
        if ioc_type == "domain":
            url = f"https://api.securitytrails.com/v1/domain/{ioc_value}"
        else:
            url = f"https://api.securitytrails.com/v1/ips/nearby/{ioc_value}"
        return {"url": url, "headers": headers}

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        if ioc_type == "domain":
            current_dns = raw.get("current_dns", {})
            self._collect(results, "dns_records", current_dns, expected_fields)
            a_records = current_dns.get("a", {}).get("values", [])
            ips = [r.get("ip") for r in a_records if r.get("ip")]
            self._collect(results, "resolved_ips", ips, expected_fields)
            if a_records:
                self._collect(results, "hosting_provider", a_records[0].get("ip_organization"), expected_fields)
            self._collect(results, "subdomains", raw.get("subdomain_count"), expected_fields)
        else:
            blocks = raw.get("blocks", [])
            hostnames = []
            for b in blocks:
                for s in b.get("sites", []):
                    hostnames.append(s)
            self._collect(results, "domains", hostnames[:20], expected_fields)
        return results


class SafeBrowsingAdapter(BaseAdapter):
    SOURCE_SLUG = "google_safebrowsing"
    SUPPORTED_IOC_TYPES = ["url", "domain"]

    def _build_request(self, ioc_value, ioc_type):
        url_to_check = ioc_value if ioc_type == "url" else f"http://{ioc_value}/"
        return {
            "method": "POST",
            "url": f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}",
            "json": {
                "client": {"clientId": "socforge", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url_to_check}],
                },
            },
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        matches = raw.get("matches", [])
        verdict = "malicious" if matches else "clean"
        self._collect(results, "classification", verdict, expected_fields)
        if matches:
            threat_types = list(set(m.get("threatType", "") for m in matches))
            self._collect(results, "threat_type", threat_types[0] if len(threat_types) == 1 else threat_types, expected_fields)
        else:
            self._collect(results, "threat_type", None, expected_fields)
        return results


class HybridAnalysisAdapter(BaseAdapter):
    SOURCE_SLUG = "hybrid_analysis"
    SUPPORTED_IOC_TYPES = ["hash", "url"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "method": "POST",
            "url": "https://www.hybrid-analysis.com/api/v2/search/hash",
            "headers": {"api-key": self.api_key, "User-Agent": "Falcon Sandbox"},
            "data": {"hash": ioc_value},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        entries = raw if isinstance(raw, list) else [raw]
        if not entries:
            return results
        entry = entries[0]

        self._collect(results, "detection_ratio", entry.get("av_detect"), expected_fields)
        self._collect(results, "malware_family", entry.get("vx_family"), expected_fields)
        self._collect(results, "classification", entry.get("threat_level_human"), expected_fields)
        self._collect(results, "file_type", entry.get("type"), expected_fields)
        self._collect(results, "file_size", entry.get("size"), expected_fields)
        self._collect(results, "file_name", entry.get("submit_name"), expected_fields)
        self._collect(results, "tags", entry.get("classification_tags"), expected_fields)
        self._collect(results, "mitre_techniques", entry.get("mitre_attcks"), expected_fields)
        self._collect(results, "sandbox_verdicts", entry.get("verdict"), expected_fields)
        self._collect(results, "first_seen", entry.get("analysis_start_time"), expected_fields)
        return results


class URLScanAdapter(BaseAdapter):
    SOURCE_SLUG = "urlscan"
    SUPPORTED_IOC_TYPES = ["url", "domain"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": "https://urlscan.io/api/v1/search/",
            "headers": {"API-Key": self.api_key},
            "params": {"q": f"page.url:\"{ioc_value}\"" if ioc_type == "url" else f"page.domain:{ioc_value}", "size": 1},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results_list = raw.get("results", [])
        if not results_list:
            return []

        results = []
        entry = results_list[0]
        page = entry.get("page", {})
        task = entry.get("task", {})

        self._collect(results, "classification", entry.get("verdicts", {}).get("overall", {}).get("malicious"), expected_fields)
        self._collect(results, "final_url", page.get("url"), expected_fields)
        self._collect(results, "http_status", page.get("status"), expected_fields)
        self._collect(results, "server", page.get("server"), expected_fields)
        self._collect(results, "page_title", page.get("title"), expected_fields)
        self._collect(results, "hosting_ip", page.get("ip"), expected_fields)
        self._collect(results, "hosting_country", page.get("country"), expected_fields)
        self._collect(results, "screenshot", task.get("screenshotURL"), expected_fields)
        return results


class PulsediveAdapter(BaseAdapter):
    SOURCE_SLUG = "pulsedive"
    SUPPORTED_IOC_TYPES = ["ip", "domain", "hash", "url"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": "https://pulsedive.com/api/info.php",
            "params": {"indicator": ioc_value, "key": self.api_key},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        self._collect(results, "classification", raw.get("risk"), expected_fields)
        self._collect(results, "first_seen", raw.get("stamp_added"), expected_fields)
        self._collect(results, "last_seen", raw.get("stamp_updated"), expected_fields)

        threats = raw.get("threats", [])
        if threats:
            threat_names = [t.get("name") for t in threats if t.get("name")]
            self._collect(results, "threat_type", threat_names, expected_fields)

        props = raw.get("properties", {}) or {}
        tech = raw.get("attributes", {}).get("technology", [])
        self._collect(results, "tags", tech if tech else None, expected_fields)

        if ioc_type in ("ip", "domain"):
            geo = props.get("geo", {}) or {}
            self._collect(results, "country", geo.get("country"), expected_fields)
            self._collect(results, "org", geo.get("org"), expected_fields)
            dns = props.get("dns", {}) or {}
            self._collect(results, "resolved_ips", dns.get("A"), expected_fields)

        if ioc_type in ("url",):
            dns = props.get("dns", {}) or {}
            self._collect(results, "hosting_ip", dns.get("A", [None])[0] if dns.get("A") else None, expected_fields)

        return results


class CriminalIPAdapter(BaseAdapter):
    SOURCE_SLUG = "criminal_ip"
    SUPPORTED_IOC_TYPES = ["ip"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": f"https://api.criminalip.io/v1/asset/ip/report",
            "headers": {"x-api-key": self.api_key},
            "params": {"ip": ioc_value},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        score = raw.get("score", {}) or {}
        whois = raw.get("whois", {}).get("data", {}) or {}
        port_data = raw.get("port", {}).get("data", []) or []

        self._collect(results, "classification", score.get("inbound"), expected_fields)
        ports = [p.get("open_port_no") for p in port_data if p.get("open_port_no")]
        self._collect(results, "open_ports", ports, expected_fields)
        vulns = []
        for p in port_data:
            for v in (p.get("vulns") or []):
                vulns.append(v)
        self._collect(results, "vulns", vulns if vulns else None, expected_fields)
        self._collect(results, "country", whois.get("country"), expected_fields)
        self._collect(results, "city", whois.get("city"), expected_fields)
        self._collect(results, "asn", whois.get("as_no"), expected_fields)
        self._collect(results, "org", whois.get("org_name"), expected_fields)
        self._collect(results, "is_vpn", score.get("is_vpn"), expected_fields)
        self._collect(results, "is_tor", score.get("is_tor"), expected_fields)
        self._collect(results, "is_proxy", score.get("is_proxy"), expected_fields)
        dns_data = raw.get("dns", {}).get("data", []) or []
        hostnames = [d.get("domain") for d in dns_data if d.get("domain")]
        self._collect(results, "hostnames", hostnames if hostnames else None, expected_fields)
        return results


class IPQualityScoreAdapter(BaseAdapter):
    SOURCE_SLUG = "ipqualityscore"
    SUPPORTED_IOC_TYPES = ["ip", "url"]

    def _build_request(self, ioc_value, ioc_type):
        if ioc_type == "ip":
            url = f"https://ipqualityscore.com/api/json/ip/{self.api_key}/{ioc_value}"
        else:
            url = f"https://ipqualityscore.com/api/json/url/{self.api_key}/{ioc_value}"
        return {"url": url}

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        if ioc_type == "ip":
            self._collect(results, "abuse_confidence", raw.get("fraud_score"), expected_fields)
            self._collect(results, "country_code", raw.get("country_code"), expected_fields)
            self._collect(results, "city", raw.get("city"), expected_fields)
            self._collect(results, "isp", raw.get("ISP"), expected_fields)
            self._collect(results, "org", raw.get("organization"), expected_fields)
            self._collect(results, "is_vpn", raw.get("vpn"), expected_fields)
            self._collect(results, "is_tor", raw.get("tor"), expected_fields)
            self._collect(results, "is_proxy", raw.get("proxy"), expected_fields)
            self._collect(results, "is_crawler", raw.get("is_crawler"), expected_fields)
            self._collect(results, "classification", raw.get("recent_abuse"), expected_fields)
        else:
            self._collect(results, "classification", raw.get("unsafe"), expected_fields)
            self._collect(results, "threat_type", raw.get("category"), expected_fields)
            self._collect(results, "hosting_ip", raw.get("ip_address"), expected_fields)
            self._collect(results, "hosting_country", raw.get("country_code"), expected_fields)
            self._collect(results, "content_type", raw.get("content_type"), expected_fields)
        return results


class CensysAdapter(BaseAdapter):
    SOURCE_SLUG = "censys"
    SUPPORTED_IOC_TYPES = ["ip", "domain"]

    def _get_api_key(self):
        keys = getattr(self, "_settings_keys", None)
        if keys is None:
            from django.conf import settings
            self._settings_keys = settings.THREAT_INTEL_KEYS
        return self._settings_keys.get("censys_id", "")

    def _build_request(self, ioc_value, ioc_type):
        api_id = self.api_key
        from django.conf import settings
        api_secret = settings.THREAT_INTEL_KEYS.get("censys_secret", "")
        auth_str = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()

        if ioc_type == "ip":
            url = f"https://search.censys.io/api/v2/hosts/{ioc_value}"
        else:
            url = f"https://search.censys.io/api/v2/hosts/search?q={ioc_value}"

        return {
            "url": url,
            "headers": {"Authorization": f"Basic {auth_str}", "Accept": "application/json"},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        result = raw.get("result", {})

        if ioc_type == "ip":
            services = result.get("services", [])
            ports = [s.get("port") for s in services if s.get("port")]
            self._collect(results, "open_ports", ports, expected_fields)
            self._collect(results, "services", services[:20], expected_fields)

            location = result.get("location", {}) or {}
            self._collect(results, "country", location.get("country"), expected_fields)
            self._collect(results, "city", location.get("city"), expected_fields)

            asys = result.get("autonomous_system", {}) or {}
            self._collect(results, "asn", asys.get("asn"), expected_fields)
            self._collect(results, "as_owner", asys.get("name"), expected_fields)

            self._collect(results, "os", result.get("operating_system", {}).get("product") if result.get("operating_system") else None, expected_fields)
            self._collect(results, "last_seen", result.get("last_updated_at"), expected_fields)
        else:
            hits = raw.get("result", {}).get("hits", [])
            if hits:
                ips = [h.get("ip") for h in hits if h.get("ip")]
                self._collect(results, "resolved_ips", ips, expected_fields)
        return results


class IPInfoAdapter(BaseAdapter):
    SOURCE_SLUG = "ipinfo"
    SUPPORTED_IOC_TYPES = ["ip"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": f"https://ipinfo.io/{ioc_value}",
            "headers": {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        self._collect(results, "country", raw.get("country"), expected_fields)
        self._collect(results, "country_code", raw.get("country"), expected_fields)
        self._collect(results, "city", raw.get("city"), expected_fields)
        self._collect(results, "region", raw.get("region"), expected_fields)
        self._collect(results, "org", raw.get("org"), expected_fields)
        self._collect(results, "asn", transform_ipinfo_asn(raw.get("org")), expected_fields)
        self._collect(results, "hostnames", raw.get("hostname"), expected_fields)

        loc = raw.get("loc")
        self._collect(results, "latitude", transform_ipinfo_loc_lat(loc), expected_fields)
        self._collect(results, "longitude", transform_ipinfo_loc_lng(loc), expected_fields)

        privacy = raw.get("privacy", {}) or {}
        self._collect(results, "is_vpn", privacy.get("vpn"), expected_fields)
        self._collect(results, "is_proxy", privacy.get("proxy"), expected_fields)
        self._collect(results, "is_tor", privacy.get("tor"), expected_fields)
        return results
