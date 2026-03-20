"""AlienVault OTX API adapter — hashes, IPs, domains, URLs."""

from apps.core.enums import IOCType
from ..base_adapter import BaseAdapter


class OTXAdapter(BaseAdapter):
    SOURCE_SLUG = "otx"
    SUPPORTED_IOC_TYPES = ["hash", "ip", "domain", "url"]

    def _build_request(self, ioc_value, ioc_type):
        base = "https://otx.alienvault.com/api/v1"
        headers = {"X-OTX-API-KEY": self.api_key}
        general = IOCType.get_general_type(ioc_type)

        if general == "hash":
            url = f"{base}/indicators/file/{ioc_value}/general"
        elif ioc_type == "ip":
            url = f"{base}/indicators/IPv4/{ioc_value}/general"
        elif ioc_type == "domain":
            url = f"{base}/indicators/domain/{ioc_value}/general"
        elif ioc_type == "url":
            url = f"{base}/indicators/url/{ioc_value}/general"
        else:
            url = f"{base}/indicators/file/{ioc_value}/general"

        return {"url": url, "headers": headers}

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        general = IOCType.get_general_type(ioc_type)

        pulse_info = raw.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        self._collect(results, "confidence_score", pulse_count, expected_fields)

        # Extract tags from pulses
        tags = set()
        for pulse in pulse_info.get("pulses", [])[:10]:
            for tag in pulse.get("tags", []):
                tags.add(tag)
        if tags:
            self._collect(results, "tags", list(tags), expected_fields)

        if general == "hash":
            self._collect(results, "malware_family", list(tags) if tags else None, expected_fields)
            self._collect(results, "file_type", raw.get("type_title"), expected_fields)

        elif ioc_type == "ip":
            self._collect(results, "country", raw.get("country_name"), expected_fields)
            self._collect(results, "country_code", raw.get("country_code"), expected_fields)
            self._collect(results, "asn", raw.get("asn"), expected_fields)

        elif ioc_type == "domain":
            whois = raw.get("whois", {}) or {}
            self._collect(results, "whois_registrar", whois.get("registrar") if isinstance(whois, dict) else None, expected_fields)

            # Passive DNS
            pdns = raw.get("passive_dns", [])
            if pdns:
                self._collect(results, "dns_records", pdns[:20], expected_fields)
                ips = list(set(r.get("address", "") for r in pdns if r.get("address")))
                self._collect(results, "resolved_ips", ips, expected_fields)

        elif ioc_type == "url":
            url_list = raw.get("url_list", {})
            if isinstance(url_list, dict):
                result = url_list.get("result", {}) or {}
                urlworker = result.get("urlworker", {}) or {}
                self._collect(results, "hosting_ip", urlworker.get("ip"), expected_fields)
                self._collect(results, "http_status", result.get("httpcode"), expected_fields)

        return results
