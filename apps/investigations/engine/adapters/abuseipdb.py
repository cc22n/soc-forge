"""AbuseIPDB API adapter — IP addresses only."""

from ..base_adapter import BaseAdapter


class AbuseIPDBAdapter(BaseAdapter):
    SOURCE_SLUG = "abuseipdb"
    SUPPORTED_IOC_TYPES = ["ip"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": "https://api.abuseipdb.com/api/v2/check",
            "headers": {
                "Key": self.api_key,
                "Accept": "application/json",
            },
            "params": {
                "ipAddress": ioc_value,
                "maxAgeInDays": 90,
                "verbose": "",
            },
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        data = raw.get("data", {})

        self._collect(results, "abuse_confidence", data.get("abuseConfidenceScore"), expected_fields)
        self._collect(results, "country_code", data.get("countryCode"), expected_fields)
        self._collect(results, "country", data.get("countryName"), expected_fields)
        self._collect(results, "isp", data.get("isp"), expected_fields)
        self._collect(results, "usage_type", data.get("usageType"), expected_fields)
        self._collect(results, "domains", data.get("domain"), expected_fields)
        self._collect(results, "hostnames", data.get("hostnames"), expected_fields)
        self._collect(results, "is_tor", data.get("isTor"), expected_fields)
        self._collect(results, "total_reports", data.get("totalReports"), expected_fields)
        self._collect(results, "last_reported", data.get("lastReportedAt"), expected_fields)
        self._collect(results, "is_whitelisted", data.get("isWhitelisted"), expected_fields)

        return results
