"""Shodan API adapter — IP addresses only."""

from ..base_adapter import BaseAdapter
from ..transforms import transform_shodan_services


class ShodanAdapter(BaseAdapter):
    SOURCE_SLUG = "shodan"
    SUPPORTED_IOC_TYPES = ["ip"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": f"https://api.shodan.io/shodan/host/{ioc_value}",
            "params": {"key": self.api_key},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []

        self._collect(results, "open_ports", raw.get("ports"), expected_fields)
        self._collect(results, "vulns", raw.get("vulns"), expected_fields)
        self._collect(results, "country", raw.get("country_name"), expected_fields)
        self._collect(results, "country_code", raw.get("country_code"), expected_fields)
        self._collect(results, "city", raw.get("city"), expected_fields)
        self._collect(results, "asn", raw.get("asn"), expected_fields)
        self._collect(results, "org", raw.get("org"), expected_fields)
        self._collect(results, "isp", raw.get("isp"), expected_fields)
        self._collect(results, "os", raw.get("os"), expected_fields)
        self._collect(results, "hostnames", raw.get("hostnames"), expected_fields)
        self._collect(results, "domains", raw.get("domains"), expected_fields)
        self._collect(results, "last_seen", raw.get("last_update"), expected_fields)
        self._collect(results, "services", transform_shodan_services(raw.get("data")), expected_fields)
        self._collect(results, "tags", raw.get("tags"), expected_fields)
        self._collect(results, "latitude", raw.get("latitude"), expected_fields)
        self._collect(results, "longitude", raw.get("longitude"), expected_fields)

        return results
