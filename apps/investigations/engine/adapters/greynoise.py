"""GreyNoise API adapter — IP addresses only."""

from ..base_adapter import BaseAdapter


class GreyNoiseAdapter(BaseAdapter):
    SOURCE_SLUG = "greynoise"
    SUPPORTED_IOC_TYPES = ["ip"]

    def _build_request(self, ioc_value, ioc_type):
        return {
            "url": f"https://api.greynoise.io/v3/community/{ioc_value}",
            "headers": {"key": self.api_key},
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []

        self._collect(results, "classification", raw.get("classification"), expected_fields)
        self._collect(results, "is_noise", raw.get("noise"), expected_fields)
        self._collect(results, "is_riot", raw.get("riot"), expected_fields)
        self._collect(results, "org", raw.get("name"), expected_fields)
        self._collect(results, "last_seen", raw.get("last_seen"), expected_fields)
        self._collect(results, "first_seen", raw.get("first_seen"), expected_fields)

        # Tags from community endpoint
        tags_raw = raw.get("tags")
        if isinstance(tags_raw, list):
            tag_names = [t.get("name", t) if isinstance(t, dict) else t for t in tags_raw]
            self._collect(results, "tags", tag_names, expected_fields)

        # Metadata fields (available in full API, may not be in community)
        meta = raw.get("metadata", {})
        if meta:
            self._collect(results, "country", meta.get("source_country") or meta.get("country"), expected_fields)
            self._collect(results, "asn", meta.get("asn"), expected_fields)
            self._collect(results, "is_tor", meta.get("tor"), expected_fields)
            self._collect(results, "os", meta.get("os"), expected_fields)

        self._collect(results, "is_vpn", raw.get("vpn"), expected_fields)

        return results
