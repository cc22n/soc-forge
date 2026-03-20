"""VirusTotal API adapter — hashes, IPs, domains, URLs."""

from apps.core.enums import IOCType
from ..base_adapter import AdapterResult, BaseAdapter
from ..transforms import transform_epoch_to_iso, transform_vt_detection_ratio


class VirusTotalAdapter(BaseAdapter):
    SOURCE_SLUG = "virustotal"
    SUPPORTED_IOC_TYPES = ["hash", "ip", "domain", "url"]

    def _build_request(self, ioc_value, ioc_type):
        headers = {"x-apikey": self.api_key}
        general = IOCType.get_general_type(ioc_type)

        if general == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        elif ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"

        return {"url": url, "headers": headers}

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        attrs = raw.get("data", {}).get("attributes", {})
        general = IOCType.get_general_type(ioc_type)

        # Common across types
        stats = attrs.get("last_analysis_stats")
        self._collect(results, "detection_ratio", transform_vt_detection_ratio(stats), expected_fields)

        last_analysis = attrs.get("last_analysis_date")
        self._collect(results, "last_seen", transform_epoch_to_iso(last_analysis), expected_fields)

        self._collect(results, "tags", attrs.get("tags"), expected_fields)

        if general == "hash":
            ptc = attrs.get("popular_threat_classification", {})
            self._collect(results, "malware_family", ptc.get("suggested_threat_label"), expected_fields)
            self._collect(results, "threat_label",
                          ptc.get("popular_threat_name", [{}])[0].get("value") if ptc.get("popular_threat_name") else None,
                          expected_fields)
            self._collect(results, "file_type", attrs.get("type_description"), expected_fields)
            self._collect(results, "file_size", attrs.get("size"), expected_fields)
            self._collect(results, "file_name", attrs.get("meaningful_name"), expected_fields)
            self._collect(results, "first_seen", transform_epoch_to_iso(attrs.get("first_submission_date")), expected_fields)
            self._collect(results, "sandbox_verdicts", attrs.get("sandbox_verdicts"), expected_fields)
            self._collect(results, "yara_rules", attrs.get("crowdsourced_yara_results"), expected_fields)

        elif ioc_type == "ip":
            self._collect(results, "country", attrs.get("country"), expected_fields)
            self._collect(results, "asn", attrs.get("asn"), expected_fields)
            self._collect(results, "as_owner", attrs.get("as_owner"), expected_fields)

        elif ioc_type == "domain":
            self._collect(results, "whois_creation_date", transform_epoch_to_iso(attrs.get("creation_date")), expected_fields)
            self._collect(results, "whois_registrar", attrs.get("registrar"), expected_fields)
            self._collect(results, "dns_records", attrs.get("last_dns_records"), expected_fields)
            self._collect(results, "categories", attrs.get("categories"), expected_fields)
            self._collect(results, "popularity_rank", attrs.get("popularity_ranks"), expected_fields)

        elif ioc_type == "url":
            self._collect(results, "final_url", attrs.get("last_final_url"), expected_fields)
            self._collect(results, "http_status", attrs.get("last_http_response_code"), expected_fields)
            self._collect(results, "page_title", attrs.get("title"), expected_fields)
            self._collect(results, "first_seen", transform_epoch_to_iso(attrs.get("first_submission_date")), expected_fields)

        return results
