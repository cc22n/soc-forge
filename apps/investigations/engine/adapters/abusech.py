"""abuse.ch family adapters: ThreatFox, URLhaus, Malware Bazaar."""

from apps.core.enums import IOCType
from ..base_adapter import BaseAdapter


class ThreatFoxAdapter(BaseAdapter):
    SOURCE_SLUG = "threatfox"
    SUPPORTED_IOC_TYPES = ["hash", "ip", "domain"]

    def _build_request(self, ioc_value, ioc_type):
        general = IOCType.get_general_type(ioc_type)
        if general == "hash":
            payload = {"query": "search_hash", "hash": ioc_value}
        else:
            payload = {"query": "search_ioc", "search_term": ioc_value}

        return {
            "method": "POST",
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "json": payload,
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        data_list = raw.get("data", [])
        if not isinstance(data_list, list) or not data_list:
            return results

        entry = data_list[0]
        self._collect(results, "threat_type", entry.get("threat_type"), expected_fields)
        self._collect(results, "malware_family", entry.get("malware"), expected_fields)
        self._collect(results, "confidence_score", entry.get("confidence_level"), expected_fields)
        self._collect(results, "first_seen", entry.get("first_seen"), expected_fields)
        self._collect(results, "last_seen", entry.get("last_seen"), expected_fields)
        self._collect(results, "reporter", entry.get("reporter"), expected_fields)

        tags = entry.get("tags")
        self._collect(results, "tags", tags if isinstance(tags, list) else None, expected_fields)

        return results


class URLhausAdapter(BaseAdapter):
    SOURCE_SLUG = "urlhaus"
    SUPPORTED_IOC_TYPES = ["url", "domain", "hash"]

    def _build_request(self, ioc_value, ioc_type):
        general = IOCType.get_general_type(ioc_type)

        if ioc_type == "url":
            url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {"url": ioc_value}
        elif ioc_type == "domain":
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": ioc_value}
        elif general == "hash":
            url = "https://urlhaus-api.abuse.ch/v1/payload/"
            if len(ioc_value) == 32:
                data = {"md5_hash": ioc_value}
            elif len(ioc_value) == 64:
                data = {"sha256_hash": ioc_value}
            else:
                data = {"sha256_hash": ioc_value}
        else:
            url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {"url": ioc_value}

        return {"method": "POST", "url": url, "data": data}

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        general = IOCType.get_general_type(ioc_type)

        if ioc_type == "url":
            self._collect(results, "classification", raw.get("url_status"), expected_fields)
            self._collect(results, "threat_type", raw.get("threat"), expected_fields)
            self._collect(results, "first_seen", raw.get("date_added"), expected_fields)
            self._collect(results, "last_seen", raw.get("last_online"), expected_fields)
            self._collect(results, "hosting_ip", raw.get("host"), expected_fields)
            self._collect(results, "hosting_country", raw.get("country"), expected_fields)
            tags = raw.get("tags")
            self._collect(results, "tags", tags if isinstance(tags, list) else None, expected_fields)

        elif ioc_type == "domain":
            self._collect(results, "classification", raw.get("urls_online"), expected_fields)
            self._collect(results, "first_seen", raw.get("firstseen"), expected_fields)
            urls = raw.get("urls", [])
            if urls:
                threats = list(set(u.get("threat", "") for u in urls if u.get("threat")))
                self._collect(results, "threat_type", threats[0] if len(threats) == 1 else threats, expected_fields)
                all_tags = set()
                for u in urls:
                    for t in (u.get("tags") or []):
                        all_tags.add(t)
                self._collect(results, "tags", list(all_tags) if all_tags else None, expected_fields)

        elif general == "hash":
            self._collect(results, "first_seen", raw.get("firstseen"), expected_fields)
            self._collect(results, "file_type", raw.get("file_type"), expected_fields)
            self._collect(results, "file_size", raw.get("file_size"), expected_fields)
            urls = raw.get("urls", [])
            if urls:
                self._collect(results, "delivery_method", urls[0].get("url_status"), expected_fields)
                url_list = [u.get("url") for u in urls if u.get("url")]
                self._collect(results, "related_urls", url_list, expected_fields)
            md5_count = raw.get("md5_count")
            self._collect(results, "classification", md5_count, expected_fields)

        return results


class MalwareBazaarAdapter(BaseAdapter):
    SOURCE_SLUG = "malware_bazaar"
    SUPPORTED_IOC_TYPES = ["hash"]

    def _build_request(self, ioc_value, ioc_type):
        if len(ioc_value) == 32:
            query_type = "get_info"
            data = {"query": query_type, "hash": ioc_value}
        else:
            data = {"query": "get_info", "hash": ioc_value}

        return {
            "method": "POST",
            "url": "https://mb-api.abuse.ch/api/v1/",
            "data": data,
        }

    def _parse_response(self, raw, ioc_type, expected_fields):
        results = []
        data_list = raw.get("data", [])
        if not isinstance(data_list, list) or not data_list:
            return results

        entry = data_list[0]
        self._collect(results, "malware_family", entry.get("signature"), expected_fields)
        self._collect(results, "file_type", entry.get("file_type"), expected_fields)
        self._collect(results, "file_size", entry.get("file_size"), expected_fields)
        self._collect(results, "file_name", entry.get("file_name"), expected_fields)
        self._collect(results, "first_seen", entry.get("first_seen"), expected_fields)
        self._collect(results, "last_seen", entry.get("last_seen"), expected_fields)
        self._collect(results, "delivery_method", entry.get("delivery_method"), expected_fields)
        self._collect(results, "reporter", entry.get("reporter"), expected_fields)

        tags = entry.get("tags")
        self._collect(results, "tags", tags if isinstance(tags, list) else None, expected_fields)

        yara = entry.get("yara_rules")
        self._collect(results, "yara_rules", yara if isinstance(yara, list) else None, expected_fields)

        intelligence = entry.get("intelligence", {}) or {}
        clamav = intelligence.get("clamav")
        self._collect(results, "threat_type", clamav if isinstance(clamav, list) else None, expected_fields)
        self._collect(results, "campaign", intelligence.get("mail"), expected_fields)

        return results
