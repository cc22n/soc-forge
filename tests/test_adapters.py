"""
Tests for API adapters — using mocked HTTP responses.
No real API calls are made.
"""

import pytest
from unittest.mock import patch, MagicMock

from apps.core.enums import ResultStatus
from apps.investigations.engine.adapters.virustotal import VirusTotalAdapter
from apps.investigations.engine.adapters.abuseipdb import AbuseIPDBAdapter
from apps.investigations.engine.adapters.greynoise import GreyNoiseAdapter
from apps.investigations.engine.adapters.abusech import MalwareBazaarAdapter, URLhausAdapter
from apps.investigations.engine.base_adapter import BaseAdapter


def _mock_response(status_code=200, json_data=None):
    """Create a mock requests.Response."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.text = str(json_data)
    mock.headers = {}
    return mock


class TestVirusTotalAdapter:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_build_request_ip(self, mock_key):
        adapter = VirusTotalAdapter()
        req = adapter._build_request("8.8.8.8", "ip")
        assert "ip_addresses/8.8.8.8" in req["url"]
        assert req["headers"]["x-apikey"] == "test-key"

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_build_request_hash(self, mock_key):
        adapter = VirusTotalAdapter()
        req = adapter._build_request("abc123def456", "hash_sha256")
        assert "files/abc123def456" in req["url"]

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_build_request_domain(self, mock_key):
        adapter = VirusTotalAdapter()
        req = adapter._build_request("example.com", "domain")
        assert "domains/example.com" in req["url"]

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_parse_ip_response(self, mock_key):
        adapter = VirusTotalAdapter()
        raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "undetected": 60, "suspicious": 0, "harmless": 5, "timeout": 0, "failure": 0},
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                    "last_analysis_date": 1700000000,
                    "tags": ["cdn"],
                }
            }
        }
        results = adapter._parse_response(raw, "ip", None)
        field_names = [r.field_name for r in results]
        assert "detection_ratio" in field_names
        assert "country" in field_names
        assert "asn" in field_names

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_parse_response_with_expected_filter(self, mock_key):
        adapter = VirusTotalAdapter()
        raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "undetected": 60, "suspicious": 0, "harmless": 5, "timeout": 0, "failure": 0},
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                }
            }
        }
        results = adapter._parse_response(raw, "ip", ["country"])
        field_names = [r.field_name for r in results]
        assert "country" in field_names
        # Fields not in expected list should be excluded
        assert "asn" not in field_names


class TestAbuseIPDBAdapter:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_build_request(self, mock_key):
        adapter = AbuseIPDBAdapter()
        req = adapter._build_request("185.220.101.50", "ip")
        assert req["params"]["ipAddress"] == "185.220.101.50"

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_parse_response(self, mock_key):
        adapter = AbuseIPDBAdapter()
        raw = {
            "data": {
                "abuseConfidenceScore": 100,
                "countryCode": "DE",
                "countryName": "Germany",
                "isp": "Hetzner",
                "isTor": True,
                "totalReports": 500,
                "lastReportedAt": "2024-01-01T00:00:00+00:00",
            }
        }
        results = adapter._parse_response(raw, "ip", None)
        fields = {r.field_name: r.value for r in results if r.status == ResultStatus.FOUND}
        assert fields["abuse_confidence"] == 100
        assert fields["country_code"] == "DE"
        assert fields["is_tor"] is True
        assert fields["total_reports"] == 500


class TestGreyNoiseAdapter:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_parse_community_response(self, mock_key):
        adapter = GreyNoiseAdapter()
        raw = {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "name": "Unknown Scanner",
            "last_seen": "2024-01-15",
        }
        results = adapter._parse_response(raw, "ip", None)
        fields = {r.field_name: r.value for r in results if r.status == ResultStatus.FOUND}
        assert fields["classification"] == "malicious"
        assert fields["is_noise"] is True
        assert fields["is_riot"] is False


class TestMalwareBazaarAdapter:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="")
    def test_parse_response(self, mock_key):
        adapter = MalwareBazaarAdapter()
        raw = {
            "data": [{
                "signature": "Emotet",
                "file_type": "exe",
                "file_size": 245760,
                "file_name": "invoice.exe",
                "first_seen": "2024-01-01",
                "last_seen": "2024-01-15",
                "delivery_method": "email_attachment",
                "tags": ["emotet", "banker"],
                "reporter": "abuse_ch",
            }]
        }
        results = adapter._parse_response(raw, "hash_sha256", None)
        fields = {r.field_name: r.value for r in results if r.status == ResultStatus.FOUND}
        assert fields["malware_family"] == "Emotet"
        assert fields["file_type"] == "exe"
        assert "emotet" in fields["tags"]


class TestURLhausAdapter:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="")
    def test_build_request_url(self, mock_key):
        adapter = URLhausAdapter()
        req = adapter._build_request("https://evil.com/malware.exe", "url")
        assert req["method"] == "POST"
        assert req["data"]["url"] == "https://evil.com/malware.exe"

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="")
    def test_build_request_domain(self, mock_key):
        adapter = URLhausAdapter()
        req = adapter._build_request("evil.com", "domain")
        assert req["data"]["host"] == "evil.com"


class TestBaseAdapterErrorHandling:
    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_timeout_marks_fields(self, mock_key):
        adapter = AbuseIPDBAdapter()
        import requests

        with patch.object(adapter.session, "request", side_effect=requests.Timeout):
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence", "country"])
            assert not response.success
            assert "Timeout" in response.error
            assert all(r.status == ResultStatus.TIMEOUT for r in response.results)

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_connection_error_marks_fields(self, mock_key):
        adapter = AbuseIPDBAdapter()
        import requests

        with patch.object(adapter.session, "request", side_effect=requests.ConnectionError):
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence"])
            assert not response.success
            assert all(r.status == ResultStatus.ERROR for r in response.results)

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_rate_limit_429(self, mock_key):
        adapter = AbuseIPDBAdapter()
        mock_resp = _mock_response(429)
        mock_resp.headers = {"Retry-After": "60"}

        with patch.object(adapter.session, "request", return_value=mock_resp):
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence"])
            assert not response.success
            assert "Rate limit" in response.error

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_successful_query(self, mock_key):
        adapter = AbuseIPDBAdapter()
        mock_resp = _mock_response(200, {
            "data": {
                "abuseConfidenceScore": 50,
                "countryCode": "US",
            }
        })

        with patch.object(adapter.session, "request", return_value=mock_resp):
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence", "country_code"])
            assert response.success
            assert response.response_time_ms >= 0
            assert len(response.results) > 0


class TestBaseAdapterReliability:
    """New reliability behaviors: 429 retry, 404-as-no-data, missing-key skip."""

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_429_with_short_retry_after_retries_once(self, mock_key):
        adapter = AbuseIPDBAdapter()
        rate_limited = _mock_response(429)
        rate_limited.headers = {"Retry-After": "1"}
        ok = _mock_response(200, {"data": {"abuseConfidenceScore": 10, "countryCode": "US"}})

        with patch.object(adapter.session, "request", side_effect=[rate_limited, ok]) as mock_req, \
             patch("apps.investigations.engine.base_adapter.time.sleep") as mock_sleep:
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence"])

        assert response.success
        assert mock_req.call_count == 2
        mock_sleep.assert_called_once_with(1)

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_429_with_long_retry_after_fails_fast(self, mock_key):
        adapter = AbuseIPDBAdapter()
        rate_limited = _mock_response(429)
        rate_limited.headers = {"Retry-After": "300"}

        with patch.object(adapter.session, "request", return_value=rate_limited) as mock_req:
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence"])

        assert not response.success
        assert "Rate limit" in response.error
        assert mock_req.call_count == 1

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_404_not_found_is_valid_reports_fields_as_not_found(self, mock_key):
        adapter = GreyNoiseAdapter()  # NOT_FOUND_IS_VALID = True
        with patch.object(adapter.session, "request", return_value=_mock_response(404)):
            response = adapter.query("10.1.2.3", "ip", expected_fields=["classification", "is_noise"])

        assert response.success
        assert not response.error
        assert {r.field_name for r in response.results} == {"classification", "is_noise"}
        assert all(r.status == ResultStatus.NOT_FOUND for r in response.results)

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="")
    def test_missing_api_key_skips_without_error_rows(self, mock_key):
        adapter = AbuseIPDBAdapter()  # REQUIRES_API_KEY = True
        with patch.object(adapter.session, "request") as mock_req:
            response = adapter.query("8.8.8.8", "ip", expected_fields=["abuse_confidence"])

        mock_req.assert_not_called()
        assert not response.success
        assert "not configured" in response.error
        assert response.results == []

    @patch("apps.investigations.engine.base_adapter.BaseAdapter._get_api_key", return_value="test-key")
    def test_session_mounts_retry_adapter(self, mock_key):
        adapter = AbuseIPDBAdapter()
        https_adapter = adapter.session.get_adapter("https://example.com")
        retries = https_adapter.max_retries
        assert retries.total == 2
        assert 503 in retries.status_forcelist
        assert retries.raise_on_status is False


class TestAbuseChAuthKey:
    """abuse.ch made API authentication mandatory — the shared ABUSECH_AUTH_KEY
    must reach all three family adapters as an Auth-Key header."""

    def test_reads_shared_abusech_key(self, settings):
        settings.THREAT_INTEL_KEYS = {"abusech": "shared-key-123"}
        from apps.investigations.engine.adapters.abusech import (
            MalwareBazaarAdapter, ThreatFoxAdapter, URLhausAdapter,
        )
        for cls in (ThreatFoxAdapter, URLhausAdapter, MalwareBazaarAdapter):
            adapter = cls()
            assert adapter.api_key == "shared-key-123", cls.__name__

    def test_auth_key_header_sent(self, settings):
        settings.THREAT_INTEL_KEYS = {"abusech": "shared-key-123"}
        from apps.investigations.engine.adapters.abusech import (
            MalwareBazaarAdapter, ThreatFoxAdapter, URLhausAdapter,
        )
        requests_built = [
            ThreatFoxAdapter()._build_request("8.8.8.8", "ip"),
            URLhausAdapter()._build_request("https://evil.com/x", "url"),
            MalwareBazaarAdapter()._build_request("a" * 64, "hash_sha256"),
        ]
        for req in requests_built:
            assert req["headers"]["Auth-Key"] == "shared-key-123"

    def test_skipped_cleanly_without_key(self, settings):
        settings.THREAT_INTEL_KEYS = {}
        from apps.investigations.engine.adapters.abusech import ThreatFoxAdapter
        adapter = ThreatFoxAdapter()
        assert adapter.REQUIRES_API_KEY is True
        with patch.object(adapter.session, "request") as mock_req:
            response = adapter.query("8.8.8.8", "ip", expected_fields=["threat_type"])
        mock_req.assert_not_called()
        assert "not configured" in response.error
