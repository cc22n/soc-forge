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
