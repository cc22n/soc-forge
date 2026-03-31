"""
Tests for apps.investigations.engine.transforms — field normalization functions.
"""

import pytest

from apps.investigations.engine.transforms import (
    apply_transform,
    transform_epoch_to_iso,
    transform_ipinfo_asn,
    transform_ipinfo_loc_lat,
    transform_ipinfo_loc_lng,
    transform_safebrowsing_verdict,
    transform_shodan_services,
    transform_vt_detection_ratio,
)


class TestVTDetectionRatio:
    def test_normal_stats(self):
        stats = {"malicious": 45, "undetected": 20, "suspicious": 2, "harmless": 3, "timeout": 0, "failure": 0}
        assert transform_vt_detection_ratio(stats) == "45/70"

    def test_zero_total(self):
        stats = {"malicious": 0, "undetected": 0, "suspicious": 0, "harmless": 0, "timeout": 0, "failure": 0}
        assert transform_vt_detection_ratio(stats) is None

    def test_clean_file(self):
        stats = {"malicious": 0, "undetected": 5, "suspicious": 0, "harmless": 65, "timeout": 0, "failure": 0}
        assert transform_vt_detection_ratio(stats) == "0/70"

    def test_invalid_input_string(self):
        assert transform_vt_detection_ratio("not a dict") is None

    def test_invalid_input_none(self):
        assert transform_vt_detection_ratio(None) is None


class TestEpochToISO:
    def test_valid_epoch(self):
        result = transform_epoch_to_iso(1700000000)
        assert "2023-11-14" in result
        assert "T" in result

    def test_string_epoch(self):
        result = transform_epoch_to_iso("1700000000")
        assert "2023-11-14" in result

    def test_none_input(self):
        assert transform_epoch_to_iso(None) is None

    def test_invalid_string(self):
        result = transform_epoch_to_iso("not-a-timestamp")
        assert result == "not-a-timestamp"


class TestSafeBrowsingVerdict:
    def test_matches_found(self):
        assert transform_safebrowsing_verdict([{"threatType": "MALWARE"}]) == "malicious"

    def test_no_matches(self):
        assert transform_safebrowsing_verdict([]) == "clean"

    def test_none_matches(self):
        assert transform_safebrowsing_verdict(None) == "clean"


class TestShodanServices:
    def test_normal_data(self):
        data = [
            {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18"},
        ]
        result = transform_shodan_services(data)
        assert len(result) == 2
        assert result[0]["port"] == 80
        assert result[1]["product"] == "nginx"

    def test_limits_to_20(self):
        data = [{"port": i, "transport": "tcp"} for i in range(30)]
        result = transform_shodan_services(data)
        assert len(result) == 20

    def test_invalid_input(self):
        assert transform_shodan_services("not a list") is None

    def test_none_input(self):
        assert transform_shodan_services(None) is None


class TestIPInfoTransforms:
    def test_asn_extraction(self):
        assert transform_ipinfo_asn("AS13335 Cloudflare, Inc.") == "AS13335"

    def test_asn_no_prefix(self):
        assert transform_ipinfo_asn("Cloudflare") == "Cloudflare"

    def test_asn_none(self):
        assert transform_ipinfo_asn(None) is None

    def test_lat_extraction(self):
        assert transform_ipinfo_loc_lat("37.7749,-122.4194") == pytest.approx(37.7749)

    def test_lng_extraction(self):
        assert transform_ipinfo_loc_lng("37.7749,-122.4194") == pytest.approx(-122.4194)

    def test_loc_none(self):
        assert transform_ipinfo_loc_lat(None) is None
        assert transform_ipinfo_loc_lng(None) is None

    def test_loc_no_comma(self):
        assert transform_ipinfo_loc_lat("invalid") is None


class TestApplyTransform:
    def test_known_transform(self):
        result = apply_transform("transform_safebrowsing_verdict", [])
        assert result == "clean"

    def test_unknown_transform(self):
        assert apply_transform("nonexistent_function", "value") == "value"

    def test_empty_name(self):
        assert apply_transform("", "value") == "value"

    def test_none_name(self):
        assert apply_transform(None, "value") == "value"
