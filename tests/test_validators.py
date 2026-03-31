"""
Tests for apps.core.validators — IOC validation and auto-detection.
"""

import pytest
from django.core.exceptions import ValidationError

from apps.core.validators import (
    detect_ioc_type,
    validate_domain,
    validate_ioc,
    validate_ip,
    validate_md5,
    validate_sha1,
    validate_sha256,
    validate_url,
)


class TestMD5Validation:
    def test_valid_md5(self):
        validate_md5("d41d8cd98f00b204e9800998ecf8427e")

    def test_valid_md5_uppercase(self):
        validate_md5("D41D8CD98F00B204E9800998ECF8427E")

    def test_invalid_md5_too_short(self):
        with pytest.raises(ValidationError):
            validate_md5("d41d8cd98f00b204")

    def test_invalid_md5_too_long(self):
        with pytest.raises(ValidationError):
            validate_md5("d41d8cd98f00b204e9800998ecf8427e00")

    def test_invalid_md5_non_hex(self):
        with pytest.raises(ValidationError):
            validate_md5("g41d8cd98f00b204e9800998ecf8427e")


class TestSHA1Validation:
    def test_valid_sha1(self):
        validate_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_invalid_sha1_wrong_length(self):
        with pytest.raises(ValidationError):
            validate_sha1("da39a3ee5e6b4b0d3255bfef")


class TestSHA256Validation:
    def test_valid_sha256(self):
        validate_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_invalid_sha256_wrong_length(self):
        with pytest.raises(ValidationError):
            validate_sha256("e3b0c44298fc1c149afbf4c8")


class TestIPValidation:
    def test_valid_ipv4(self):
        validate_ip("8.8.8.8")

    def test_valid_ipv4_public(self):
        validate_ip("1.1.1.1")

    def test_valid_ipv6(self):
        validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_valid_ipv6_short(self):
        validate_ip("2606:4700:4700::1111")

    def test_private_ipv4_raises(self):
        with pytest.raises(ValidationError):
            validate_ip("192.168.1.1")

    def test_loopback_ipv6_raises(self):
        with pytest.raises(ValidationError):
            validate_ip("::1")

    def test_invalid_ip(self):
        with pytest.raises(ValidationError):
            validate_ip("999.999.999.999")

    def test_invalid_ip_text(self):
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")


class TestDomainValidation:
    def test_valid_domain(self):
        validate_domain("example.com")

    def test_valid_subdomain(self):
        validate_domain("sub.example.com")

    def test_valid_deep_subdomain(self):
        validate_domain("a.b.c.example.com")

    def test_invalid_domain_no_tld(self):
        with pytest.raises(ValidationError):
            validate_domain("example")

    def test_invalid_domain_starts_with_dash(self):
        with pytest.raises(ValidationError):
            validate_domain("-example.com")


class TestURLValidation:
    def test_valid_http(self):
        validate_url("http://example.com")

    def test_valid_https(self):
        validate_url("https://example.com/path?q=1")

    def test_invalid_no_scheme(self):
        with pytest.raises(ValidationError):
            validate_url("example.com")

    def test_invalid_ftp(self):
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com")


class TestValidateIOCDispatcher:
    def test_dispatch_md5(self):
        validate_ioc("d41d8cd98f00b204e9800998ecf8427e", "hash_md5")

    def test_dispatch_ip(self):
        validate_ioc("8.8.8.8", "ip")

    def test_dispatch_domain(self):
        validate_ioc("example.com", "domain")

    def test_dispatch_unknown_type(self):
        with pytest.raises(ValidationError, match="Unknown IOC type"):
            validate_ioc("something", "unknown_type")

    def test_dispatch_type_mismatch(self):
        with pytest.raises(ValidationError):
            validate_ioc("not-a-hash", "hash_md5")


class TestIOCAutoDetection:
    def test_detect_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"

    def test_detect_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash_sha1"

    def test_detect_sha256(self):
        result = detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == "hash_sha256"

    def test_detect_ipv4(self):
        assert detect_ioc_type("8.8.4.4") == "ip"

    def test_detect_ipv6(self):
        assert detect_ioc_type("2001:4860:4860::8888") == "ip"

    def test_detect_domain(self):
        assert detect_ioc_type("malware.example.com") == "domain"

    def test_detect_url(self):
        assert detect_ioc_type("https://evil.com/payload.exe") == "url"

    def test_detect_url_before_domain(self):
        """URLs should be detected before domains since URLs contain domains."""
        assert detect_ioc_type("http://example.com") == "url"

    def test_detect_unknown(self):
        assert detect_ioc_type("random gibberish 123") is None

    def test_detect_strips_whitespace(self):
        assert detect_ioc_type("  8.8.8.8  ") == "ip"
