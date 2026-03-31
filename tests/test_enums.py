"""
Tests for apps.core.enums — IOC type mapping and enum behavior.
"""

import pytest
from apps.core.enums import IOCType


class TestIOCTypeGeneralMapping:
    """Test get_general_type handles both strings and enum members."""

    def test_hash_md5_string(self):
        assert IOCType.get_general_type("hash_md5") == "hash"

    def test_hash_sha1_string(self):
        assert IOCType.get_general_type("hash_sha1") == "hash"

    def test_hash_sha256_string(self):
        assert IOCType.get_general_type("hash_sha256") == "hash"

    def test_ip_string(self):
        assert IOCType.get_general_type("ip") == "ip"

    def test_domain_string(self):
        assert IOCType.get_general_type("domain") == "domain"

    def test_url_string(self):
        assert IOCType.get_general_type("url") == "url"

    def test_hash_md5_enum(self):
        assert IOCType.get_general_type(IOCType.HASH_MD5) == "hash"

    def test_hash_sha256_enum(self):
        assert IOCType.get_general_type(IOCType.HASH_SHA256) == "hash"

    def test_ip_enum(self):
        assert IOCType.get_general_type(IOCType.IP) == "ip"

    def test_domain_enum(self):
        assert IOCType.get_general_type(IOCType.DOMAIN) == "domain"


class TestIOCTypeHelpers:
    def test_hash_types(self):
        ht = IOCType.hash_types()
        assert IOCType.HASH_MD5 in ht
        assert IOCType.HASH_SHA1 in ht
        assert IOCType.HASH_SHA256 in ht
        assert IOCType.IP not in ht

    def test_choices_exist(self):
        choices = IOCType.choices
        assert len(choices) == 6
        values = [c[0] for c in choices]
        assert "ip" in values
        assert "hash_sha256" in values
