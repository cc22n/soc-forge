"""
IOC validators for SOC Forge.
Validate format of indicators before processing.

Usage:
    from apps.core.validators import validate_ioc, detect_ioc_type
"""

import ipaddress
import re
from ipaddress import IPv4Address, IPv6Address

from django.core.exceptions import ValidationError

_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local
    ipaddress.IPv4Network("100.64.0.0/10"),     # shared address space
    ipaddress.IPv4Network("0.0.0.0/8"),         # "this" network
    ipaddress.IPv4Network("224.0.0.0/4"),       # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),       # reserved
    ipaddress.IPv6Network("::1/128"),           # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),          # IPv6 unique local
    ipaddress.IPv6Network("fe80::/10"),         # IPv6 link-local
]

# Compiled patterns for performance
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
URL_PATTERN = re.compile(r"^https?://")


def validate_md5(value: str) -> None:
    """Validate MD5 hash format (32 hex characters)."""
    if not MD5_PATTERN.match(value):
        raise ValidationError(
            "Invalid MD5 hash format. Expected 32 hexadecimal characters.",
            code="invalid_md5",
        )


def validate_sha1(value: str) -> None:
    """Validate SHA1 hash format (40 hex characters)."""
    if not SHA1_PATTERN.match(value):
        raise ValidationError(
            "Invalid SHA1 hash format. Expected 40 hexadecimal characters.",
            code="invalid_sha1",
        )


def validate_sha256(value: str) -> None:
    """Validate SHA256 hash format (64 hex characters)."""
    if not SHA256_PATTERN.match(value):
        raise ValidationError(
            "Invalid SHA256 hash format. Expected 64 hexadecimal characters.",
            code="invalid_sha256",
        )


def validate_ip(value: str) -> None:
    """Validate IPv4 or IPv6 address format and reject private/reserved ranges."""
    try:
        addr = IPv4Address(value)
        ip_obj = ipaddress.IPv4Address(value)
    except ValueError:
        try:
            addr = IPv6Address(value)
            ip_obj = ipaddress.IPv6Address(value)
        except ValueError:
            raise ValidationError(
                "Invalid IP address format.",
                code="invalid_ip",
            )
    for network in _PRIVATE_NETWORKS:
        if ip_obj in network:
            raise ValidationError(
                f"IP {value} is in a private or reserved range and cannot be queried against external threat intelligence sources.",
                code="private_ip",
            )


def validate_domain(value: str) -> None:
    """Validate domain name format."""
    if not DOMAIN_PATTERN.match(value):
        raise ValidationError(
            "Invalid domain format.",
            code="invalid_domain",
        )


def validate_url(value: str) -> None:
    """Validate URL format (must start with http:// or https://)."""
    if not URL_PATTERN.match(value):
        raise ValidationError(
            "Invalid URL format. Must start with http:// or https://",
            code="invalid_url",
        )


# Map IOC types to their validators
IOC_VALIDATORS = {
    "hash_md5": validate_md5,
    "hash_sha1": validate_sha1,
    "hash_sha256": validate_sha256,
    "ip": validate_ip,
    "domain": validate_domain,
    "url": validate_url,
}


def validate_ioc(value: str, ioc_type: str) -> None:
    """
    Validate an IOC value against its declared type.

    Args:
        value: The indicator value to validate
        ioc_type: One of IOCType choices (hash_md5, ip, domain, etc.)

    Raises:
        ValidationError: If the value doesn't match the expected format
    """
    validator = IOC_VALIDATORS.get(ioc_type)
    if validator:
        validator(value)
    else:
        raise ValidationError(f"Unknown IOC type: {ioc_type}")


def detect_ioc_type(value: str) -> str | None:
    """
    Auto-detect the IOC type from a raw string value.
    Returns the IOCType value or None if unrecognizable.

    Useful for when analysts paste an indicator without specifying its type.
    """
    value = value.strip()

    # Check URL first (before domain, since URLs contain domains)
    if URL_PATTERN.match(value):
        return "url"

    # Check hashes by length
    if SHA256_PATTERN.match(value):
        return "hash_sha256"
    if SHA1_PATTERN.match(value):
        return "hash_sha1"
    if MD5_PATTERN.match(value):
        return "hash_md5"

    # Check IP
    try:
        IPv4Address(value)
        return "ip"
    except ValueError:
        pass
    try:
        IPv6Address(value)
        return "ip"
    except ValueError:
        pass

    # Check domain
    if DOMAIN_PATTERN.match(value):
        return "domain"

    return None
