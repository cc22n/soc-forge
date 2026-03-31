"""
Shared fixtures for SOC Forge test suite.
"""

import pytest
from django.test import Client

_LOCMEM_CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    "rate_limit": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "rate_limit",
    },
}


@pytest.fixture(autouse=True)
def use_locmem_cache(settings):
    """Force LocMemCache for all tests — no Redis required."""
    settings.CACHES = _LOCMEM_CACHES

from apps.core.enums import IOCType, UserRole
from apps.users.models import User


@pytest.fixture
def analyst_user(db):
    """Create a standard analyst user."""
    return User.objects.create_user(
        username="analyst1",
        password="TestPass1234!",
        email="analyst1@socforge.test",
        role=UserRole.ANALYST,
    )


@pytest.fixture
def admin_user(db):
    """Create an admin user."""
    return User.objects.create_user(
        username="admin1",
        password="AdminPass1234!",
        email="admin1@socforge.test",
        role=UserRole.ADMIN,
        is_staff=True,
    )

@pytest.fixture
def auth_client(analyst_user):
    """Return a Django test client logged in as analyst."""
    client = Client()
    # Usamos force_login para saltarnos las validaciones de django-axes
    client.force_login(analyst_user)
    return client


@pytest.fixture
def admin_client(admin_user):
    """Return a Django test client logged in as admin."""
    client = Client()
    # Usamos force_login para saltarnos las validaciones de django-axes
    client.force_login(admin_user)
    return client



@pytest.fixture
def sample_sources(db):
    """Create a minimal set of test sources."""
    from apps.sources.models import AvailableField, Source

    vt = Source.objects.create(
        name="VirusTotal",
        slug="virustotal",
        base_url="https://www.virustotal.com/api/v3",
        auth_type="header",
        supported_ioc_types=["hash", "ip", "domain", "url"],
        rate_limit_per_minute=4,
        default_ttl_seconds=86400,
        priority=1,
    )
    abuse = Source.objects.create(
        name="AbuseIPDB",
        slug="abuseipdb",
        base_url="https://api.abuseipdb.com/api/v2",
        auth_type="header",
        supported_ioc_types=["ip"],
        rate_limit_per_minute=17,
        default_ttl_seconds=43200,
        priority=2,
    )

    # Add some available fields
    AvailableField.objects.create(
        source=vt, ioc_type="ip", normalized_name="detection_ratio",
        api_field_path="last_analysis_stats", classification="required",
    )
    AvailableField.objects.create(
        source=vt, ioc_type="ip", normalized_name="country",
        api_field_path="country", classification="core",
    )
    AvailableField.objects.create(
        source=abuse, ioc_type="ip", normalized_name="abuse_confidence",
        api_field_path="data.abuseConfidenceScore", classification="required",
    )
    AvailableField.objects.create(
        source=abuse, ioc_type="ip", normalized_name="country_code",
        api_field_path="data.countryCode", classification="core",
    )

    return {"virustotal": vt, "abuseipdb": abuse}


@pytest.fixture
def sample_profile(db, analyst_user, sample_sources):
    """Create a test investigation profile with sources and expected fields."""
    from apps.profiles.models import (
        ExpectedField,
        InvestigationProfile,
        ProfileSourceConfig,
    )
    from apps.sources.models import AvailableField

    profile = InvestigationProfile.objects.create(
        owner=analyst_user,
        name="Test IP Profile",
        ioc_type="ip",
        description="Test profile for IP investigations",
    )

    # Add VT source config
    vt_config = ProfileSourceConfig.objects.create(
        profile=profile,
        source=sample_sources["virustotal"],
        priority=1,
    )
    for af in AvailableField.objects.filter(source=sample_sources["virustotal"], ioc_type="ip"):
        ExpectedField.objects.create(
            profile_source=vt_config,
            available_field=af,
            is_required=(af.classification == "required"),
        )

    # Add AbuseIPDB source config
    abuse_config = ProfileSourceConfig.objects.create(
        profile=profile,
        source=sample_sources["abuseipdb"],
        priority=2,
    )
    for af in AvailableField.objects.filter(source=sample_sources["abuseipdb"], ioc_type="ip"):
        ExpectedField.objects.create(
            profile_source=abuse_config,
            available_field=af,
            is_required=(af.classification == "required"),
        )

    return profile
