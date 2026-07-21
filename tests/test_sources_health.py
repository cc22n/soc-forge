"""
Tests for the adapter health dashboard (apps/sources/views.py:source_health).

Covers: role-gating (admin-only), sources with zero results surfacing as
"no_data" instead of disappearing, and the found/not_found/error split driving
the health label (not_found must never read as broken).
"""

import pytest
from django.urls import reverse

from apps.core.enums import ResultStatus
from apps.investigations.models import Indicator, Investigation, InvestigationResult


@pytest.fixture
def sample_investigation(db, analyst_user, sample_profile):
    """Minimal Investigation with a linked Indicator, to attach results to."""
    indicator = Indicator.objects.create(value="8.8.8.8", ioc_type="ip", created_by=analyst_user)
    return Investigation.objects.create(
        analyst=analyst_user,
        indicator=indicator,
        profile_used=sample_profile,
        status="completed",
        coverage_score=75.0,
    )


def _result(investigation, source, status, response_time_ms=100):
    return InvestigationResult.objects.create(
        investigation=investigation,
        source=source,
        field_name="test_field",
        value="x",
        status=status,
        response_time_ms=response_time_ms,
    )


def _rows_by_slug(response):
    return {row["source"].slug: row for row in response.context["sources"]}


class TestSourceHealthAccess:
    """Health panel is the first admin-only-gated view in the project."""

    def url(self):
        return reverse("sources:health")

    def test_requires_login(self, client):
        response = client.get(self.url())
        assert response.status_code == 302
        assert "/auth/login/" in response.url

    def test_analyst_is_denied(self, auth_client):
        response = auth_client.get(self.url())
        assert response.status_code == 302
        assert "/auth/login/" in response.url

    def test_admin_is_allowed(self, admin_client):
        response = admin_client.get(self.url())
        assert response.status_code == 200


class TestSourceHealthData:
    def url(self):
        return reverse("sources:health")

    def test_source_with_no_results_shows_as_no_data(self, admin_client, sample_sources):
        """A source that never left a row (missing key, dropped by global timeout)
        must still be listed, not silently omitted."""
        response = admin_client.get(self.url())
        rows = _rows_by_slug(response)
        assert rows["virustotal"]["health"] == "no_data"
        assert rows["abuseipdb"]["health"] == "no_data"

    def test_mostly_errors_marks_source_down(self, admin_client, sample_sources, sample_investigation):
        vt = sample_sources["virustotal"]
        for _ in range(8):
            _result(sample_investigation, vt, ResultStatus.ERROR)
        for _ in range(2):
            _result(sample_investigation, vt, ResultStatus.FOUND)

        response = admin_client.get(self.url())
        rows = _rows_by_slug(response)
        assert rows["virustotal"]["health"] == "down"
        assert rows["virustotal"]["total"] == 10
        assert rows["virustotal"]["errors"] == 8

    def test_mostly_not_found_is_healthy_not_down(self, admin_client, sample_sources, sample_investigation):
        """NOT_FOUND means the source works but has no data for this IOC — it
        must not be conflated with a real failure."""
        abuse = sample_sources["abuseipdb"]
        for _ in range(9):
            _result(sample_investigation, abuse, ResultStatus.NOT_FOUND)
        _result(sample_investigation, abuse, ResultStatus.FOUND)

        response = admin_client.get(self.url())
        rows = _rows_by_slug(response)
        assert rows["abuseipdb"]["health"] == "healthy"
        assert rows["abuseipdb"]["not_found"] == 9
        assert rows["abuseipdb"]["errors"] == 0

    def test_avg_response_time_and_counts(self, admin_client, sample_sources, sample_investigation):
        vt = sample_sources["virustotal"]
        _result(sample_investigation, vt, ResultStatus.FOUND, response_time_ms=100)
        _result(sample_investigation, vt, ResultStatus.FOUND, response_time_ms=200)

        response = admin_client.get(self.url())
        rows = _rows_by_slug(response)
        assert rows["virustotal"]["total"] == 2
        assert rows["virustotal"]["found"] == 2
        assert rows["virustotal"]["avg_ms"] == 150
