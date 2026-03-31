"""
Tests for InvestigationOrchestrator — full investigation flow with mocked adapters.
"""

import pytest
from unittest.mock import patch, MagicMock

from apps.core.enums import InvestigationStatus, ResultStatus
from apps.investigations.engine.base_adapter import AdapterResponse, AdapterResult
from apps.investigations.engine.orchestrator import InvestigationOrchestrator
from apps.investigations.models import Indicator, Investigation, InvestigationResult


def _make_adapter_response(fields_data, success=True, error=""):
    """Helper to create a mock AdapterResponse."""
    resp = AdapterResponse()
    resp.success = success
    resp.error = error
    resp.response_time_ms = 100
    for name, value, status in fields_data:
        resp.results.append(AdapterResult(name, value, status))
    return resp


@pytest.mark.django_db
class TestOrchestrator:

    def test_successful_investigation(self, analyst_user, sample_profile):
        """Test a full investigation with mocked adapter responses."""
        vt_response = _make_adapter_response([
            ("detection_ratio", "5/70", ResultStatus.FOUND),
            ("country", "US", ResultStatus.FOUND),
        ])
        abuse_response = _make_adapter_response([
            ("abuse_confidence", 25, ResultStatus.FOUND),
            ("country_code", "US", ResultStatus.FOUND),
        ])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            if slug == "virustotal":
                adapter.query.return_value = vt_response
            elif slug == "abuseipdb":
                adapter.query.return_value = abuse_response
            else:
                return None
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            orchestrator = InvestigationOrchestrator()
            investigation = orchestrator.run(analyst_user, "8.8.8.8", sample_profile)

        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.coverage_score > 0
        assert investigation.started_at is not None
        assert investigation.completed_at is not None

        # Check results were saved
        results = InvestigationResult.objects.filter(investigation=investigation)
        assert results.count() == 4
        found_count = results.filter(status=ResultStatus.FOUND).count()
        assert found_count == 4

    def test_partial_failure(self, analyst_user, sample_profile):
        """Test investigation where one source fails."""
        vt_response = _make_adapter_response(
            [("detection_ratio", None, ResultStatus.ERROR), ("country", None, ResultStatus.ERROR)],
            success=False,
            error="HTTP 500",
        )
        abuse_response = _make_adapter_response([
            ("abuse_confidence", 90, ResultStatus.FOUND),
            ("country_code", "DE", ResultStatus.FOUND),
        ])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            if slug == "virustotal":
                adapter.query.return_value = vt_response
            elif slug == "abuseipdb":
                adapter.query.return_value = abuse_response
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            orchestrator = InvestigationOrchestrator()
            investigation = orchestrator.run(analyst_user, "185.220.101.50", sample_profile)

        assert investigation.status == InvestigationStatus.PARTIAL
        assert investigation.error_detail != ""

    def test_creates_indicator(self, analyst_user, sample_profile):
        """Test that an Indicator record is created."""
        empty_response = _make_adapter_response([])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            adapter.query.return_value = empty_response
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            orchestrator = InvestigationOrchestrator()
            orchestrator.run(analyst_user, "1.1.1.1", sample_profile)

        indicator = Indicator.objects.get(value="1.1.1.1")
        assert indicator.ioc_type == "ip"
        assert indicator.times_investigated == 1
        assert indicator.created_by == analyst_user

    def test_increments_investigation_count(self, analyst_user, sample_profile):
        """Test that re-investigating increments the counter."""
        empty_response = _make_adapter_response([])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            adapter.query.return_value = empty_response
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            orchestrator = InvestigationOrchestrator()
            orchestrator.run(analyst_user, "8.8.8.8", sample_profile)
            orchestrator.run(analyst_user, "8.8.8.8", sample_profile)

        indicator = Indicator.objects.get(value="8.8.8.8")
        assert indicator.times_investigated == 2

    def test_invalid_ioc_raises(self, analyst_user, sample_profile):
        """Test that invalid IOC format raises an error."""
        orchestrator = InvestigationOrchestrator()
        with pytest.raises(Exception):
            orchestrator.run(analyst_user, "not-a-valid-ip", sample_profile)

    def test_no_adapter_skips_source(self, analyst_user, sample_profile):
        """Test that missing adapters are skipped gracefully."""

        def mock_get_adapter(slug):
            return None  # No adapter for any source

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            orchestrator = InvestigationOrchestrator()
            investigation = orchestrator.run(analyst_user, "8.8.4.4", sample_profile)

        # Should complete but with no results
        assert investigation.status in (InvestigationStatus.COMPLETED, InvestigationStatus.ERROR)
        assert InvestigationResult.objects.filter(investigation=investigation).count() == 0
