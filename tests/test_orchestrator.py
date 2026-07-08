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

    def test_missing_api_key_source_skipped_cleanly(self, analyst_user, sample_profile):
        """An unconfigured source must not degrade the investigation to PARTIAL."""
        abuse_response = _make_adapter_response([
            ("abuse_confidence", 90, ResultStatus.FOUND),
            ("country_code", "DE", ResultStatus.FOUND),
        ])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            if slug == "virustotal":
                adapter.REQUIRES_API_KEY = True
                adapter.api_key = ""  # not configured
            else:
                adapter.query.return_value = abuse_response
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            investigation = InvestigationOrchestrator().run(analyst_user, "8.8.8.8", sample_profile)

        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.error_detail == ""
        # Coverage counts only the consulted source's fields: 2/2 found
        assert investigation.coverage_score == 100.0
        assert InvestigationResult.objects.filter(
            investigation=investigation, source__slug="virustotal"
        ).count() == 0

    def test_global_timeout_keeps_finished_results(self, analyst_user, sample_profile, monkeypatch):
        """When the global budget is exceeded, finished sources are kept and the
        investigation completes as PARTIAL instead of losing everything."""
        import time as _time

        monkeypatch.setattr(
            "apps.investigations.engine.orchestrator.GLOBAL_TIMEOUT_SECONDS", 1
        )

        abuse_response = _make_adapter_response([
            ("abuse_confidence", 75, ResultStatus.FOUND),
            ("country_code", "RU", ResultStatus.FOUND),
        ])

        def slow_query(**kwargs):
            _time.sleep(3)
            return _make_adapter_response([])

        def mock_get_adapter(slug):
            adapter = MagicMock()
            adapter.supports.return_value = True
            if slug == "virustotal":
                adapter.query.side_effect = slow_query
            else:
                adapter.query.return_value = abuse_response
            return adapter

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=mock_get_adapter):
            investigation = InvestigationOrchestrator().run(analyst_user, "9.9.9.9", sample_profile)

        assert investigation.status == InvestigationStatus.PARTIAL
        assert "investigation budget" in investigation.error_detail
        # The fast source's results were persisted, not lost
        assert InvestigationResult.objects.filter(
            investigation=investigation, source__slug="abuseipdb",
            status=ResultStatus.FOUND,
        ).count() == 2
        # Let the straggler thread finish before DB teardown
        _time.sleep(2.5)


class TestSourceRateLimitThrottle:
    """Unit tests for the local per-source throttle."""

    def _source(self, slug="pulsedive", rpm=1):
        from types import SimpleNamespace
        return SimpleNamespace(slug=slug, rate_limit_per_minute=rpm)

    def test_disabled_via_settings(self, settings):
        from apps.investigations.engine.orchestrator import _wait_for_rate_limit
        settings.SOURCE_RATE_LIMIT_ENABLED = False
        assert _wait_for_rate_limit(self._source()) == ""

    def test_first_query_passes_and_records_timestamp(self, settings):
        import time as _time
        from django.core.cache import caches
        from apps.investigations.engine.orchestrator import _wait_for_rate_limit

        settings.SOURCE_RATE_LIMIT_ENABLED = True
        cache = caches["rate_limit"]
        cache.delete("source-last-query:pulsedive")

        assert _wait_for_rate_limit(self._source()) == ""
        assert cache.get("source-last-query:pulsedive") == pytest.approx(_time.time(), abs=5)

    def test_skips_when_wait_exceeds_cap(self, settings):
        import time as _time
        from django.core.cache import caches
        from apps.investigations.engine.orchestrator import _wait_for_rate_limit

        settings.SOURCE_RATE_LIMIT_ENABLED = True
        # 1/min → 60s interval; last query just now → wait ~60s > 45s cap
        caches["rate_limit"].set("source-last-query:pulsedive", _time.time())

        msg = _wait_for_rate_limit(self._source(rpm=1))
        assert "rate limit" in msg

    def test_sleeps_for_short_waits(self, settings):
        import time as _time
        from django.core.cache import caches
        from apps.investigations.engine.orchestrator import _wait_for_rate_limit

        settings.SOURCE_RATE_LIMIT_ENABLED = True
        # 30/min → 2s interval; last query just now → short wait, sleeps
        caches["rate_limit"].set("source-last-query:fastsrc", _time.time())

        with patch("apps.investigations.engine.orchestrator.time.sleep") as mock_sleep:
            msg = _wait_for_rate_limit(self._source(slug="fastsrc", rpm=30))

        assert msg == ""
        mock_sleep.assert_called_once()
        assert 0 < mock_sleep.call_args[0][0] <= 2
