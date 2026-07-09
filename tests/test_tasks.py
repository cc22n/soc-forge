"""
Tests for the async investigation flow (dispatch + Celery task).

The task is executed eagerly with .apply() — no broker required.
Adapters are mocked; no real API calls are made.
"""

import pytest
from unittest.mock import MagicMock, patch

from apps.core.enums import InvestigationStatus, ResultStatus
from apps.investigations.engine.base_adapter import AdapterResponse, AdapterResult
from apps.investigations.models import Investigation
from apps.investigations.tasks import dispatch_investigation, run_investigation_task


def _mock_get_adapter(slug):
    adapter = MagicMock()
    adapter.supports.return_value = True
    resp = AdapterResponse()
    resp.success = True
    resp.response_time_ms = 50
    resp.results = [AdapterResult("abuse_confidence", 10, ResultStatus.FOUND)]
    adapter.query.return_value = resp
    return adapter


@pytest.mark.django_db
class TestDispatchInvestigation:

    def test_creates_pending_placeholder_and_queues_task(self, analyst_user, sample_profile):
        with patch.object(run_investigation_task, "apply_async") as mock_apply:
            investigation = dispatch_investigation(analyst_user, "8.8.8.8", sample_profile)

        assert investigation.status == InvestigationStatus.PENDING
        assert investigation.indicator.value == "8.8.8.8"
        mock_apply.assert_called_once()
        assert mock_apply.call_args.kwargs["kwargs"] == {"investigation_id": investigation.pk}
        assert mock_apply.call_args.kwargs["task_id"] == f"inv-{investigation.pk}"

    def test_broker_down_falls_back_to_sync_reusing_placeholder(self, analyst_user, sample_profile):
        with patch.object(run_investigation_task, "apply_async", side_effect=OSError("broker down")), \
             patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=_mock_get_adapter):
            investigation = dispatch_investigation(analyst_user, "8.8.8.8", sample_profile)

        # Same record completed in place — no duplicate Investigation
        assert Investigation.objects.count() == 1
        investigation.refresh_from_db()
        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.completed_at is not None


@pytest.mark.django_db(transaction=False)
class TestRunInvestigationTask:

    def test_task_completes_the_placeholder_in_place(self, analyst_user, sample_profile):
        with patch.object(run_investigation_task, "apply_async"):
            placeholder = dispatch_investigation(analyst_user, "8.8.8.8", sample_profile)
        assert placeholder.status == InvestigationStatus.PENDING

        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=_mock_get_adapter):
            result = run_investigation_task.apply(
                args=[analyst_user.pk, "8.8.8.8", sample_profile.pk],
                kwargs={"investigation_id": placeholder.pk},
            ).get()

        assert result["investigation_id"] == placeholder.pk
        assert Investigation.objects.count() == 1  # reused, not duplicated
        placeholder.refresh_from_db()
        assert placeholder.status in (InvestigationStatus.COMPLETED, InvestigationStatus.PARTIAL)
        assert placeholder.completed_at is not None

    def test_task_without_placeholder_creates_investigation(self, analyst_user, sample_profile):
        with patch("apps.investigations.engine.orchestrator.get_adapter", side_effect=_mock_get_adapter):
            result = run_investigation_task.apply(
                args=[analyst_user.pk, "9.9.9.9", sample_profile.pk],
            ).get()

        investigation = Investigation.objects.get(pk=result["investigation_id"])
        assert investigation.status in (InvestigationStatus.COMPLETED, InvestigationStatus.PARTIAL)
