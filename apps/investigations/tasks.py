"""
Celery tasks for asynchronous investigation execution.

Usage:
    # Dispatch a task (returns immediately with task ID)
    from apps.investigations.tasks import run_investigation_task
    result = run_investigation_task.apply_async(
        args=[user_id, ioc_value, profile_id],
        queue="full_investigation",
    )

    # Poll status via API
    GET /api/investigations/{investigation_pk}/status/
"""

import logging

from celery import shared_task
from django.contrib.auth import get_user_model

from apps.core.enums import InvestigationStatus
from apps.investigations.engine.orchestrator import InvestigationOrchestrator
from apps.investigations.models import Investigation
from apps.profiles.models import InvestigationProfile

logger = logging.getLogger(__name__)
User = get_user_model()

# Queue selection logic:
# - Profiles with ≤3 sources → high_priority (fast response)
# - Everything else         → full_investigation (background)
_HIGH_PRIORITY_MAX_SOURCES = 3


@shared_task(
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    name="apps.investigations.tasks.run_investigation_task",
)
def run_investigation_task(self, user_id: int, ioc_value: str, profile_id: int,
                           investigation_id: int | None = None) -> dict:
    """
    Execute an investigation asynchronously.

    When investigation_id is given (dispatch_investigation flow), the PENDING
    placeholder is reused and completed in place — the caller can keep polling
    the same pk. Otherwise a new Investigation record is created.

    Returns a dict with:
        {"investigation_id": int, "status": str, "coverage_score": float}
    """
    try:
        user = User.objects.get(pk=user_id)
        profile = InvestigationProfile.objects.get(pk=profile_id)
    except (User.DoesNotExist, InvestigationProfile.DoesNotExist) as exc:
        logger.error(f"Task setup failed: {exc}")
        raise

    placeholder = None
    if investigation_id is not None:
        placeholder = Investigation.objects.filter(pk=investigation_id).first()
        if placeholder is None:
            logger.warning("[task:%s] Placeholder investigation #%s missing, creating a new one",
                           self.request.id, investigation_id)

    logger.info("[task:%s] Starting investigation: %s with profile '%s'", self.request.id, ioc_value, profile.name)

    try:
        orchestrator = InvestigationOrchestrator()
        investigation = orchestrator.run(
            user=user, ioc_value=ioc_value, profile=profile, investigation=placeholder,
        )
    except Exception as exc:
        logger.exception("[task:%s] Investigation failed", self.request.id)
        # Out of retries: leave the placeholder in a terminal state so pollers
        # don't wait on a PENDING record forever.
        if placeholder is not None and self.request.retries >= self.max_retries:
            from django.utils import timezone
            placeholder.status = InvestigationStatus.ERROR
            placeholder.error_detail = str(exc)[:2000]
            placeholder.completed_at = timezone.now()
            placeholder.save(update_fields=["status", "error_detail", "completed_at"])
        raise self.retry(exc=exc)

    logger.info(
        "[task:%s] Done — investigation #%d status=%s coverage=%s",
        self.request.id, investigation.pk, investigation.status, investigation.coverage_score,
    )
    return {
        "investigation_id": investigation.pk,
        "status": investigation.status,
        "coverage_score": investigation.coverage_score,
    }


def dispatch_investigation(user, ioc_value: str, profile: InvestigationProfile) -> Investigation:
    """
    Dispatch an investigation task to Celery and return a placeholder Investigation.

    If Celery/Redis is unavailable, falls back to synchronous execution.
    The caller should poll /api/investigations/{pk}/status/ for completion.
    """
    source_count = profile.source_configs.filter(is_enabled=True).count()
    queue = "high_priority" if source_count <= _HIGH_PRIORITY_MAX_SOURCES else "full_investigation"

    # Create a PENDING investigation record first so the caller has a PK to poll.
    # Both the Indicator upsert and the Investigation insert must succeed or
    # both must be rolled back — wrap them in a single atomic block.
    from apps.core.validators import detect_ioc_type
    from apps.investigations.models import Indicator
    from django.db import transaction
    from django.utils import timezone

    ioc_value = ioc_value.strip()
    detected = detect_ioc_type(ioc_value) or profile.ioc_type
    with transaction.atomic():
        indicator, _ = Indicator.objects.get_or_create(
            value=ioc_value,
            ioc_type=detected,
            defaults={"created_by": user},
        )
        investigation = Investigation.objects.create(
            analyst=user,
            indicator=indicator,
            profile_used=profile,
            status=InvestigationStatus.PENDING,
            started_at=timezone.now(),
        )

    try:
        run_investigation_task.apply_async(
            args=[user.pk, ioc_value, profile.pk],
            kwargs={"investigation_id": investigation.pk},
            queue=queue,
            task_id=f"inv-{investigation.pk}",
        )
        logger.info("Dispatched investigation #%d to queue '%s'", investigation.pk, queue)
        return investigation

    except Exception as exc:
        logger.warning("Celery unavailable (%s), falling back to sync execution", exc)
        return InvestigationOrchestrator().run(
            user=user, ioc_value=ioc_value, profile=profile, investigation=investigation,
        )
