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
def run_investigation_task(self, user_id: int, ioc_value: str, profile_id: int) -> dict:
    """
    Execute an investigation asynchronously.

    Returns a dict with:
        {"investigation_id": int, "status": str, "coverage_score": float}
    """
    try:
        user = User.objects.get(pk=user_id)
        profile = InvestigationProfile.objects.get(pk=profile_id)
    except (User.DoesNotExist, InvestigationProfile.DoesNotExist) as exc:
        logger.error(f"Task setup failed: {exc}")
        raise

    logger.info(f"[task:{self.request.id}] Starting investigation: {ioc_value} with profile '{profile.name}'")

    try:
        orchestrator = InvestigationOrchestrator()
        investigation = orchestrator.run(user=user, ioc_value=ioc_value, profile=profile)
    except Exception as exc:
        logger.exception(f"[task:{self.request.id}] Investigation failed: {exc}")
        raise self.retry(exc=exc)

    logger.info(
        f"[task:{self.request.id}] Done — investigation #{investigation.pk} "
        f"status={investigation.status} coverage={investigation.coverage_score}"
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

    try:
        # Create a PENDING investigation record first so the caller has a PK to poll
        from apps.core.validators import detect_ioc_type
        from apps.investigations.models import Indicator
        from django.utils import timezone

        ioc_value = ioc_value.strip()
        detected = detect_ioc_type(ioc_value) or profile.ioc_type
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

        run_investigation_task.apply_async(
            args=[user.pk, ioc_value, profile.pk],
            kwargs={},
            queue=queue,
            task_id=f"inv-{investigation.pk}",
        )
        logger.info(f"Dispatched investigation #{investigation.pk} to queue '{queue}'")
        return investigation

    except Exception as exc:
        logger.warning(f"Celery unavailable ({exc}), falling back to sync execution")
        return InvestigationOrchestrator().run(user=user, ioc_value=ioc_value, profile=profile)
