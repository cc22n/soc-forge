"""
Reusable model mixins for SOC Forge.

Usage:
    from apps.core.mixins import TimestampMixin

    class MyModel(TimestampMixin, models.Model):
        ...
"""

from django.db import models


class TimestampMixin(models.Model):
    """Adds created_at and updated_at timestamps to any model."""

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


def org_investigations_filter(user):
    """
    Return a Q filter for investigations visible to a user.

    - If the user belongs to an organization: show all investigations
      from members of the same org.
    - Otherwise: show only the user's own investigations.

    Usage:
        from apps.core.mixins import org_investigations_filter
        qs = Investigation.objects.filter(org_investigations_filter(request.user))
    """
    from django.db.models import Q

    if user.organization_id:
        return Q(analyst__organization=user.organization)
    return Q(analyst=user)


def user_can_access_investigation(user, investigation) -> bool:
    """
    Check if a user has read access to an investigation.

    Org members share access; solo users can only see their own.
    """
    if user.organization_id and investigation.analyst.organization_id == user.organization_id:
        return True
    return investigation.analyst_id == user.pk
