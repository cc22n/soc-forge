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

    NOTE: investigation.analyst is a nullable FK.  We must guard against
    analyst=None (e.g. the analyst account was deleted) to avoid an
    AttributeError when accessing .organization_id on NoneType.
    """
    if investigation.analyst_id is None:
        return False
    if investigation.analyst_id == user.pk:
        return True
    if user.organization_id:
        # Avoid hitting the DB when analyst is already prefetched; fall back
        # to a direct FK comparison on the investigation row.
        analyst_org = (
            investigation.analyst.organization_id
            if hasattr(investigation, "_analyst_cache") or investigation.__dict__.get("analyst")
            else None
        )
        if analyst_org is None:
            # Perform a single targeted query rather than loading the full User object.
            from apps.users.models import User
            analyst_org = User.objects.filter(pk=investigation.analyst_id).values_list(
                "organization_id", flat=True
            ).first()
        return analyst_org == user.organization_id
    return False
