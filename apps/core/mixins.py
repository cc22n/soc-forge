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
