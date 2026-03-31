"""
Investigation execution models.
Track indicators, investigation runs, and their results.
"""

from django.conf import settings
from django.db import models

from apps.core.enums import IOCType, InvestigationStatus, ResultStatus
from apps.core.mixins import TimestampMixin


class Indicator(TimestampMixin, models.Model):
    """
    A unique IOC that has been investigated at least once.
    Acts as the persistent knowledge base entity.

    One Indicator can have many Investigations (re-investigated over time).
    """

    value = models.CharField(
        max_length=2048,
        help_text="The IOC value (hash, IP, domain, URL).",
    )
    ioc_type = models.CharField(
        max_length=20,
        choices=IOCType.choices,
        db_index=True,
    )
    first_investigated_at = models.DateTimeField(
        auto_now_add=True,
    )
    last_investigated_at = models.DateTimeField(
        auto_now=True,
    )
    times_investigated = models.PositiveIntegerField(
        default=0,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="discovered_indicators",
        help_text="The first user to investigate this IOC.",
    )

    class Meta:
        db_table = "indicators"
        ordering = ["-last_investigated_at"]
        verbose_name = "Indicator"
        verbose_name_plural = "Indicators"
        unique_together = [("value", "ioc_type")]
        indexes = [
            models.Index(fields=["ioc_type", "-last_investigated_at"]),
        ]

    def __str__(self):
        short = self.value[:40] + "..." if len(self.value) > 40 else self.value
        return f"{self.get_ioc_type_display()}: {short}"


class Investigation(TimestampMixin, models.Model):
    """
    A single execution of an investigation profile against an indicator.
    Records which profile was used, status, and timing.
    """

    analyst = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="investigations",
    )
    indicator = models.ForeignKey(
        Indicator,
        on_delete=models.CASCADE,
        related_name="investigations",
    )
    profile_used = models.ForeignKey(
        "profiles.InvestigationProfile",
        on_delete=models.SET_NULL,
        null=True,
        related_name="investigations",
    )
    status = models.CharField(
        max_length=20,
        choices=InvestigationStatus.choices,
        default=InvestigationStatus.PENDING,
        db_index=True,
    )
    coverage_score = models.FloatField(
        null=True,
        blank=True,
        help_text="Percentage of expected fields that were found (0.0 to 100.0).",
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
    )
    shared_to_community = models.BooleanField(
        default=False,
        help_text="Whether results were copied to the community knowledge base.",
    )
    error_detail = models.TextField(
        blank=True,
        default="",
        help_text="Error details if status is 'error' or 'partial'.",
    )

    class Meta:
        db_table = "investigations"
        ordering = ["-created_at"]
        verbose_name = "Investigation"
        verbose_name_plural = "Investigations"
        indexes = [
            models.Index(fields=["analyst", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]

    def __str__(self):
        return f"Investigation #{self.pk} — {self.indicator} ({self.status})"


class InvestigationResult(models.Model):
    """
    A single field result from a single source within an investigation.
    This is the most granular data unit in the system.

    One Investigation produces many InvestigationResults (one per field per source).
    """

    investigation = models.ForeignKey(
        Investigation,
        on_delete=models.CASCADE,
        related_name="results",
    )
    source = models.ForeignKey(
        "sources.Source",
        on_delete=models.SET_NULL,
        null=True,
        related_name="investigation_results",
    )
    field_name = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Normalized field name (e.g., 'malware_family').",
    )
    value = models.JSONField(
        null=True,
        blank=True,
        help_text="The normalized value returned by the source.",
    )
    status = models.CharField(
        max_length=20,
        choices=ResultStatus.choices,
        db_index=True,
    )
    was_expected = models.BooleanField(
        default=True,
        help_text="Whether this field was in the analyst's expected fields list.",
    )
    response_time_ms = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="How long the source took to respond (milliseconds).",
    )
    raw_response = models.JSONField(
        null=True,
        blank=True,
        help_text="Original API response for debugging (optional, can be large).",
    )
    schema_version = models.PositiveSmallIntegerField(
        default=1,
        help_text="Version of the normalization schema used when this result was fetched.",
    )
    fetched_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        db_table = "investigation_results"
        ordering = ["source", "field_name"]
        verbose_name = "Investigation Result"
        verbose_name_plural = "Investigation Results"
        indexes = [
            models.Index(fields=["investigation", "source"]),
            models.Index(fields=["field_name", "status"]),
        ]

    def __str__(self):
        return f"{self.source}:{self.field_name} = {self.status}"


class IndicatorTag(TimestampMixin, models.Model):
    """
    Manual tags applied to indicators by analysts.
    E.g., 'high_priority', 'false_positive', 'needs_review'.
    """

    indicator = models.ForeignKey(
        Indicator,
        on_delete=models.CASCADE,
        related_name="tags",
    )
    tag = models.CharField(
        max_length=100,
        db_index=True,
    )
    tagged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
    )

    class Meta:
        db_table = "indicator_tags"
        unique_together = [("indicator", "tag")]
        verbose_name = "Indicator Tag"
        verbose_name_plural = "Indicator Tags"

    def __str__(self):
        return f"{self.indicator}: #{self.tag}"
