"""
Source and AvailableField models.
Represent the catalog of threat intelligence APIs and their capabilities.

These models are populated via `python manage.py seed_sources` (Phase 3).
"""

from django.db import models

from apps.core.enums import AuthType, FieldClassification, IOCType
from apps.core.mixins import TimestampMixin


class Source(TimestampMixin, models.Model):
    """
    A threat intelligence API source (e.g., VirusTotal, Shodan, AbuseIPDB).

    Each source declares:
    - What IOC types it supports
    - How to authenticate
    - Its rate limits and TTL defaults
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Human-readable name (e.g., 'VirusTotal')",
    )
    slug = models.SlugField(
        max_length=50,
        unique=True,
        help_text="URL-safe identifier (e.g., 'virustotal')",
    )
    base_url = models.URLField(
        help_text="Base URL for API requests",
    )
    auth_type = models.CharField(
        max_length=20,
        choices=AuthType.choices,
        default=AuthType.HEADER,
    )
    env_var_name = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Environment variable name for the API key (e.g., 'VIRUSTOTAL_API_KEY')",
    )
    supported_ioc_types = models.JSONField(
        default=list,
        help_text="List of IOC types this source supports. E.g., ['hash_sha256', 'ip', 'domain']",
    )
    rate_limit_per_minute = models.PositiveIntegerField(
        default=10,
        help_text="Maximum requests per minute for this source.",
    )
    default_ttl_seconds = models.PositiveIntegerField(
        default=86400,  # 24 hours
        help_text="Default time-to-live for cached results from this source.",
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Whether this source is enabled for queries.",
    )
    priority = models.PositiveSmallIntegerField(
        default=10,
        help_text="Default priority order (lower = queried first).",
    )
    description = models.TextField(
        blank=True,
        default="",
    )

    class Meta:
        db_table = "sources"
        ordering = ["priority", "name"]
        verbose_name = "Intelligence Source"
        verbose_name_plural = "Intelligence Sources"

    def __str__(self):
        status = "active" if self.is_active else "inactive"
        return f"{self.name} ({status})"

    def supports_ioc_type(self, ioc_type: str) -> bool:
        """Check if this source can handle a given IOC type."""
        general_type = IOCType.get_general_type(ioc_type)
        return general_type in self.supported_ioc_types or ioc_type in self.supported_ioc_types


class AvailableField(models.Model):
    """
    A field that a Source can provide for a specific IOC type.

    This is the catalog that powers the "field tagging" system.
    When an analyst builds a profile, they select from these available fields.

    Example: VirusTotal for HASH can provide 'malware_family', 'detection_ratio', etc.
    """

    source = models.ForeignKey(
        Source,
        on_delete=models.CASCADE,
        related_name="available_fields",
    )
    ioc_type = models.CharField(
        max_length=20,
        choices=IOCType.choices,
        db_index=True,
        help_text="Which IOC type this field applies to.",
    )
    normalized_name = models.CharField(
        max_length=100,
        db_index=True,
        help_text="Normalized field name from the master taxonomy (e.g., 'malware_family').",
    )
    api_field_path = models.CharField(
        max_length=255,
        help_text="JSON path in the API response (e.g., 'popular_threat_classification.suggested_threat_label').",
    )
    classification = models.CharField(
        max_length=20,
        choices=FieldClassification.choices,
        default=FieldClassification.CORE,
        help_text="Priority classification: required, core, or optional.",
    )
    data_type = models.CharField(
        max_length=20,
        default="str",
        help_text="Expected data type: str, int, float, bool, list, dict.",
    )
    transform_function = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Name of the transform function to normalize this field (e.g., 'transform_detection_ratio').",
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    class Meta:
        db_table = "available_fields"
        ordering = ["source", "classification", "normalized_name"]
        verbose_name = "Available Field"
        verbose_name_plural = "Available Fields"
        unique_together = [("source", "ioc_type", "normalized_name")]
        indexes = [
            models.Index(fields=["normalized_name", "ioc_type"]),
        ]

    def __str__(self):
        return f"{self.source.slug}:{self.ioc_type}:{self.normalized_name}"
