"""
Investigation Profile models.
The core differentiator of SOC Forge: customizable investigation playbooks.
"""

from django.conf import settings
from django.db import models

from apps.core.enums import IOCType
from apps.core.mixins import TimestampMixin


class InvestigationProfile(TimestampMixin, models.Model):
    """
    A reusable investigation configuration created by an analyst.

    Defines: what IOC type, which API sources to query, and what fields
    to expect from each source.
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="investigation_profiles",
    )
    name = models.CharField(
        max_length=200,
        help_text="Profile name (e.g., 'Malware Deep Dive', 'Quick IP Check').",
    )
    description = models.TextField(
        blank=True,
        default="",
    )
    ioc_type = models.CharField(
        max_length=20,
        choices=IOCType.choices,
        db_index=True,
        help_text="The type of IOC this profile investigates.",
    )
    is_default = models.BooleanField(
        default=False,
        help_text="Pre-loaded system profile (not owned by a specific user).",
    )

    class Meta:
        db_table = "investigation_profiles"
        ordering = ["-updated_at"]
        verbose_name = "Investigation Profile"
        verbose_name_plural = "Investigation Profiles"

    def __str__(self):
        return f"{self.name} ({self.get_ioc_type_display()})"

    @property
    def source_count(self):
        return self.source_configs.filter(is_enabled=True).count()

    @property
    def expected_field_count(self):
        return ExpectedField.objects.filter(
            profile_source__profile=self,
            profile_source__is_enabled=True,
        ).count()


class ProfileSourceConfig(models.Model):
    """
    Configuration for a specific source within a profile.
    Defines priority, timeout, and whether this source is active in this profile.
    """

    profile = models.ForeignKey(
        InvestigationProfile,
        on_delete=models.CASCADE,
        related_name="source_configs",
    )
    source = models.ForeignKey(
        "sources.Source",
        on_delete=models.CASCADE,
        related_name="profile_configs",
    )
    priority = models.PositiveSmallIntegerField(
        default=10,
        help_text="Execution order within this profile (lower = first).",
    )
    is_enabled = models.BooleanField(
        default=True,
    )
    timeout_seconds = models.PositiveIntegerField(
        default=30,
        help_text="Max seconds to wait for this source's response.",
    )

    class Meta:
        db_table = "profile_source_configs"
        ordering = ["priority"]
        unique_together = [("profile", "source")]
        verbose_name = "Profile Source Config"
        verbose_name_plural = "Profile Source Configs"

    def __str__(self):
        status = "on" if self.is_enabled else "off"
        return f"{self.profile.name} → {self.source.name} [{status}]"


class ExpectedField(models.Model):
    """
    A field that the analyst expects from a specific source in a profile.
    This is the "tag" the analyst puts on each API.

    Links ProfileSourceConfig to AvailableField.
    """

    profile_source = models.ForeignKey(
        ProfileSourceConfig,
        on_delete=models.CASCADE,
        related_name="expected_fields",
    )
    available_field = models.ForeignKey(
        "sources.AvailableField",
        on_delete=models.CASCADE,
        related_name="expected_in_profiles",
    )
    is_required = models.BooleanField(
        default=False,
        help_text="If True, this field is essential for the profile's purpose.",
    )

    class Meta:
        db_table = "expected_fields"
        unique_together = [("profile_source", "available_field")]
        verbose_name = "Expected Field"
        verbose_name_plural = "Expected Fields"

    def __str__(self):
        req = "req" if self.is_required else "opt"
        return f"{self.available_field.normalized_name} [{req}]"
