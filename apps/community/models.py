"""
Community Knowledge Base models.
Shared, immutable intelligence contributed by analysts.

Rules:
- Anyone can read and add data
- Nobody modifies or deletes another analyst's contributions
- Each contribution has full traceability (who, when)
- Confidence votes allow the community to validate data
"""

from django.conf import settings
from django.db import models

from apps.core.enums import VoteType
from apps.core.mixins import TimestampMixin


class CommunityIndicator(TimestampMixin, models.Model):
    """
    A shared view of an Indicator in the community knowledge base.
    One-to-one with Indicator — created when an analyst shares their investigation.
    """

    indicator = models.OneToOneField(
        "investigations.Indicator",
        on_delete=models.CASCADE,
        related_name="community_entry",
    )
    first_seen_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="community_discoveries",
        help_text="Credit to the analyst who first shared this IOC.",
    )
    first_seen_at = models.DateTimeField(
        auto_now_add=True,
    )
    times_investigated = models.PositiveIntegerField(
        default=1,
        help_text="How many times this IOC has been investigated by the community.",
    )
    last_enriched_at = models.DateTimeField(
        auto_now=True,
        help_text="Last time new data was contributed.",
    )

    class Meta:
        db_table = "community_indicators"
        ordering = ["-last_enriched_at"]
        verbose_name = "Community Indicator"
        verbose_name_plural = "Community Indicators"

    def __str__(self):
        return f"Community: {self.indicator}"


class CommunityResult(models.Model):
    """
    A field result contributed to the community by an analyst.
    Immutable after creation — nobody can edit another analyst's contribution.
    """

    community_indicator = models.ForeignKey(
        CommunityIndicator,
        on_delete=models.CASCADE,
        related_name="results",
    )
    source = models.ForeignKey(
        "sources.Source",
        on_delete=models.SET_NULL,
        null=True,
        related_name="community_results",
    )
    field_name = models.CharField(
        max_length=100,
        db_index=True,
    )
    value = models.JSONField(
        null=True,
        blank=True,
    )
    contributed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="community_contributions",
    )
    contributed_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )
    confidence_votes = models.PositiveIntegerField(
        default=0,
        help_text="Net positive confirmation votes.",
    )

    class Meta:
        db_table = "community_results"
        ordering = ["-contributed_at"]
        verbose_name = "Community Result"
        verbose_name_plural = "Community Results"
        indexes = [
            models.Index(fields=["community_indicator", "field_name"]),
            models.Index(fields=["contributed_by", "-contributed_at"]),
        ]

    def __str__(self):
        return f"{self.field_name}: {self.value} (by {self.contributed_by})"


class CommunityNote(TimestampMixin, models.Model):
    """
    Free-text notes added by analysts to community indicators.
    Only the author can edit their own notes.
    """

    community_indicator = models.ForeignKey(
        CommunityIndicator,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="community_notes",
    )
    content = models.TextField(
        help_text="Context, observations, or analysis notes.",
    )

    class Meta:
        db_table = "community_notes"
        ordering = ["-created_at"]
        verbose_name = "Community Note"
        verbose_name_plural = "Community Notes"

    def __str__(self):
        preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"Note by {self.author}: {preview}"


class ConfidenceVote(models.Model):
    """
    A vote by an analyst to confirm or dispute a community result.
    Each analyst can vote once per result.
    """

    community_result = models.ForeignKey(
        CommunityResult,
        on_delete=models.CASCADE,
        related_name="votes",
    )
    voter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="confidence_votes",
    )
    vote = models.CharField(
        max_length=10,
        choices=VoteType.choices,
    )
    voted_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        db_table = "confidence_votes"
        unique_together = [("community_result", "voter")]
        verbose_name = "Confidence Vote"
        verbose_name_plural = "Confidence Votes"

    def __str__(self):
        return f"{self.voter} → {self.vote} on {self.community_result}"
