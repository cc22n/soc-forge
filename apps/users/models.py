"""
User and Audit models for SOC Forge.

User extends Django's AbstractUser with a role field.
AuditLog tracks all significant user actions for security traceability.
"""

import hashlib
import json

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.text import slugify

from apps.core.enums import AuditAction, UserRole


class Organization(models.Model):
    """
    Organizational unit for multi-tenant isolation.
    Users in the same organization share access to investigations and profiles.
    """

    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=50, unique=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organizations"
        ordering = ["name"]
        verbose_name = "Organization"
        verbose_name_plural = "Organizations"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class User(AbstractUser):
    """
    Custom User for SOC Forge.
    Extends AbstractUser to add SOC-specific fields.
    """

    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.ANALYST,
        db_index=True,
        help_text="User role in the SOC Forge system.",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="members",
        help_text="The organization this user belongs to (optional for solo use).",
    )

    class Meta:
        db_table = "users"
        ordering = ["-date_joined"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def is_admin(self):
        return self.role == UserRole.ADMIN

    @property
    def is_analyst(self):
        return self.role == UserRole.ANALYST


class UserReputation(models.Model):
    """
    Tracks an analyst's contribution quality in the community knowledge base.
    Used to weight votes and gate community publishing throttling.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reputation",
    )
    reputation_score = models.PositiveIntegerField(
        default=100,
        help_text="Score from 0 to 1000. Affects vote weight in the community.",
    )
    verified_analyst = models.BooleanField(
        default=False,
        help_text="Verified analysts have maximum trust weight (1.0x).",
    )
    total_contributions = models.PositiveIntegerField(default=0)
    disputed_contributions = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "user_reputation"
        verbose_name = "User Reputation"
        verbose_name_plural = "User Reputations"

    @property
    def trust_weight(self) -> float:
        """Vote weight: 0.1x (new user) → 1.0x (verified analyst)."""
        if self.verified_analyst:
            return 1.0
        return max(0.1, min(1.0, self.reputation_score / 1000))

    def __str__(self):
        return f"{self.user.username} — score={self.reputation_score}, weight={self.trust_weight:.1f}x"

    @classmethod
    def get_or_create_for(cls, user):
        rep, _ = cls.objects.get_or_create(user=user)
        return rep


class AuditLog(models.Model):
    """
    Immutable audit trail for SOC Forge.
    Records who did what, when, and from where.

    This model is append-only: no updates, no deletes.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="audit_logs",
    )
    action = models.CharField(
        max_length=20,
        choices=AuditAction.choices,
        db_index=True,
    )
    target_type = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="The model or resource type affected.",
    )
    target_id = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="The ID of the affected resource.",
    )
    detail = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional context about the action.",
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )
    previous_hash = models.CharField(
        max_length=64,
        default="0" * 64,
        editable=False,
        help_text="SHA-256 hash of the previous log entry (chain integrity).",
    )
    entry_hash = models.CharField(
        max_length=64,
        default="",
        editable=False,
        help_text="SHA-256 hash of this entry's content + previous_hash.",
    )

    class Meta:
        db_table = "audit_log"
        ordering = ["-timestamp"]
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log"
        indexes = [
            models.Index(fields=["user", "-timestamp"]),
            models.Index(fields=["action", "-timestamp"]),
        ]

    def _compute_hash(self, previous_hash: str) -> str:
        payload = json.dumps({
            "user_id": self.user_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "ip_address": str(self.ip_address),
            "previous_hash": previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.pk:  # only on creation (AuditLog is append-only)
            last = AuditLog.objects.order_by("pk").last()
            prev = last.entry_hash if last and last.entry_hash else "0" * 64
            self.previous_hash = prev
            self.entry_hash = self._compute_hash(prev)
        super().save(*args, **kwargs)

    def __str__(self):
        username = self.user.username if self.user else "system"
        return f"[{self.timestamp:%Y-%m-%d %H:%M}] {username} → {self.action} {self.target_type}"

    @classmethod
    def verify_chain(cls) -> tuple[bool, int]:
        """
        Verify the integrity of the audit chain.
        Returns (is_valid, first_broken_pk) — first_broken_pk is None if valid.
        """
        entries = cls.objects.order_by("pk").values(
            "pk", "user_id", "action", "target_type", "target_id", "ip_address",
            "previous_hash", "entry_hash",
        )
        prev_hash = "0" * 64
        for entry in entries:
            expected = hashlib.sha256(json.dumps({
                "user_id": entry["user_id"],
                "action": entry["action"],
                "target_type": entry["target_type"],
                "target_id": entry["target_id"],
                "ip_address": str(entry["ip_address"]),
                "previous_hash": prev_hash,
            }, sort_keys=True).encode()).hexdigest()
            if entry["entry_hash"] != expected:
                return False, entry["pk"]
            prev_hash = entry["entry_hash"]
        return True, None
