"""
User and Audit models for SOC Forge.

User extends Django's AbstractUser with a role field.
AuditLog tracks all significant user actions for security traceability.
"""

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models

from apps.core.enums import AuditAction, UserRole


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

    class Meta:
        db_table = "audit_log"
        ordering = ["-timestamp"]
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log"
        indexes = [
            models.Index(fields=["user", "-timestamp"]),
            models.Index(fields=["action", "-timestamp"]),
        ]

    def __str__(self):
        username = self.user.username if self.user else "system"
        return f"[{self.timestamp:%Y-%m-%d %H:%M}] {username} → {self.action} {self.target_type}"
