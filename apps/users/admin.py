from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import AuditLog, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("username", "email", "role", "is_active", "date_joined")
    list_filter = ("role", "is_active", "is_staff", "date_joined")
    search_fields = ("username", "email")
    ordering = ("-date_joined",)

    # Add role field to the existing fieldsets
    fieldsets = BaseUserAdmin.fieldsets + (
        ("SOC Forge", {"fields": ("role",)}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("SOC Forge", {"fields": ("role",)}),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action", "target_type", "ip_address")
    list_filter = ("action", "timestamp")
    search_fields = ("user__username", "target_type", "ip_address")
    readonly_fields = (
        "user",
        "action",
        "target_type",
        "target_id",
        "detail",
        "ip_address",
        "timestamp",
    )
    date_hierarchy = "timestamp"
    list_per_page = 50

    def has_add_permission(self, request):
        """Audit logs are created automatically, not manually."""
        return False

    def has_change_permission(self, request, obj=None):
        """Audit logs are immutable."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit logs cannot be deleted."""
        return False
