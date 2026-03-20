from django.contrib import admin

from .models import ExpectedField, InvestigationProfile, ProfileSourceConfig


class ProfileSourceConfigInline(admin.TabularInline):
    model = ProfileSourceConfig
    extra = 0
    fields = ("source", "priority", "is_enabled", "timeout_seconds")


@admin.register(InvestigationProfile)
class InvestigationProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "ioc_type", "is_default", "source_count", "updated_at")
    list_filter = ("ioc_type", "is_default")
    search_fields = ("name", "owner__username")
    inlines = [ProfileSourceConfigInline]

    @admin.display(description="Sources")
    def source_count(self, obj):
        return obj.source_configs.filter(is_enabled=True).count()


@admin.register(ProfileSourceConfig)
class ProfileSourceConfigAdmin(admin.ModelAdmin):
    list_display = ("profile", "source", "priority", "is_enabled")
    list_filter = ("is_enabled", "source")


@admin.register(ExpectedField)
class ExpectedFieldAdmin(admin.ModelAdmin):
    list_display = ("profile_source", "available_field", "is_required")
    list_filter = ("is_required",)
