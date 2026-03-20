from django.contrib import admin

from .models import Indicator, IndicatorTag, Investigation, InvestigationResult


class IndicatorTagInline(admin.TabularInline):
    model = IndicatorTag
    extra = 0


class InvestigationResultInline(admin.TabularInline):
    model = InvestigationResult
    extra = 0
    fields = ("source", "field_name", "value", "status", "was_expected", "response_time_ms")
    readonly_fields = ("source", "field_name", "value", "status", "was_expected", "response_time_ms")


@admin.register(Indicator)
class IndicatorAdmin(admin.ModelAdmin):
    list_display = ("value_short", "ioc_type", "times_investigated", "created_by", "last_investigated_at")
    list_filter = ("ioc_type", "last_investigated_at")
    search_fields = ("value",)
    inlines = [IndicatorTagInline]

    @admin.display(description="Value")
    def value_short(self, obj):
        return obj.value[:60] + "..." if len(obj.value) > 60 else obj.value


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = ("id", "analyst", "indicator", "profile_used", "status", "coverage_score", "created_at")
    list_filter = ("status", "created_at", "shared_to_community")
    search_fields = ("indicator__value", "analyst__username")
    inlines = [InvestigationResultInline]


@admin.register(InvestigationResult)
class InvestigationResultAdmin(admin.ModelAdmin):
    list_display = ("investigation", "source", "field_name", "status", "was_expected", "response_time_ms")
    list_filter = ("status", "was_expected", "source")
    search_fields = ("field_name",)


@admin.register(IndicatorTag)
class IndicatorTagAdmin(admin.ModelAdmin):
    list_display = ("indicator", "tag", "tagged_by", "created_at")
    list_filter = ("tag",)
    search_fields = ("tag", "indicator__value")
