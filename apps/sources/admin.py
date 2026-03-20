from django.contrib import admin

from .models import AvailableField, Source


class AvailableFieldInline(admin.TabularInline):
    model = AvailableField
    extra = 0
    fields = ("ioc_type", "normalized_name", "classification", "api_field_path", "data_type")


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "rate_limit_per_minute", "priority", "field_count")
    list_filter = ("is_active", "auth_type")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [AvailableFieldInline]

    @admin.display(description="Fields")
    def field_count(self, obj):
        return obj.available_fields.count()


@admin.register(AvailableField)
class AvailableFieldAdmin(admin.ModelAdmin):
    list_display = ("source", "ioc_type", "normalized_name", "classification", "data_type")
    list_filter = ("source", "ioc_type", "classification")
    search_fields = ("normalized_name", "api_field_path")
