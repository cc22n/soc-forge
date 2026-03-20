from django.contrib import admin

from .models import CommunityIndicator, CommunityNote, CommunityResult, ConfidenceVote


class CommunityResultInline(admin.TabularInline):
    model = CommunityResult
    extra = 0
    readonly_fields = ("source", "field_name", "value", "contributed_by", "contributed_at", "confidence_votes")


class CommunityNoteInline(admin.TabularInline):
    model = CommunityNote
    extra = 0
    readonly_fields = ("author", "content", "created_at")


@admin.register(CommunityIndicator)
class CommunityIndicatorAdmin(admin.ModelAdmin):
    list_display = ("indicator", "first_seen_by", "times_investigated", "last_enriched_at")
    search_fields = ("indicator__value",)
    inlines = [CommunityResultInline, CommunityNoteInline]


@admin.register(CommunityResult)
class CommunityResultAdmin(admin.ModelAdmin):
    list_display = ("community_indicator", "source", "field_name", "contributed_by", "confidence_votes")
    list_filter = ("source", "field_name")
    search_fields = ("field_name",)
    readonly_fields = ("contributed_at",)


@admin.register(CommunityNote)
class CommunityNoteAdmin(admin.ModelAdmin):
    list_display = ("community_indicator", "author", "content_preview", "created_at")
    search_fields = ("content",)

    @admin.display(description="Content")
    def content_preview(self, obj):
        return obj.content[:80] + "..." if len(obj.content) > 80 else obj.content


@admin.register(ConfidenceVote)
class ConfidenceVoteAdmin(admin.ModelAdmin):
    list_display = ("community_result", "voter", "vote", "voted_at")
    list_filter = ("vote",)
