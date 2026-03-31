"""
DRF serializers for SOC Forge REST API.
"""

from rest_framework import serializers

from apps.investigations.models import Indicator, Investigation, InvestigationResult
from apps.community.models import CommunityIndicator, CommunityResult


class IndicatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Indicator
        fields = ["id", "value", "ioc_type", "times_investigated",
                  "first_investigated_at", "last_investigated_at"]


class InvestigationResultSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)

    class Meta:
        model = InvestigationResult
        fields = ["id", "source_name", "field_name", "value", "status",
                  "was_expected", "response_time_ms", "schema_version", "fetched_at"]


class InvestigationSerializer(serializers.ModelSerializer):
    indicator = IndicatorSerializer(read_only=True)
    profile_name = serializers.CharField(source="profile_used.name", read_only=True)
    analyst_username = serializers.CharField(source="analyst.username", read_only=True)
    results = InvestigationResultSerializer(many=True, read_only=True)

    class Meta:
        model = Investigation
        fields = ["id", "indicator", "profile_name", "analyst_username",
                  "status", "coverage_score", "started_at", "completed_at",
                  "shared_to_community", "error_detail", "results"]


class InvestigationCreateSerializer(serializers.Serializer):
    ioc_value = serializers.CharField(max_length=2048)
    profile_id = serializers.IntegerField()


class CommunityResultSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    contributor = serializers.CharField(source="contributed_by.username", read_only=True)

    class Meta:
        model = CommunityResult
        fields = ["id", "source_name", "field_name", "value",
                  "contributor", "contributed_at", "confidence_votes"]


class CommunityIndicatorSerializer(serializers.ModelSerializer):
    indicator = IndicatorSerializer(read_only=True)
    results = CommunityResultSerializer(many=True, read_only=True)
    first_seen_by = serializers.CharField(source="first_seen_by.username", read_only=True)

    class Meta:
        model = CommunityIndicator
        fields = ["id", "indicator", "first_seen_by", "first_seen_at",
                  "times_investigated", "last_enriched_at", "results"]
