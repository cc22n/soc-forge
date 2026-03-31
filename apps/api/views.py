"""
REST API views for SOC Forge.

Authentication: Token-based (DRF TokenAuthentication).
All endpoints require a valid token in the Authorization header:
    Authorization: Token <token>
"""

import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.community.models import CommunityIndicator
from apps.core.enums import IOCType
from apps.core.mixins import org_investigations_filter, user_can_access_investigation
from apps.core.validators import detect_ioc_type
from apps.investigations.engine.orchestrator import InvestigationOrchestrator
from apps.investigations.models import Investigation
from apps.profiles.models import InvestigationProfile

from .serializers import (
    CommunityIndicatorSerializer,
    InvestigationCreateSerializer,
    InvestigationSerializer,
)

logger = logging.getLogger(__name__)


@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def investigation_create(request):
    """
    POST /api/investigations/
    Start a new investigation. Returns the completed investigation.

    Body: { "ioc_value": "1.1.1.1", "profile_id": 3 }
    """
    ser = InvestigationCreateSerializer(data=request.data)
    if not ser.is_valid():
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    ioc_value = ser.validated_data["ioc_value"].strip()
    profile_id = ser.validated_data["profile_id"]
    profile = get_object_or_404(InvestigationProfile, pk=profile_id)

    detected = detect_ioc_type(ioc_value)
    if detected and IOCType.get_general_type(detected) != IOCType.get_general_type(profile.ioc_type):
        return Response(
            {"detail": f"IOC type mismatch: detected '{detected}', profile expects '{profile.ioc_type}'."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        investigation = InvestigationOrchestrator().run(
            user=request.user, ioc_value=ioc_value, profile=profile
        )
    except Exception as exc:
        logger.exception("API investigation failed")
        return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(InvestigationSerializer(investigation).data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def investigation_list(request):
    """
    GET /api/investigations/
    List investigations visible to the authenticated user (own or org-shared).
    Supports ?limit=N (default 20, max 100).
    """
    limit = min(int(request.query_params.get("limit", 20)), 100)
    qs = (
        Investigation.objects
        .filter(org_investigations_filter(request.user))
        .select_related("indicator", "profile_used", "analyst")
        .prefetch_related("results__source")
        .order_by("-created_at")[:limit]
    )
    return Response(InvestigationSerializer(qs, many=True).data)


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def investigation_detail(request, pk):
    """
    GET /api/investigations/{pk}/
    Retrieve a single investigation with all results.
    """
    investigation = get_object_or_404(
        Investigation.objects
        .select_related("indicator", "profile_used", "analyst")
        .prefetch_related("results__source"),
        pk=pk,
    )
    if not user_can_access_investigation(request.user, investigation):
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    return Response(InvestigationSerializer(investigation).data)


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def investigation_status(request, pk):
    """
    GET /api/investigations/{pk}/status/
    Lightweight status check for polling (used by async flows).
    """
    investigation = get_object_or_404(Investigation, pk=pk)
    if not user_can_access_investigation(request.user, investigation):
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
    return Response({
        "id": investigation.pk,
        "status": investigation.status,
        "coverage_score": investigation.coverage_score,
        "completed_at": investigation.completed_at,
    })


@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def community_list(request):
    """
    GET /api/community/
    List community indicators. Supports ?q=<search> and ?limit=N (default 20).
    """
    limit = min(int(request.query_params.get("limit", 20)), 100)
    query = request.query_params.get("q", "").strip()
    qs = (
        CommunityIndicator.objects
        .select_related("indicator", "first_seen_by")
        .prefetch_related("results__source", "results__contributed_by")
        .order_by("-last_enriched_at")
    )
    if query:
        qs = qs.filter(indicator__value__icontains=query)
    return Response(CommunityIndicatorSerializer(qs[:limit], many=True).data)
