import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.enums import IOCType
from apps.core.validators import detect_ioc_type
from apps.profiles.models import InvestigationProfile

from .engine.orchestrator import InvestigationOrchestrator
from .models import Investigation, InvestigationResult

logger = logging.getLogger(__name__)


@login_required
def investigation_list(request):
    """List user's investigations."""
    investigations = (
        Investigation.objects
        .filter(analyst=request.user)
        .select_related("indicator", "profile_used")
        .order_by("-created_at")[:50]
    )
    return render(request, "investigations/list.html", {
        "investigations": investigations,
    })


@login_required
def investigation_new(request):
    """Form to start a new investigation — paste IOC and select profile."""
    profiles = InvestigationProfile.objects.filter(
        owner=request.user, is_default=False
    ).order_by("ioc_type", "name") | InvestigationProfile.objects.filter(
        is_default=True
    ).order_by("ioc_type", "name")

    if request.method == "POST":
        ioc_value = request.POST.get("ioc_value", "").strip()
        profile_id = request.POST.get("profile_id", "")

        if not ioc_value:
            messages.error(request, "Enter an IOC value.")
            return render(request, "investigations/new.html", {"profiles": profiles})

        if not profile_id:
            messages.error(request, "Select an investigation profile.")
            return render(request, "investigations/new.html", {
                "profiles": profiles,
                "ioc_value": ioc_value,
            })

        profile = get_object_or_404(InvestigationProfile, pk=profile_id)

        # Auto-detect IOC type and check compatibility with profile
        detected = detect_ioc_type(ioc_value)
        if detected:
            profile_general = IOCType.get_general_type(profile.ioc_type)
            detected_general = IOCType.get_general_type(detected)
            if profile_general != detected_general:
                messages.error(
                    request,
                    f"IOC type mismatch: detected '{detected}' but profile expects '{profile.get_ioc_type_display()}'."
                )
                return render(request, "investigations/new.html", {
                    "profiles": profiles,
                    "ioc_value": ioc_value,
                })

        # Execute investigation
        try:
            orchestrator = InvestigationOrchestrator()
            investigation = orchestrator.run(
                user=request.user,
                ioc_value=ioc_value,
                profile=profile,
            )
            messages.success(
                request,
                f"Investigation completed — {investigation.coverage_score:.0f}% coverage ({investigation.get_status_display()})"
            )
            return redirect("investigations:detail", pk=investigation.pk)

        except Exception as e:
            logger.exception(f"Investigation failed: {e}")
            messages.error(request, f"Investigation failed: {str(e)}")
            return render(request, "investigations/new.html", {
                "profiles": profiles,
                "ioc_value": ioc_value,
            })

    return render(request, "investigations/new.html", {"profiles": profiles})


@login_required
def investigation_detail(request, pk):
    """View investigation results grouped by source."""
    investigation = get_object_or_404(
        Investigation.objects.select_related("indicator", "profile_used", "analyst"),
        pk=pk,
    )

    # Check access
    if investigation.analyst != request.user:
        messages.error(request, "You don't have access to this investigation.")
        return redirect("investigations:list")

    results = (
        InvestigationResult.objects
        .filter(investigation=investigation)
        .select_related("source")
        .order_by("source__name", "field_name")
    )

    # Group results by source
    results_by_source = {}
    for r in results:
        source_name = r.source.name if r.source else "Unknown"
        if source_name not in results_by_source:
            results_by_source[source_name] = {
                "source": r.source,
                "results": [],
                "found": 0,
                "total": 0,
                "response_time_ms": r.response_time_ms,
            }
        results_by_source[source_name]["results"].append(r)
        results_by_source[source_name]["total"] += 1
        if r.status == "found":
            results_by_source[source_name]["found"] += 1

    # Duration
    duration = None
    if investigation.started_at and investigation.completed_at:
        duration = (investigation.completed_at - investigation.started_at).total_seconds()

    return render(request, "investigations/detail.html", {
        "investigation": investigation,
        "results_by_source": results_by_source,
        "total_results": results.count(),
        "duration": duration,
    })