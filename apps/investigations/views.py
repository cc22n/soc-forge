import json
import logging
import uuid
from datetime import timezone as dt_timezone

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.enums import IOCType
from apps.core.mixins import org_investigations_filter, user_can_access_investigation
from apps.core.validators import detect_ioc_type
from apps.profiles.models import InvestigationProfile

from .engine.orchestrator import InvestigationOrchestrator
from .llm import LLMNotConfiguredError, call_llm, get_provider_config
from .models import Investigation, InvestigationResult

logger = logging.getLogger(__name__)


@login_required
def investigation_list(request):
    """List investigations visible to this user (own or org-shared)."""
    investigations = (
        Investigation.objects
        .filter(org_investigations_filter(request.user))
        .select_related("indicator", "profile_used", "analyst")
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

    # Check access — org members share access to each other's investigations
    if not user_can_access_investigation(request.user, investigation):
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
                "errors": 0,
                "response_time_ms": r.response_time_ms,
            }
        results_by_source[source_name]["results"].append(r)
        results_by_source[source_name]["total"] += 1
        if r.status == "found":
            results_by_source[source_name]["found"] += 1
        elif r.status in ("error", "timeout"):
            results_by_source[source_name]["errors"] += 1

    # Derive adapter_status for each source panel
    for data in results_by_source.values():
        if data["found"] > 0 and data["errors"] == 0:
            data["adapter_status"] = "success"
        elif data["found"] > 0 and data["errors"] > 0:
            data["adapter_status"] = "partial"
        elif data["found"] == 0 and data["errors"] > 0:
            data["adapter_status"] = "error"
        else:
            data["adapter_status"] = "no_data"

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


# IOC type → STIX pattern prefix mapping
_STIX_PATTERN_MAP = {
    "ip": "ipv4-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "hash_md5": "file:hashes.MD5",
    "hash_sha1": "file:hashes.SHA-1",
    "hash_sha256": "file:hashes.SHA-256",
}


@login_required
def investigation_export_stix(request, pk):
    """Export an investigation as a STIX 2.1 Bundle JSON file."""
    investigation = get_object_or_404(
        Investigation.objects.select_related("indicator", "profile_used", "analyst"),
        pk=pk,
    )

    if not user_can_access_investigation(request.user, investigation):
        messages.error(request, "You don't have access to this investigation.")
        return redirect("investigations:list")

    indicator = investigation.indicator
    now_iso = investigation.completed_at.astimezone(dt_timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    ) if investigation.completed_at else ""

    # Build STIX Indicator object
    pattern_attr = _STIX_PATTERN_MAP.get(indicator.ioc_type, "ipv4-addr:value")
    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, indicator.value)}",
        "created": now_iso,
        "modified": now_iso,
        "name": indicator.value,
        "pattern": f"[{pattern_attr} = '{indicator.value}']",
        "pattern_type": "stix",
        "valid_from": now_iso,
        "labels": ["malicious-activity"],
        "extensions": {
            "x-soc-forge-v1": {
                "ioc_type": indicator.ioc_type,
                "coverage_score": investigation.coverage_score,
                "profile_used": investigation.profile_used.name if investigation.profile_used else "",
                "investigation_id": investigation.pk,
                "investigation_status": investigation.status,
            }
        },
    }

    # Build observed-data objects per source
    results = (
        InvestigationResult.objects
        .filter(investigation=investigation, status="found")
        .select_related("source")
        .order_by("source__name", "field_name")
    )

    # Group by source for cleaner STIX objects
    by_source = {}
    for r in results:
        slug = r.source.slug if r.source else "unknown"
        by_source.setdefault(slug, {"source_name": r.source.name if r.source else "Unknown", "fields": {}})
        by_source[slug]["fields"][r.field_name] = r.value

    stix_objects = [stix_indicator]
    for slug, data in by_source.items():
        stix_objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "first_observed": now_iso,
            "last_observed": now_iso,
            "number_observed": 1,
            "object_refs": [stix_indicator["id"]],
            "extensions": {
                "x-soc-forge-source-v1": {
                    "source_slug": slug,
                    "source_name": data["source_name"],
                    "fields": data["fields"],
                }
            },
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects,
    }

    filename = f"soc-forge-investigation-{pk}.stix.json"
    response = HttpResponse(
        json.dumps(bundle, indent=2, default=str),
        content_type="application/json",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@login_required
@require_POST
def investigation_generate_summary(request, pk):
    """
    Generate a natural-language summary via the configured LLM provider.
    Provider is selected by LLM_PROVIDER in .env (default: anthropic).

    Returns JSON: {"summary": str, "recommendation": str, "provider": str}
    """
    investigation = get_object_or_404(
        Investigation.objects.select_related("indicator", "profile_used"),
        pk=pk,
    )

    if not user_can_access_investigation(request.user, investigation):
        return JsonResponse({"error": "Access denied."}, status=403)

    # Build a compact, structured context from the results
    results = (
        InvestigationResult.objects
        .filter(investigation=investigation, status="found")
        .select_related("source")
        .order_by("source__name", "field_name")
    )

    by_source: dict = {}
    for r in results:
        name = r.source.name if r.source else "Unknown"
        by_source.setdefault(name, [])
        by_source[name].append(f"{r.field_name}: {r.value}")

    sources_text = ""
    for source_name, fields in by_source.items():
        sources_text += f"\n### {source_name}\n" + "\n".join(f"- {f}" for f in fields[:20])

    if not sources_text:
        sources_text = "\n(No data found by any source)"

    prompt = f"""You are a SOC analyst assistant. Analyze the following threat intelligence results and provide:
1. A concise summary (2-4 sentences) of what the data reveals about this IOC.
2. A clear action recommendation (1-2 sentences) for a SOC analyst.

Be direct and actionable. Use plain language without markdown headers.

## IOC
- Value: {investigation.indicator.value}
- Type: {investigation.indicator.get_ioc_type_display()}
- Coverage score: {investigation.coverage_score:.0f}% ({investigation.get_status_display()})
- Profile: {investigation.profile_used.name if investigation.profile_used else "default"}

## Threat Intelligence Results
{sources_text}

Respond in valid JSON only, with keys "summary" and "recommendation"."""

    raw = ""
    try:
        from .llm import PROVIDER_LABELS, get_provider_config
        provider, _, model = get_provider_config()
        provider_label = f"{PROVIDER_LABELS.get(provider, provider)} / {model}"

        raw = call_llm(prompt)

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        data = json.loads(raw)
        return JsonResponse({
            "summary": str(data.get("summary", "")),
            "recommendation": str(data.get("recommendation", "")),
            "provider": provider_label,
        })

    except LLMNotConfiguredError as exc:
        return JsonResponse({"error": str(exc)}, status=503)
    except json.JSONDecodeError:
        return JsonResponse({"summary": raw, "recommendation": "", "provider": ""})
    except Exception as exc:
        logger.exception(f"LLM summary failed for investigation #{pk}: {exc}")
        return JsonResponse({"error": f"LLM request failed: {exc}"}, status=502)