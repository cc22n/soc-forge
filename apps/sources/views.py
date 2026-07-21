from datetime import timedelta

from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Avg, Count, Max, Q
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from apps.core.enums import IOCType, ResultStatus
from apps.investigations.models import InvestigationResult
from .models import Source


@login_required
def source_list(request):
    """List all intelligence sources with field counts and IOC type coverage."""
    sources = (
        Source.objects
        .annotate(
            field_count=Count("available_fields"),
            hash_fields=Count("available_fields", filter=Q(available_fields__ioc_type__startswith="hash")),
            ip_fields=Count("available_fields", filter=Q(available_fields__ioc_type="ip")),
            domain_fields=Count("available_fields", filter=Q(available_fields__ioc_type="domain")),
            url_fields=Count("available_fields", filter=Q(available_fields__ioc_type="url")),
        )
        .order_by("priority")
    )

    # Stats
    total_fields = sum(s.field_count for s in sources)
    active_sources = sum(1 for s in sources if s.is_active)

    # IOC type coverage matrix
    ioc_types = [
        ("hash", "Hash", "hash_fields"),
        ("ip", "IP", "ip_fields"),
        ("domain", "Domain", "domain_fields"),
        ("url", "URL", "url_fields"),
    ]

    return render(request, "sources/list.html", {
        "sources": sources,
        "total_fields": total_fields,
        "active_sources": active_sources,
        "ioc_types": ioc_types,
    })


@login_required
def source_detail(request, slug):
    """Detail view for a single source with all available fields grouped by IOC type."""
    source = get_object_or_404(Source, slug=slug)
    fields = source.available_fields.all().order_by("ioc_type", "classification", "normalized_name")

    # Group fields by IOC type
    fields_by_ioc = {}
    for field in fields:
        ioc_label = field.get_ioc_type_display()
        if ioc_label not in fields_by_ioc:
            fields_by_ioc[ioc_label] = {"required": [], "core": [], "optional": []}
        fields_by_ioc[ioc_label][field.classification].append(field)

    # Count profiles using this source
    profile_count = source.profile_configs.filter(is_enabled=True).count()

    return render(request, "sources/detail.html", {
        "source": source,
        "fields_by_ioc": fields_by_ioc,
        "total_fields": fields.count(),
        "profile_count": profile_count,
    })


@login_required
@user_passes_test(lambda u: u.is_admin)
def source_health(request):
    """
    Adapter health dashboard (admin-only).

    Lists every active source with its real 30-day outcome breakdown —
    found / not_found / error+timeout — instead of just a found rate. Sources
    that never left an InvestigationResult row (missing API key, dropped by
    the orchestrator's global timeout) are still listed, flagged as "no_data",
    rather than silently disappearing.
    """
    last_30d = timezone.now() - timedelta(days=30)

    stats_by_source = {
        row["source_id"]: row
        for row in (
            InvestigationResult.objects
            .filter(source__isnull=False, fetched_at__gte=last_30d)
            .values("source_id")
            .annotate(
                total=Count("id"),
                found=Count("id", filter=Q(status=ResultStatus.FOUND)),
                not_found=Count("id", filter=Q(status=ResultStatus.NOT_FOUND)),
                errors=Count("id", filter=Q(status__in=[ResultStatus.ERROR, ResultStatus.TIMEOUT])),
                avg_ms=Avg("response_time_ms"),
                last_used=Max("fetched_at"),
            )
        )
    }

    sources = []
    summary = {"healthy": 0, "degraded": 0, "down": 0, "no_data": 0}

    for source in Source.objects.filter(is_active=True).order_by("priority", "name"):
        stats = stats_by_source.get(source.id)

        if stats is None or stats["total"] == 0:
            health = "no_data"
            row = {
                "source": source,
                "health": health,
                "total": 0,
                "found": 0,
                "not_found": 0,
                "errors": 0,
                "found_rate": 0,
                "not_found_rate": 0,
                "error_rate": 0,
                "avg_ms": None,
                "last_used": None,
            }
        else:
            total = stats["total"]
            error_rate = round(stats["errors"] / total * 100, 1)

            if error_rate >= 50:
                health = "down"
            elif error_rate >= 15:
                health = "degraded"
            else:
                health = "healthy"

            row = {
                "source": source,
                "health": health,
                "total": total,
                "found": stats["found"],
                "not_found": stats["not_found"],
                "errors": stats["errors"],
                "found_rate": round(stats["found"] / total * 100, 1),
                "not_found_rate": round(stats["not_found"] / total * 100, 1),
                "error_rate": error_rate,
                "avg_ms": stats["avg_ms"],
                "last_used": stats["last_used"],
            }

        summary[health] += 1
        sources.append(row)

    return render(request, "sources/health.html", {
        "sources": sources,
        "active_count": len(sources),
        "summary": summary,
    })
