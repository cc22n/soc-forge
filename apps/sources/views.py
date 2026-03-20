from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, render

from apps.core.enums import IOCType
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
