import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.enums import IOCType
from apps.sources.models import AvailableField, Source

from .models import ExpectedField, InvestigationProfile, ProfileSourceConfig


@login_required
def profile_list(request):
    """List all profiles (user's own + default system profiles)."""
    my_profiles = (
        InvestigationProfile.objects
        .filter(owner=request.user, is_default=False)
        .annotate(num_sources=Count("source_configs", distinct=True))
        .order_by("-updated_at")
    )
    default_profiles = (
        InvestigationProfile.objects
        .filter(is_default=True)
        .annotate(num_sources=Count("source_configs", distinct=True))
        .order_by("name")
    )

    return render(request, "profiles/list.html", {
        "my_profiles": my_profiles,
        "default_profiles": default_profiles,
        "ioc_types": IOCType.choices,
    })


@login_required
def profile_detail(request, pk):
    """View a profile with its sources and expected fields."""
    profile = get_object_or_404(InvestigationProfile, pk=pk)

    # Check access: owner or default profile
    if not profile.is_default and profile.owner != request.user:
        messages.error(request, "You don't have access to this profile.")
        return redirect("profiles:list")

    source_configs = (
        profile.source_configs
        .filter(is_enabled=True)
        .select_related("source")
        .prefetch_related("expected_fields__available_field")
        .order_by("priority")
    )

    # Calculate coverage stats
    total_expected = 0
    required_count = 0
    for sc in source_configs:
        for ef in sc.expected_fields.all():
            total_expected += 1
            if ef.is_required:
                required_count += 1

    return render(request, "profiles/detail.html", {
        "profile": profile,
        "source_configs": source_configs,
        "total_expected": total_expected,
        "required_count": required_count,
    })


@login_required
def profile_create(request):
    """Create a new investigation profile — step 1: name and IOC type."""
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        ioc_type = request.POST.get("ioc_type", "")
        description = request.POST.get("description", "").strip()

        if not name:
            messages.error(request, "Profile name is required.")
            return render(request, "profiles/create.html", {"ioc_types": IOCType.choices})

        if ioc_type not in dict(IOCType.choices):
            messages.error(request, "Invalid IOC type.")
            return render(request, "profiles/create.html", {"ioc_types": IOCType.choices})

        profile = InvestigationProfile.objects.create(
            owner=request.user,
            name=name,
            ioc_type=ioc_type,
            description=description,
        )

        messages.success(request, f'Profile "{name}" created. Now select your sources.')
        return redirect("profiles:edit_sources", pk=profile.pk)

    return render(request, "profiles/create.html", {"ioc_types": IOCType.choices})


@login_required
def profile_edit_sources(request, pk):
    """Step 2: Select which sources to include and pick fields from each."""
    profile = get_object_or_404(InvestigationProfile, pk=pk, owner=request.user, is_default=False)

    # Get general IOC type for matching sources
    general_type = IOCType.get_general_type(profile.ioc_type)

    # All sources that support this IOC type
    all_sources = Source.objects.filter(is_active=True).order_by("priority")
    compatible_sources = [s for s in all_sources if s.supports_ioc_type(profile.ioc_type)]

    # Current selections
    current_configs = {
        sc.source_id: sc
        for sc in profile.source_configs.select_related("source").prefetch_related("expected_fields__available_field")
    }

    if request.method == "POST":
        selected_source_ids = request.POST.getlist("sources")

        with transaction.atomic():
            # Remove deselected sources
            profile.source_configs.exclude(source_id__in=selected_source_ids).delete()

            # Add/update selected sources
            for priority, source_id_str in enumerate(selected_source_ids, start=1):
                source_id = int(source_id_str)
                psc, created = ProfileSourceConfig.objects.get_or_create(
                    profile=profile,
                    source_id=source_id,
                    defaults={"priority": priority},
                )
                if not created:
                    psc.priority = priority
                    psc.save(update_fields=["priority"])

        messages.success(request, "Sources updated. Now configure expected fields.")
        return redirect("profiles:edit_fields", pk=profile.pk)

    # Build source data for template
    sources_data = []
    for source in compatible_sources:
        config = current_configs.get(source.id)
        field_count = AvailableField.objects.filter(
            source=source,
            ioc_type=profile.ioc_type,
        ).count()
        sources_data.append({
            "source": source,
            "is_selected": config is not None,
            "field_count": field_count,
        })

    return render(request, "profiles/edit_sources.html", {
        "profile": profile,
        "sources_data": sources_data,
    })


@login_required
def profile_edit_fields(request, pk):
    """Step 3: For each selected source, choose which fields to expect."""
    profile = get_object_or_404(InvestigationProfile, pk=pk, owner=request.user, is_default=False)
    source_configs = (
        profile.source_configs
        .select_related("source")
        .prefetch_related("expected_fields__available_field")
        .order_by("priority")
    )

    if not source_configs.exists():
        messages.warning(request, "Select at least one source first.")
        return redirect("profiles:edit_sources", pk=profile.pk)

    if request.method == "POST":
        with transaction.atomic():
            for sc in source_configs:
                # Clear existing expected fields for this source config
                sc.expected_fields.all().delete()

                # Get selected field IDs for this source
                field_key = f"fields_{sc.source.id}"
                selected_field_ids = request.POST.getlist(field_key)
                required_key = f"required_{sc.source.id}"
                required_field_ids = request.POST.getlist(required_key)

                field_objects = []
                for field_id_str in selected_field_ids:
                    field_id = int(field_id_str)
                    field_objects.append(
                        ExpectedField(
                            profile_source=sc,
                            available_field_id=field_id,
                            is_required=(field_id_str in required_field_ids),
                        )
                    )
                ExpectedField.objects.bulk_create(field_objects)

        messages.success(request, f'Profile "{profile.name}" saved successfully.')
        return redirect("profiles:detail", pk=profile.pk)

    # Build field data for each source config
    configs_with_fields = []
    for sc in source_configs:
        available = AvailableField.objects.filter(
            source=sc.source,
            ioc_type=profile.ioc_type,
        ).order_by("classification", "normalized_name")

        current_expected_ids = set(
            sc.expected_fields.values_list("available_field_id", flat=True)
        )
        current_required_ids = set(
            sc.expected_fields.filter(is_required=True).values_list("available_field_id", flat=True)
        )

        fields_data = []
        for af in available:
            fields_data.append({
                "field": af,
                "is_selected": af.id in current_expected_ids,
                "is_required": af.id in current_required_ids,
            })

        configs_with_fields.append({
            "config": sc,
            "fields_data": fields_data,
        })

    return render(request, "profiles/edit_fields.html", {
        "profile": profile,
        "configs_with_fields": configs_with_fields,
    })


@login_required
def profile_delete(request, pk):
    """Delete a custom profile."""
    profile = get_object_or_404(InvestigationProfile, pk=pk, owner=request.user, is_default=False)

    if request.method == "POST":
        name = profile.name
        profile.delete()
        messages.success(request, f'Profile "{name}" deleted.')
        return redirect("profiles:list")

    return render(request, "profiles/delete_confirm.html", {"profile": profile})


@login_required
def profile_clone(request, pk):
    """Clone a default (or any) profile into user's own profiles."""
    original = get_object_or_404(InvestigationProfile, pk=pk)

    with transaction.atomic():
        # Create the clone
        clone = InvestigationProfile.objects.create(
            owner=request.user,
            name=f"{original.name} (Copy)",
            description=original.description,
            ioc_type=original.ioc_type,
            is_default=False,
        )

        # Clone source configs and expected fields
        for sc in original.source_configs.all():
            new_sc = ProfileSourceConfig.objects.create(
                profile=clone,
                source=sc.source,
                priority=sc.priority,
                is_enabled=sc.is_enabled,
                timeout_seconds=sc.timeout_seconds,
            )
            for ef in sc.expected_fields.all():
                ExpectedField.objects.create(
                    profile_source=new_sc,
                    available_field=ef.available_field,
                    is_required=ef.is_required,
                )

    messages.success(request, f'Cloned "{original.name}" into your profiles.')
    return redirect("profiles:detail", pk=clone.pk)
