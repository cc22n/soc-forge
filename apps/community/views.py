import logging
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count, Q, Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from apps.core.enums import ResultStatus, VoteType
from apps.investigations.models import Investigation, InvestigationResult

from django.db import models as django_models
from django.db.models.functions import Greatest

from apps.users.models import UserReputation

from .models import CommunityIndicator, CommunityNote, CommunityResult, ConfidenceVote

# Max community result submissions per hour per user (throttle)
_COMMUNITY_THROTTLE_LIMIT = 30
_COMMUNITY_THROTTLE_WINDOW = 3600

logger = logging.getLogger(__name__)


@login_required
def community_search(request):
    """Search the community knowledge base."""
    query = request.GET.get("q", "").strip()
    ioc_filter = request.GET.get("type", "")

    indicators = CommunityIndicator.objects.select_related(
        "indicator", "first_seen_by"
    ).annotate(
        result_count=Count("results"),
        note_count=Count("notes"),
    ).order_by("-last_enriched_at")

    if query:
        indicators = indicators.filter(indicator__value__icontains=query)
    if ioc_filter:
        indicators = indicators.filter(indicator__ioc_type=ioc_filter)

    # Stats
    total_indicators = CommunityIndicator.objects.count()
    total_results = CommunityResult.objects.count()
    total_contributors = CommunityResult.objects.values("contributed_by").distinct().count()

    return render(request, "community/search.html", {
        "indicators": indicators[:50],
        "query": query,
        "ioc_filter": ioc_filter,
        "total_indicators": total_indicators,
        "total_results": total_results,
        "total_contributors": total_contributors,
    })


@login_required
def community_detail(request, pk):
    """View a community indicator with all shared results and notes."""
    community_indicator = get_object_or_404(
        CommunityIndicator.objects.select_related("indicator", "first_seen_by"),
        pk=pk,
    )

    results = (
        CommunityResult.objects
        .filter(community_indicator=community_indicator)
        .select_related("source", "contributed_by")
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
            }
        results_by_source[source_name]["results"].append(r)

    notes = (
        CommunityNote.objects
        .filter(community_indicator=community_indicator)
        .select_related("author")
        .order_by("-created_at")
    )

    # Check user's votes on results
    user_votes = {}
    if request.user.is_authenticated:
        votes = ConfidenceVote.objects.filter(
            community_result__community_indicator=community_indicator,
            voter=request.user,
        ).values_list("community_result_id", "vote")
        user_votes = dict(votes)

    return render(request, "community/detail.html", {
        "ci": community_indicator,
        "results_by_source": results_by_source,
        "notes": notes,
        "total_results": results.count(),
        "user_votes": user_votes,
    })


@login_required
def share_investigation(request, investigation_pk):
    """Share an investigation's results to the community knowledge base."""
    investigation = get_object_or_404(
        Investigation.objects.select_related("indicator"),
        pk=investigation_pk,
        analyst=request.user,
    )

    if investigation.shared_to_community:
        messages.info(request, "This investigation has already been shared.")
        return redirect("investigations:detail", pk=investigation_pk)

    if request.method == "POST":
        # Throttle: limit community submissions per user per hour
        from django.core.cache import caches
        cache = caches["rate_limit"]
        throttle_key = f"community_share:{request.user.pk}"
        if not cache.add(throttle_key, 1, timeout=_COMMUNITY_THROTTLE_WINDOW):
            try:
                count = cache.incr(throttle_key)
            except ValueError:
                cache.set(throttle_key, 1, timeout=_COMMUNITY_THROTTLE_WINDOW)
                count = 1
            if count > _COMMUNITY_THROTTLE_LIMIT:
                messages.error(request, f"Sharing limit reached ({_COMMUNITY_THROTTLE_LIMIT}/hour). Please wait.")
                return redirect("investigations:detail", pk=investigation_pk)

        with transaction.atomic():
            # Get or create community indicator
            ci, ci_created = CommunityIndicator.objects.get_or_create(
                indicator=investigation.indicator,
                defaults={
                    "first_seen_by": request.user,
                },
            )

            if not ci_created:
                ci.times_investigated += 1
                ci.last_enriched_at = timezone.now()
                ci.save(update_fields=["times_investigated", "last_enriched_at"])

            # Copy found results to community
            inv_results = InvestigationResult.objects.filter(
                investigation=investigation,
                status=ResultStatus.FOUND,
            ).select_related("source")

            shared_count = 0
            for r in inv_results:
                source_ttl = r.source.default_ttl_seconds if r.source else 0
                cutoff = timezone.now() - timedelta(seconds=source_ttl) if source_ttl > 0 else None

                existing = CommunityResult.objects.filter(
                    community_indicator=ci,
                    source=r.source,
                    field_name=r.field_name,
                ).first()

                if existing is None:
                    CommunityResult.objects.create(
                        community_indicator=ci,
                        source=r.source,
                        field_name=r.field_name,
                        value=r.value,
                        contributed_by=request.user,
                    )
                    shared_count += 1
                elif cutoff and existing.contributed_at < cutoff:
                    # Stale result — update with fresh data
                    CommunityResult.objects.filter(pk=existing.pk).update(
                        value=r.value,
                        contributed_by=request.user,
                        contributed_at=timezone.now(),
                    )
                    shared_count += 1
                # else: fresh existing result — skip

            # Mark investigation as shared
            investigation.shared_to_community = True
            investigation.save(update_fields=["shared_to_community"])

            # Update contributor reputation
            if shared_count > 0:
                rep = UserReputation.get_or_create_for(request.user)
                rep.total_contributions = django_models.F("total_contributions") + shared_count
                rep.save(update_fields=["total_contributions"])

        messages.success(
            request,
            f"Shared {shared_count} results to the community knowledge base."
        )
        return redirect("community:detail", pk=ci.pk)

    # GET — show confirmation
    found_results = InvestigationResult.objects.filter(
        investigation=investigation,
        status=ResultStatus.FOUND,
    ).count()

    return render(request, "community/share_confirm.html", {
        "investigation": investigation,
        "found_results": found_results,
    })


@login_required
def community_vote(request, result_pk, vote_type):
    """Vote to confirm or dispute a community result."""
    if request.method != "POST":
        return redirect("community:search")

    community_result = get_object_or_404(CommunityResult, pk=result_pk)

    if vote_type not in ("confirm", "dispute"):
        messages.error(request, "Invalid vote type.")
        return redirect("community:detail", pk=community_result.community_indicator.pk)

    # Don't let users vote on their own contributions
    if community_result.contributed_by == request.user:
        messages.warning(request, "You can't vote on your own contribution.")
        return redirect("community:detail", pk=community_result.community_indicator.pk)

    with transaction.atomic():
        vote, created = ConfidenceVote.objects.update_or_create(
            community_result=community_result,
            voter=request.user,
            defaults={"vote": vote_type},
        )

        # Recalculate confidence score
        confirms = ConfidenceVote.objects.filter(
            community_result=community_result,
            vote=VoteType.CONFIRM,
        ).count()
        disputes = ConfidenceVote.objects.filter(
            community_result=community_result,
            vote=VoteType.DISPUTE,
        ).count()
        community_result.confidence_votes = confirms - disputes
        community_result.save(update_fields=["confidence_votes"])

    # Update contributor's reputation on dispute
    if vote_type == VoteType.DISPUTE and community_result.contributed_by:
        rep = UserReputation.get_or_create_for(community_result.contributed_by)
        UserReputation.objects.filter(pk=rep.pk).update(
            disputed_contributions=django_models.F("disputed_contributions") + 1,
            reputation_score=Greatest(
                django_models.F("reputation_score") - 10, 0
            ),
        )

    action = "confirmed" if vote_type == "confirm" else "disputed"
    messages.success(request, f"You {action} this result.")
    return redirect("community:detail", pk=community_result.community_indicator.pk)


@login_required
def community_add_note(request, ci_pk):
    """Add a note to a community indicator."""
    ci = get_object_or_404(CommunityIndicator, pk=ci_pk)

    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        if not content:
            messages.error(request, "Note content is required.")
        elif len(content) > 5000:
            messages.error(request, "Note is too long (max 5000 characters).")
        else:
            CommunityNote.objects.create(
                community_indicator=ci,
                author=request.user,
                content=content,
            )
            messages.success(request, "Note added.")

    return redirect("community:detail", pk=ci.pk)
