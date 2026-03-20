from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.sources.models import Source
from apps.profiles.models import InvestigationProfile
from apps.investigations.models import Investigation
from apps.community.models import CommunityIndicator


@login_required
def dashboard(request):
    """Main dashboard view with real stats."""
    context = {
        "active_sources": Source.objects.filter(is_active=True).count(),
        "my_profiles": InvestigationProfile.objects.filter(owner=request.user, is_default=False).count(),
        "default_profiles": InvestigationProfile.objects.filter(is_default=True).count(),
        "my_investigations": Investigation.objects.filter(analyst=request.user).count(),
        "community_iocs": CommunityIndicator.objects.count(),
    }
    return render(request, "users/dashboard.html", context)
