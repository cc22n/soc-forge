import logging
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.decorators import login_required
from django.core.cache import caches
from django.db.models import Avg, Count, F, Q
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from apps.community.models import CommunityIndicator
from apps.core.enums import ResultStatus
from apps.core.mixins import org_investigations_filter
from apps.investigations.models import Investigation, InvestigationResult
from apps.profiles.models import InvestigationProfile
from apps.sources.models import Source

from .forms import RegistrationForm

logger = logging.getLogger(__name__)
User = get_user_model()

# Registration IP rate limit: max 5 attempts per 10 minutes per IP
_REG_LIMIT = 5
_REG_WINDOW = 600  # seconds
_REG_CACHE_PREFIX = "rl:reg:"


def _get_client_ip(request) -> str:
    """Return the client IP, preferring REMOTE_ADDR (not spoofable)."""
    return request.META.get("REMOTE_ADDR", "unknown")


def _registration_allowed(ip: str) -> bool:
    """
    IP-based rate limit for registration endpoint.
    Returns True if the IP is within the allowed limit.
    Uses the same atomic cache pattern as RateLimitMiddleware.
    """
    cache = caches["rate_limit"]
    key = f"{_REG_CACHE_PREFIX}{ip}"
    if cache.add(key, 1, timeout=_REG_WINDOW):
        return True
    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=_REG_WINDOW)
        return True
    return count <= _REG_LIMIT


def home(request):
    """
    Public landing page.
    Authenticated users are redirected directly to the dashboard.
    """
    if request.user.is_authenticated:
        return redirect("users:dashboard")
    return render(request, "home.html")


@require_http_methods(["GET", "POST"])
def register(request):
    """
    User registration view.

    Security:
    - IP-based rate limit (5 attempts / 10 min) via cache
    - CSRF enforced by Django middleware
    - Password strength validated by AUTH_PASSWORD_VALIDATORS
    - Username restricted to [a-zA-Z0-9_-] (form clean_username)
    - Email uniqueness enforced (form clean_email)
    - No SQL injection risk — all DB access via Django ORM (parameterized)
    - Redirects authenticated users away (no double registration)
    - After success: log in immediately and redirect to dashboard
    """
    if request.user.is_authenticated:
        return redirect("users:dashboard")

    if request.method == "POST":
        ip = _get_client_ip(request)
        if not _registration_allowed(ip):
            logger.warning(f"Registration rate limit exceeded from IP {ip}")
            messages.error(
                request,
                "Too many registration attempts. Please wait 10 minutes and try again.",
            )
            return redirect("users:register")

        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            logger.info(f"New user registered: {user.username} from {ip}")
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            messages.success(request, f"Welcome to SOC Forge, {user.username}!")
            return redirect("users:dashboard")
    else:
        form = RegistrationForm()

    return render(request, "registration/register.html", {"form": form})


@login_required
def dashboard(request):
    """Analytics dashboard — aggregated metrics from PostgreSQL."""
    now = timezone.now()
    last_30d = now - timedelta(days=30)
    last_7d = now - timedelta(days=7)

    inv_qs = Investigation.objects.filter(org_investigations_filter(request.user))

    # ── Core counts ──────────────────────────────────────────────
    total_investigations = inv_qs.count()
    investigations_30d = inv_qs.filter(created_at__gte=last_30d).count()
    avg_coverage = inv_qs.filter(
        coverage_score__isnull=False
    ).aggregate(avg=Avg("coverage_score"))["avg"] or 0

    # ── IOC type breakdown ────────────────────────────────────────
    ioc_breakdown = (
        inv_qs
        .values(ioc_type=F("indicator__ioc_type"))
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    # ── Daily investigation volume (last 30 days) ─────────────────
    daily_volume = (
        inv_qs
        .filter(created_at__gte=last_30d)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    # ── Top 5 most investigated IOCs ──────────────────────────────
    top_iocs = (
        inv_qs
        .values(value=F("indicator__value"), ioc_type=F("indicator__ioc_type"))
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )

    # ── Source performance (found rate + avg response time) ───────
    result_qs = InvestigationResult.objects.filter(
        investigation__in=inv_qs,
        investigation__created_at__gte=last_30d,
    )
    source_stats = (
        result_qs
        .values(source_name=F("source__name"))
        .annotate(
            total=Count("id"),
            found=Count("id", filter=Q(status=ResultStatus.FOUND)),
            errors=Count("id", filter=Q(status__in=[ResultStatus.ERROR, ResultStatus.TIMEOUT])),
            avg_ms=Avg("response_time_ms"),
        )
        .order_by("-found")[:10]
    )
    # Compute found_rate in Python (avoid DB-level division)
    source_stats_list = [
        {
            **s,
            "found_rate": round(s["found"] / s["total"] * 100, 1) if s["total"] else 0,
        }
        for s in source_stats
    ]

    # ── Recent activity ───────────────────────────────────────────
    recent_investigations = (
        inv_qs
        .select_related("indicator", "profile_used", "analyst")
        .order_by("-created_at")[:8]
    )

    context = {
        # Counts
        "active_sources": Source.objects.filter(is_active=True).count(),
        "my_profiles": InvestigationProfile.objects.filter(owner=request.user, is_default=False).count(),
        "default_profiles": InvestigationProfile.objects.filter(is_default=True).count(),
        "total_investigations": total_investigations,
        "investigations_30d": investigations_30d,
        "avg_coverage": round(avg_coverage, 1),
        "community_iocs": CommunityIndicator.objects.count(),
        # Analytics
        "ioc_breakdown": list(ioc_breakdown),
        "daily_volume": list(daily_volume),
        "top_iocs": list(top_iocs),
        "source_stats": source_stats_list,
        # Recent
        "recent_investigations": recent_investigations,
    }
    return render(request, "users/dashboard.html", context)
