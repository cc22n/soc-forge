"""
Security middleware for SOC Forge.

Provides:
- Per-user investigation rate limiting (cache-backed: Redis in production, LocMem in dev)
- Input sanitization for IOC values
- Additional security headers beyond Django defaults
"""

import logging
import re

from django.core.cache import caches

logger = logging.getLogger(__name__)


class RateLimitMiddleware:
    """
    Cache-backed rate limiter for investigation queries.
    Limits authenticated users to N investigation submissions per minute.

    Uses the 'rate_limit' cache alias (Redis if REDIS_URL is configured,
    otherwise LocMemCache for development). Works correctly across multiple
    Gunicorn workers when Redis is configured.
    """

    RATE_LIMIT = 10
    WINDOW_SECONDS = 60
    _CACHE_PREFIX = "rl:inv:"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.method == "POST"
            and request.path == "/investigations/new/"
            and hasattr(request, "user")
            and request.user.is_authenticated
        ):
            if not self._allow_request(request.user.pk):
                logger.warning(
                    f"Rate limit exceeded for user {request.user.username} "
                    f"on {request.path}"
                )
                from django.contrib import messages
                from django.shortcuts import redirect

                messages.error(
                    request,
                    f"Rate limit exceeded. Maximum {self.RATE_LIMIT} investigations "
                    f"per minute. Please wait and try again.",
                )
                return redirect("investigations:new")

        return self.get_response(request)

    def _allow_request(self, user_id: int) -> bool:
        """
        Returns True if the request is within the rate limit.
        Uses atomic cache operations: add (create-if-missing) + incr.
        """
        cache = caches["rate_limit"]
        key = f"{self._CACHE_PREFIX}{user_id}"
        # add() sets key with value 1 only if it doesn't exist; returns True if created
        if cache.add(key, 1, timeout=self.WINDOW_SECONDS):
            return True
        try:
            count = cache.incr(key)
        except ValueError:
            # Key expired between add() check and incr() — safe to allow and reset
            cache.set(key, 1, timeout=self.WINDOW_SECONDS)
            return True
        return count <= self.RATE_LIMIT


class SecurityHeadersMiddleware:
    """
    Additional security headers beyond what Django provides by default.
    Reinforces defense-in-depth.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Prevent MIME type sniffing
        response["X-Content-Type-Options"] = "nosniff"

        # Referrer policy — only send origin for cross-origin requests
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy — disable unnecessary browser features
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=()"
        )

        # Prevent the page from being embedded (already set by Django but reinforce)
        response["X-Frame-Options"] = "DENY"

        # Cache control for authenticated pages
        if hasattr(request, "user") and request.user.is_authenticated:
            if not request.path.startswith("/static/"):
                response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
                response["Pragma"] = "no-cache"

        return response


class IOCSanitizationMiddleware:
    """
    Sanitize IOC input values to prevent injection attacks.
    Applied to POST requests that contain IOC values.
    """

    # Patterns that should NEVER appear in IOC values
    DANGEROUS_PATTERNS = [
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # onclick=, onerror=, etc.
        re.compile(r"UNION\s+SELECT", re.IGNORECASE),
        re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE)\s", re.IGNORECASE),
        re.compile(r"\.\./\.\./"),  # Path traversal
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "POST" and "ioc_value" in request.POST:
            ioc_value = request.POST.get("ioc_value", "")
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern.search(ioc_value):
                    logger.warning(
                        f"Blocked suspicious IOC input from "
                        f"{request.user.username if request.user.is_authenticated else 'anon'}: "
                        f"{ioc_value[:100]}"
                    )
                    from django.contrib import messages

                    messages.error(request, "Invalid input detected.")
                    from django.shortcuts import redirect

                    return redirect("investigations:new")

        return self.get_response(request)
