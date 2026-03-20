"""
Shared utility functions for SOC Forge.
"""

from django.utils import timezone


def get_client_ip(request) -> str:
    """Extract the real client IP from a Django request, handling proxies."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def is_stale(timestamp, ttl_seconds: int) -> bool:
    """Check if a timestamp is older than the given TTL."""
    if timestamp is None:
        return True
    age = (timezone.now() - timestamp).total_seconds()
    return age > ttl_seconds
