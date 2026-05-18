"""
Shared utility functions for SOC Forge.
"""

from django.utils import timezone


def get_client_ip(request) -> str:
    """
    Extract the real client IP from a Django request.

    WARNING: HTTP_X_FORWARDED_FOR is trivially spoofable by any client unless
    your deployment guarantees that only a trusted reverse proxy sets this
    header (e.g. nginx/Gunicorn with SECURE_PROXY_SSL_HEADER configured).
    In production, use REMOTE_ADDR exclusively or validate the header source.
    For now we use REMOTE_ADDR for security-sensitive paths (rate limiting,
    audit log) and only fall back to X-Forwarded-For for logging context.
    """
    return request.META.get("REMOTE_ADDR", "unknown")


def is_stale(timestamp, ttl_seconds: int) -> bool:
    """Check if a timestamp is older than the given TTL."""
    if timestamp is None:
        return True
    age = (timezone.now() - timestamp).total_seconds()
    return age > ttl_seconds
