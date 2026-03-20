"""
Audit middleware for SOC Forge.
Automatically logs significant user actions (POST, PUT, PATCH, DELETE).
"""

import logging

from apps.core.utils import get_client_ip

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """
    Records state-changing requests to the AuditLog.
    Skips static files, debug toolbar, and unauthenticated requests.
    """

    EXCLUDED_PATHS = ("/static/", "/__debug__/", "/favicon.ico", "/admin/jsi18n/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if self._should_log(request):
            self._create_log(request)

        return response

    def _should_log(self, request) -> bool:
        """Determine if this request should be logged."""
        # Only log state-changing methods
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return False

        # Skip excluded paths
        if any(request.path.startswith(p) for p in self.EXCLUDED_PATHS):
            return False

        # Only log authenticated users
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False

        return True

    def _create_log(self, request):
        """Create an audit log entry. Fails silently to not break the request."""
        try:
            # Import here to avoid circular imports
            from apps.users.models import AuditLog

            AuditLog.objects.create(
                user=request.user,
                action=self._get_action(request),
                target_type=getattr(request.resolver_match, "url_name", "") or "",
                detail={
                    "method": request.method,
                    "path": request.path,
                },
                ip_address=get_client_ip(request),
            )
        except Exception:
            logger.exception("Failed to create audit log entry")

    def _get_action(self, request) -> str:
        """Infer the action type from the request."""
        path = request.path.lower()
        if "login" in path:
            return "login"
        if "logout" in path:
            return "logout"

        method_map = {
            "POST": "create",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "delete",
        }
        return method_map.get(request.method, "query")
