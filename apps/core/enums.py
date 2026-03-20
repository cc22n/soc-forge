"""
Domain enums for SOC Forge.
Centralized here so any app can import them.

Usage:
    from apps.core.enums import IOCType, FieldClassification
"""

from django.db import models


class IOCType(models.TextChoices):
    """Types of Indicators of Compromise supported by the system."""

    HASH_MD5 = "hash_md5", "Hash MD5"
    HASH_SHA1 = "hash_sha1", "Hash SHA1"
    HASH_SHA256 = "hash_sha256", "Hash SHA256"
    IP = "ip", "IP Address"
    DOMAIN = "domain", "Domain"
    URL = "url", "URL"

    @classmethod
    def hash_types(cls):
        """Return all hash-type IOCs."""
        return [cls.HASH_MD5, cls.HASH_SHA1, cls.HASH_SHA256]

    @classmethod
    def get_general_type(cls, ioc_type):
        """Map specific hash types to general 'hash' for API lookups.
        Accepts both enum members and plain strings."""
        # Handle both enum and string
        val = ioc_type.value if hasattr(ioc_type, 'value') else str(ioc_type)
        if val in ("hash_md5", "hash_sha1", "hash_sha256"):
            return "hash"
        return val


class FieldClassification(models.TextChoices):
    """Priority classification for expected fields in investigation profiles."""

    REQUIRED = "required", "Required"
    CORE = "core", "Core"
    OPTIONAL = "optional", "Optional"


class InvestigationStatus(models.TextChoices):
    """Status of an investigation execution."""

    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    PARTIAL = "partial", "Partial"  # Some APIs failed but others succeeded
    ERROR = "error", "Error"


class ResultStatus(models.TextChoices):
    """Status of a single field result from an API query."""

    FOUND = "found", "Found"
    NOT_FOUND = "not_found", "Not Found"
    ERROR = "error", "Error"
    TIMEOUT = "timeout", "Timeout"


class UserRole(models.TextChoices):
    """User roles in the SOC Forge system."""

    ANALYST = "analyst", "Analyst"
    ADMIN = "admin", "Admin"


class AuditAction(models.TextChoices):
    """Actions tracked in the audit log."""

    LOGIN = "login", "Login"
    LOGOUT = "logout", "Logout"
    QUERY = "query", "API Query"
    CREATE = "create", "Create"
    UPDATE = "update", "Update"
    DELETE = "delete", "Delete"
    SHARE = "share", "Share to Community"


class VoteType(models.TextChoices):
    """Types of confidence votes on community results."""

    CONFIRM = "confirm", "Confirm"
    DISPUTE = "dispute", "Dispute"


class AuthType(models.TextChoices):
    """Authentication methods for threat intelligence API sources."""

    HEADER = "header", "Header"
    QUERY_PARAM = "query_param", "Query Parameter"
    BASIC_AUTH = "basic_auth", "Basic Auth"
    BODY_PARAM = "body_param", "Body Parameter"
    NONE = "none", "No Authentication"