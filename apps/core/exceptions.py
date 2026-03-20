"""
Custom domain exceptions for SOC Forge.
"""


class SOCForgeError(Exception):
    """Base exception for SOC Forge."""

    pass


class SourceUnavailableError(SOCForgeError):
    """Raised when a threat intelligence API source is unreachable or returns an error."""

    def __init__(self, source_name: str, detail: str = ""):
        self.source_name = source_name
        self.detail = detail
        super().__init__(f"Source '{source_name}' unavailable: {detail}")


class RateLimitExceededError(SOCForgeError):
    """Raised when an API rate limit is exceeded."""

    def __init__(self, source_name: str, retry_after: int | None = None):
        self.source_name = source_name
        self.retry_after = retry_after
        msg = f"Rate limit exceeded for '{source_name}'"
        if retry_after:
            msg += f". Retry after {retry_after}s"
        super().__init__(msg)


class InvalidIOCError(SOCForgeError):
    """Raised when an IOC value doesn't match its declared type."""

    pass


class ProfileConfigError(SOCForgeError):
    """Raised when an investigation profile has invalid configuration."""

    pass
