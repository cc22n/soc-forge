"""
Base adapter for threat intelligence API sources.

All API adapters inherit from BaseAdapter and implement:
- _build_request() → prepare the HTTP request
- _parse_response() → extract normalized fields from the raw response

The base class handles:
- HTTP execution with timeout and error handling
- Response time tracking
- API key retrieval from settings
- Logging
"""

import logging
import time
from abc import ABC, abstractmethod

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from django.conf import settings

from apps.core.enums import ResultStatus
from apps.core.exceptions import RateLimitExceededError, SourceUnavailableError

logger = logging.getLogger(__name__)


class AdapterResult:
    """Result from a single adapter query — one field."""

    __slots__ = ("field_name", "value", "status", "raw_snippet")

    def __init__(self, field_name: str, value=None, status: str = ResultStatus.FOUND, raw_snippet=None):
        self.field_name = field_name
        self.value = value
        self.status = status
        self.raw_snippet = raw_snippet

    def __repr__(self):
        return f"AdapterResult({self.field_name}={self.value}, status={self.status})"


class AdapterResponse:
    """Full response from an adapter — all fields + metadata."""

    def __init__(self, source_slug: str = ""):
        self.source_slug: str = source_slug
        self.results: list[AdapterResult] = []
        self.response_time_ms: int = 0
        self.raw_response: dict | None = None
        self.error: str = ""
        self.success: bool = False

    def add(self, field_name: str, value, status: str = ResultStatus.FOUND):
        self.results.append(AdapterResult(field_name, value, status))

    def add_error(self, field_name: str, error_msg: str = ""):
        self.results.append(AdapterResult(field_name, None, ResultStatus.ERROR))


class BaseAdapter(ABC):
    """
    Abstract base class for all threat intelligence API adapters.

    Subclasses must define:
        SOURCE_SLUG: str — matches the Source.slug in the database
        SUPPORTED_IOC_TYPES: list[str] — e.g., ["hash", "ip", "domain"]

    And implement:
        _build_request(ioc_value, ioc_type) → dict with url, headers, params, etc.
        _parse_response(raw_json, ioc_type, expected_fields) → list[AdapterResult]

    Optional class-level flags:
        REQUIRES_API_KEY — set False for APIs that work without authentication
                           (URLhaus, MalwareBazaar, ThreatFox). When True and the
                           key is empty, the query is skipped cleanly instead of
                           making a request that will 401.
        NOT_FOUND_IS_VALID — set True for sources where HTTP 404 means "this IOC
                              is not in our database" (GreyNoise, Shodan,
                              SecurityTrails). Without this flag a 404 is logged
                              as a SourceUnavailableError which fills logs with
                              false positives for unknown IPs/domains.
    """

    SOURCE_SLUG: str = ""
    SUPPORTED_IOC_TYPES: list[str] = []
    DEFAULT_TIMEOUT: int = 30
    REQUIRES_API_KEY: bool = True
    NOT_FOUND_IS_VALID: bool = False
    # THREAT_INTEL_KEYS entry to read the key from; defaults to SOURCE_SLUG.
    # Lets several adapters share one credential (abuse.ch family).
    API_KEY_SLUG: str = ""
    # On HTTP 429, retry once if the server's Retry-After is at most this many
    # seconds; longer waits fail fast so they don't eat the investigation budget.
    MAX_RETRY_AFTER_WAIT: int = 15

    # Transparent retries for transient failures: connection errors and 5xx.
    # raise_on_status=False returns the last response so the normal >=400
    # handling below still applies; 429 is excluded because it has its own
    # Retry-After-aware handling in query().
    _RETRY_STRATEGY = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
        respect_retry_after_header=False,
    )

    def __init__(self):
        self.api_key = self._get_api_key()
        self.session = requests.Session()
        http_adapter = HTTPAdapter(max_retries=self._RETRY_STRATEGY)
        self.session.mount("https://", http_adapter)
        self.session.mount("http://", http_adapter)

    def _get_api_key(self) -> str:
        """Retrieve API key from Django settings."""
        keys = getattr(settings, "THREAT_INTEL_KEYS", {})
        return keys.get(self.API_KEY_SLUG or self.SOURCE_SLUG, "")

    def supports(self, ioc_type: str) -> bool:
        """Check if this adapter can handle the given IOC type."""
        from apps.core.enums import IOCType
        general = IOCType.get_general_type(ioc_type)
        return general in self.SUPPORTED_IOC_TYPES or ioc_type in self.SUPPORTED_IOC_TYPES

    def query(self, ioc_value: str, ioc_type: str, expected_fields: list[str] | None = None,
              timeout: int | None = None) -> AdapterResponse:
        """
        Execute a query against this source.

        Args:
            ioc_value: The IOC to look up
            ioc_type: Type from IOCType enum
            expected_fields: List of normalized field names to extract (None = all)
            timeout: Request timeout in seconds

        Returns:
            AdapterResponse with results and metadata
        """
        response = AdapterResponse(source_slug=self.SOURCE_SLUG)
        timeout = timeout or self.DEFAULT_TIMEOUT

        # Skip the HTTP round-trip entirely when the key is absent.  A missing
        # key causes a 401/403 which would be logged as an error and counted
        # against the investigation's coverage score unfairly.  No field rows
        # are recorded: an unconfigured source is "not consulted", not failed.
        if self.REQUIRES_API_KEY and not self.api_key:
            response.error = f"{self.SOURCE_SLUG} not configured (missing API key)"
            logger.info("Skipping %s — API key not set", self.SOURCE_SLUG)
            return response

        try:
            # Build the request
            req = self._build_request(ioc_value, ioc_type)
            method = req.pop("method", "GET")
            url = req.pop("url")
            headers = req.pop("headers", {})
            params = req.pop("params", {})
            json_body = req.pop("json", None)
            data_body = req.pop("data", None)

            # Execute with timing
            start = time.monotonic()
            http_response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=data_body,
                timeout=timeout,
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            response.response_time_ms = elapsed_ms

            # Check for rate limiting — honor short Retry-After hints with a
            # single retry; anything longer fails fast.
            if http_response.status_code == 429:
                retry_after = self._parse_retry_after(http_response)
                if retry_after is not None and 0 < retry_after <= self.MAX_RETRY_AFTER_WAIT:
                    logger.info(
                        "[%s] HTTP 429, retrying once after %ds (Retry-After)",
                        self.SOURCE_SLUG, retry_after,
                    )
                    time.sleep(retry_after)
                    http_response = self.session.request(
                        method=method, url=url, headers=headers, params=params,
                        json=json_body, data=data_body, timeout=timeout,
                    )
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    response.response_time_ms = elapsed_ms
                if http_response.status_code == 429:
                    raise RateLimitExceededError(self.SOURCE_SLUG, retry_after)

            # 404 on sources where it means "IOC not in database" (GreyNoise,
            # Shodan, SecurityTrails…) should be treated as zero results, not
            # as a service failure.
            if http_response.status_code == 404 and self.NOT_FOUND_IS_VALID:
                logger.info("[%s] IOC not found in source (HTTP 404)", self.SOURCE_SLUG)
                response.success = True
                response.response_time_ms = elapsed_ms
                # Record NOT_FOUND per expected field so the UI shows "no
                # data" for this source instead of an empty gap.
                if expected_fields:
                    for field in expected_fields:
                        response.add(field, None, ResultStatus.NOT_FOUND)
                return response

            # Check for errors
            if http_response.status_code >= 400:
                raise SourceUnavailableError(
                    self.SOURCE_SLUG,
                    f"HTTP {http_response.status_code}: {http_response.text[:200]}",
                )

            # Parse the response
            raw_json = http_response.json()
            response.raw_response = raw_json
            response.results = self._parse_response(raw_json, ioc_type, expected_fields)
            response.success = True

            logger.info(
                "[%s] Query for %s:%s -> %d fields in %dms",
                self.SOURCE_SLUG, ioc_type, ioc_value[:30], len(response.results), elapsed_ms,
            )

        except RateLimitExceededError:
            response.error = f"Rate limit exceeded for {self.SOURCE_SLUG}"
            logger.warning("Rate limit exceeded for %s", self.SOURCE_SLUG)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.TIMEOUT)

        except SourceUnavailableError as e:
            response.error = str(e)
            logger.error("Source unavailable — %s: %s", self.SOURCE_SLUG, e)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.ERROR)

        except requests.Timeout:
            response.error = f"Timeout after {timeout}s for {self.SOURCE_SLUG}"
            logger.warning("Timeout after %ds for %s", timeout, self.SOURCE_SLUG)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.TIMEOUT)

        except requests.ConnectionError:
            response.error = f"Connection error for {self.SOURCE_SLUG}"
            logger.error("Connection error for %s", self.SOURCE_SLUG)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.ERROR)

        except Exception as e:
            response.error = f"Unexpected error for {self.SOURCE_SLUG}: {str(e)}"
            logger.exception("Unexpected error for %s", self.SOURCE_SLUG)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.ERROR)

        return response

    @abstractmethod
    def _build_request(self, ioc_value: str, ioc_type: str) -> dict:
        """
        Build the HTTP request parameters.

        Must return a dict with at least 'url'. Can include:
        - method (default GET)
        - url (required)
        - headers
        - params (query string)
        - json (JSON body)
        - data (form body)
        """
        ...

    @abstractmethod
    def _parse_response(self, raw: dict, ioc_type: str,
                        expected_fields: list[str] | None) -> list[AdapterResult]:
        """
        Parse the raw JSON response and extract normalized fields.

        Args:
            raw: The raw JSON response from the API
            ioc_type: The IOC type that was queried
            expected_fields: Fields to extract (None = all available)

        Returns:
            List of AdapterResult objects
        """
        ...

    @staticmethod
    def _parse_retry_after(http_response) -> int | None:
        """Parse the Retry-After header (seconds form only; HTTP-date → None)."""
        value = http_response.headers.get("Retry-After")
        if not value:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _safe_get(self, data: dict, path: str, default=None):
        """
        Safely traverse a nested dict using dot notation.
        Example: _safe_get(data, "a.b.c") → data["a"]["b"]["c"]
        """
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
            if current is None:
                return default
        return current

    def _make_result(self, field_name: str, value, expected_fields: list[str] | None) -> AdapterResult | None:
        """Create a result only if the field is expected (or all fields are expected)."""
        if expected_fields is not None and field_name not in expected_fields:
            return None
        if value is None or value == "" or value == []:
            return AdapterResult(field_name, None, ResultStatus.NOT_FOUND)
        return AdapterResult(field_name, value, ResultStatus.FOUND)

    def _collect(self, results: list, field_name: str, value, expected_fields):
        """Helper to add a result to the list if applicable."""
        result = self._make_result(field_name, value, expected_fields)
        if result is not None:
            results.append(result)
