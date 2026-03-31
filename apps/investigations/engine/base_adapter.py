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
    """

    SOURCE_SLUG: str = ""
    SUPPORTED_IOC_TYPES: list[str] = []
    DEFAULT_TIMEOUT: int = 30

    def __init__(self):
        self.api_key = self._get_api_key()
        self.session = requests.Session()

    def _get_api_key(self) -> str:
        """Retrieve API key from Django settings."""
        keys = getattr(settings, "THREAT_INTEL_KEYS", {})
        return keys.get(self.SOURCE_SLUG, "")

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

            # Check for rate limiting
            if http_response.status_code == 429:
                retry_after = http_response.headers.get("Retry-After")
                raise RateLimitExceededError(
                    self.SOURCE_SLUG,
                    int(retry_after) if retry_after else None,
                )

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
                f"[{self.SOURCE_SLUG}] Query for {ioc_type}:{ioc_value[:30]} "
                f"→ {len(response.results)} fields in {elapsed_ms}ms"
            )

        except RateLimitExceededError:
            response.error = f"Rate limit exceeded for {self.SOURCE_SLUG}"
            logger.warning(response.error)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.TIMEOUT)

        except SourceUnavailableError as e:
            response.error = str(e)
            logger.error(response.error)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.ERROR)

        except requests.Timeout:
            response.error = f"Timeout after {timeout}s for {self.SOURCE_SLUG}"
            logger.warning(response.error)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.TIMEOUT)

        except requests.ConnectionError:
            response.error = f"Connection error for {self.SOURCE_SLUG}"
            logger.error(response.error)
            if expected_fields:
                for field in expected_fields:
                    response.add(field, None, ResultStatus.ERROR)

        except Exception as e:
            response.error = f"Unexpected error for {self.SOURCE_SLUG}: {str(e)}"
            logger.exception(response.error)
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
