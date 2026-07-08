"""
Investigation orchestrator.

Executes a full investigation:
1. Validate the IOC
2. Get or create the Indicator
3. Create an Investigation record
4. For each source in the profile (by priority):
   a. Get the adapter
   b. Query the API
   c. Save results to InvestigationResult
5. Calculate coverage score
6. Return the completed investigation
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import timedelta

from django.conf import settings
from django.core.cache import caches
from django.db import connections, transaction
from django.utils import timezone

from apps.core.enums import IOCType, InvestigationStatus, ResultStatus
from apps.core.validators import detect_ioc_type, validate_ioc
from apps.investigations.models import Indicator, Investigation, InvestigationResult
from apps.profiles.models import InvestigationProfile

from .registry import get_adapter

logger = logging.getLogger(__name__)

# Wall-clock budget for the parallel query phase. When exceeded, results from
# sources that already finished are kept and the stragglers are reported as
# errors — the investigation completes as PARTIAL instead of being lost.
GLOBAL_TIMEOUT_SECONDS = 90

# Preventive throttle: if respecting a source's rate_limit_per_minute would
# require waiting longer than this, skip the source for this investigation.
MAX_RATE_LIMIT_WAIT_SECONDS = 45


def _wait_for_rate_limit(source) -> str:
    """
    Best-effort local throttle based on Source.rate_limit_per_minute.

    Sleeps until the source's minimum interval has passed since our last query
    to it (tracked in the rate_limit cache). Returns "" to proceed, or a skip
    reason when the required wait exceeds MAX_RATE_LIMIT_WAIT_SECONDS.

    Disable with SOURCE_RATE_LIMIT_ENABLED = False (used by the test suite).
    """
    if not getattr(settings, "SOURCE_RATE_LIMIT_ENABLED", True):
        return ""
    rpm = source.rate_limit_per_minute
    if not rpm:
        return ""
    interval = 60.0 / rpm
    cache = caches["rate_limit"]
    key = f"source-last-query:{source.slug}"
    last = cache.get(key)
    if last is not None:
        wait = interval - (time.time() - last)
        if wait > MAX_RATE_LIMIT_WAIT_SECONDS:
            return f"rate limit ({rpm}/min): next query allowed in {int(wait)}s"
        if wait > 0:
            logger.info("Throttling %s for %.1fs (rate limit %d/min)", source.slug, wait, rpm)
            time.sleep(wait)
    cache.set(key, time.time(), timeout=max(int(interval) * 2, 120))
    return ""


class InvestigationOrchestrator:
    """
    Executes an investigation based on a profile and IOC.
    """

    def run(self, user, ioc_value: str, profile: InvestigationProfile,
            investigation: Investigation | None = None) -> Investigation:
        """
        Execute a full investigation.

        Args:
            user: The analyst executing the investigation
            ioc_value: The IOC to investigate
            profile: The investigation profile to use
            investigation: Optional pre-created PENDING placeholder (async
                dispatch flow); reused instead of creating a new record.

        Returns:
            The completed Investigation object
        """
        ioc_value = ioc_value.strip()

        # The profile's ioc_type is the canonical type for DB storage and field matching.
        # For hashes, the profile always uses hash_sha256 as the canonical type.
        profile_ioc_type = profile.ioc_type

        # Detect the actual IOC type for validation purposes
        detected_type = detect_ioc_type(ioc_value)
        if detected_type:
            # Use detected type for validation
            validation_type = detected_type
        else:
            validation_type = profile_ioc_type

        # Validate the IOC format
        try:
            validate_ioc(ioc_value, validation_type)
        except Exception as e:
            logger.error("IOC validation failed: %s", e)
            raise

        # For storage, use the detected type (more specific)
        # But for field matching, always use the profile's ioc_type
        storage_ioc_type = detected_type if detected_type else profile_ioc_type

        with transaction.atomic():
            if investigation is not None:
                # Async flow: reuse the PENDING placeholder created at dispatch.
                indicator = investigation.indicator
                indicator.times_investigated += 1
                indicator.save(update_fields=["times_investigated", "updated_at"])
                investigation.status = InvestigationStatus.RUNNING
                if investigation.started_at is None:
                    investigation.started_at = timezone.now()
                investigation.save(update_fields=["status", "started_at"])
            else:
                # Get or create indicator with the specific detected type
                indicator, created = Indicator.objects.get_or_create(
                    value=ioc_value,
                    ioc_type=storage_ioc_type,
                    defaults={"created_by": user},
                )
                indicator.times_investigated += 1
                indicator.save(update_fields=["times_investigated", "updated_at"])

                # Create investigation record
                investigation = Investigation.objects.create(
                    analyst=user,
                    indicator=indicator,
                    profile_used=profile,
                    status=InvestigationStatus.RUNNING,
                    started_at=timezone.now(),
                )

        # Get source configs in priority order
        source_configs = (
            profile.source_configs
            .filter(is_enabled=True)
            .select_related("source")
            .prefetch_related("expected_fields__available_field")
            .order_by("priority")
        )

        total_expected = 0
        total_found = 0
        errors = []

        # --- Phase 1: resolve adapters and expected fields (DB work, main thread) ---
        configs_to_query = []
        for sc in source_configs:
            source = sc.source
            adapter = get_adapter(source.slug)

            if adapter is None:
                logger.warning("No adapter found for source: %s", source.slug)
                errors.append(f"No adapter for {source.name}")
                continue

            if not adapter.supports(storage_ioc_type):
                logger.info("Adapter %s doesn't support %s, skipping", source.slug, storage_ioc_type)
                continue

            # Unconfigured source: skip it here so its expected fields don't
            # count against coverage and it doesn't degrade the investigation
            # to PARTIAL. It was never consulted, it didn't fail.
            if adapter.REQUIRES_API_KEY and not adapter.api_key:
                logger.info("Skipping %s — API key not configured", source.slug)
                continue

            expected_fields_qs = sc.expected_fields.select_related("available_field")
            expected_field_names = [ef.available_field.normalized_name for ef in expected_fields_qs]

            if not expected_field_names:
                logger.warning(
                    "No expected fields for %s in profile '%s'. "
                    "Profile ioc_type=%s, storage ioc_type=%s. "
                    "Querying ALL fields instead.",
                    source.name, profile.name, profile_ioc_type, storage_ioc_type,
                )
                expected_field_names_for_query = None
            else:
                expected_field_names_for_query = expected_field_names

            total_expected += len(expected_field_names) if expected_field_names else 0
            configs_to_query.append({
                "source": source,
                "adapter": adapter,
                "expected_field_names": expected_field_names,
                "expected_field_names_for_query": expected_field_names_for_query,
                "timeout": sc.timeout_seconds,
            })

        # --- Phase 2: execute all API queries in parallel (read-only DB + HTTP) ---
        def _query_one(cfg):
            try:
                return _query_one_inner(cfg)
            finally:
                # Each worker thread opens its own thread-local DB connection
                # for the cache-TTL check; close it so it doesn't linger after
                # the pool shuts down.
                for conn in connections.all():
                    conn.close()

        def _query_one_inner(cfg):
            source = cfg["source"]
            adapter = cfg["adapter"]
            expected_field_names = cfg["expected_field_names"]
            expected_set = set(expected_field_names) if expected_field_names else set()

            # Cache check: reuse InvestigationResult records for the same indicator + source
            # if they were fetched within this source's TTL window.
            ttl = source.default_ttl_seconds
            if ttl > 0:
                cutoff = timezone.now() - timedelta(seconds=ttl)
                cached_qs = InvestigationResult.objects.filter(
                    investigation__indicator=investigation.indicator,
                    source=source,
                    fetched_at__gte=cutoff,
                ).exclude(investigation=investigation)
                cached = list(cached_qs)
                if cached:
                    result_objects = [
                        InvestigationResult(
                            investigation=investigation,
                            source=source,
                            field_name=r.field_name,
                            value=r.value,
                            status=r.status,
                            was_expected=(r.field_name in expected_set) if expected_set else True,
                            response_time_ms=r.response_time_ms,
                        )
                        for r in cached
                    ]
                    found_count = sum(1 for r in cached if r.status == ResultStatus.FOUND)
                    logger.info("  -> %s: cache hit (%d results reused)", source.name, len(cached))
                    return source.name, "", result_objects, found_count

            # Cache miss: respect the source's rate limit before hitting it.
            throttle_msg = _wait_for_rate_limit(source)
            if throttle_msg:
                result_objects = [
                    InvestigationResult(
                        investigation=investigation,
                        source=source,
                        field_name=field,
                        value=None,
                        status=ResultStatus.TIMEOUT,
                        was_expected=True,
                        response_time_ms=0,
                    )
                    for field in (expected_field_names or [])
                ]
                logger.warning("Skipping %s — %s", source.name, throttle_msg)
                return source.name, throttle_msg, result_objects, 0

            logger.info(
                "Querying %s for %s:%s... (expecting %s fields)",
                source.name,
                storage_ioc_type,
                ioc_value[:30],
                len(expected_field_names) if expected_field_names else "all",
            )
            adapter_response = adapter.query(
                ioc_value=ioc_value,
                ioc_type=storage_ioc_type,
                expected_fields=cfg["expected_field_names_for_query"],
                timeout=cfg["timeout"],
            )
            result_objects = []
            found_fields = set()
            for ar in adapter_response.results:
                is_expected = (ar.field_name in expected_set) if expected_set else True
                result_objects.append(
                    InvestigationResult(
                        investigation=investigation,
                        source=source,
                        field_name=ar.field_name,
                        value=ar.value,
                        status=ar.status,
                        was_expected=is_expected,
                        response_time_ms=adapter_response.response_time_ms,
                    )
                )
                if ar.status == ResultStatus.FOUND:
                    found_fields.add(ar.field_name)
            return source.name, adapter_response.error, result_objects, len(found_fields)

        all_result_objects = []
        total_found_box = [0]  # mutable so _harvest can update it

        def _harvest(future, cfg):
            try:
                source_name, error, result_objects, found_count = future.result()
                if error:
                    errors.append(f"{source_name}: {error}")
                all_result_objects.extend(result_objects)
                total_found_box[0] += found_count
                logger.info("  -> %s: %d results, %d found", source_name, len(result_objects), found_count)
            except Exception as exc:
                errors.append(f"{cfg['source'].name}: unexpected error -- {exc}")
                logger.exception("Unexpected error querying %s", cfg["source"].name)

        max_workers = min(8, len(configs_to_query)) if configs_to_query else 1
        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = {executor.submit(_query_one, cfg): cfg for cfg in configs_to_query}
        pending = set(futures)
        try:
            for future in as_completed(futures, timeout=GLOBAL_TIMEOUT_SECONDS):
                pending.discard(future)
                _harvest(future, futures[future])
        except FuturesTimeoutError:
            # Budget exhausted: keep everything that finished, report the
            # stragglers as errors, and let the investigation complete as
            # PARTIAL instead of losing all collected results.
            for future in pending:
                cfg = futures[future]
                if future.done():
                    _harvest(future, cfg)
                else:
                    errors.append(
                        f"{cfg['source'].name}: no response within the "
                        f"{GLOBAL_TIMEOUT_SECONDS}s investigation budget"
                    )
                    logger.warning(
                        "Global timeout (%ds) — dropping %s",
                        GLOBAL_TIMEOUT_SECONDS, cfg["source"].name,
                    )
        finally:
            # Don't block on stragglers; their threads finish in the
            # background and their results are discarded.
            executor.shutdown(wait=False, cancel_futures=True)

        total_found += total_found_box[0]

        # --- Phase 3: persist all results in one batch ---
        if all_result_objects:
            InvestigationResult.objects.bulk_create(all_result_objects)

        # Calculate coverage and finalize
        if total_expected > 0:
            coverage = total_found / total_expected * 100
        elif total_found > 0:
            # No expected fields were configured but we found data anyway
            coverage = 100.0
        else:
            coverage = 0.0

        has_errors = len(errors) > 0
        all_failed = total_found == 0 and has_errors

        investigation.status = (
            InvestigationStatus.ERROR if all_failed
            else InvestigationStatus.PARTIAL if has_errors
            else InvestigationStatus.COMPLETED
        )
        investigation.coverage_score = round(coverage, 1)
        investigation.completed_at = timezone.now()
        investigation.error_detail = "\n".join(errors) if errors else ""
        investigation.save()

        logger.info(
            "Investigation #%d completed: %s -- %d/%d fields (%.1f%% coverage)",
            investigation.pk, investigation.status, total_found, total_expected, coverage,
        )

        return investigation
