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

from django.db import transaction
from django.utils import timezone

from apps.core.enums import IOCType, InvestigationStatus, ResultStatus
from apps.core.validators import detect_ioc_type, validate_ioc
from apps.investigations.models import Indicator, Investigation, InvestigationResult
from apps.profiles.models import InvestigationProfile

from .registry import get_adapter

logger = logging.getLogger(__name__)


class InvestigationOrchestrator:
    """
    Executes an investigation based on a profile and IOC.
    """

    def run(self, user, ioc_value: str, profile: InvestigationProfile) -> Investigation:
        """
        Execute a full investigation.

        Args:
            user: The analyst executing the investigation
            ioc_value: The IOC to investigate
            profile: The investigation profile to use

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
            logger.error(f"IOC validation failed: {e}")
            raise

        # For storage, use the detected type (more specific)
        # But for field matching, always use the profile's ioc_type
        storage_ioc_type = detected_type if detected_type else profile_ioc_type

        with transaction.atomic():
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

        for sc in source_configs:
            source = sc.source
            adapter = get_adapter(source.slug)

            if adapter is None:
                logger.warning(f"No adapter found for source: {source.slug}")
                errors.append(f"No adapter for {source.name}")
                continue

            # Check adapter support using the GENERAL type (hash, ip, domain, url)
            general_type = IOCType.get_general_type(storage_ioc_type)
            if not adapter.supports(storage_ioc_type):
                logger.info(f"Adapter {source.slug} doesn't support {storage_ioc_type}, skipping")
                continue

            # Get expected field names for this source.
            # Expected fields are linked to AvailableField which uses the PROFILE's ioc_type
            # (e.g., hash_sha256), not the detected type (e.g., hash_md5).
            expected_fields_qs = sc.expected_fields.select_related("available_field")
            expected_field_names = [ef.available_field.normalized_name for ef in expected_fields_qs]

            if not expected_field_names:
                logger.warning(
                    f"No expected fields for {source.name} in profile '{profile.name}'. "
                    f"Profile ioc_type={profile_ioc_type}, storage ioc_type={storage_ioc_type}. "
                    f"Querying ALL fields instead."
                )
                # If no expected fields configured, query all fields (pass None)
                expected_field_names_for_query = None
            else:
                expected_field_names_for_query = expected_field_names

            total_expected += len(expected_field_names) if expected_field_names else 0

            # Execute the query
            logger.info(
                f"Querying {source.name} for {storage_ioc_type}:{ioc_value[:30]}... "
                f"(expecting {len(expected_field_names) if expected_field_names else 'all'} fields)"
            )
            adapter_response = adapter.query(
                ioc_value=ioc_value,
                ioc_type=storage_ioc_type,
                expected_fields=expected_field_names_for_query,
                timeout=sc.timeout_seconds,
            )

            if adapter_response.error:
                errors.append(f"{source.name}: {adapter_response.error}")

            # Save results
            result_objects = []
            found_fields = set()

            for ar in adapter_response.results:
                is_expected = (
                    ar.field_name in expected_field_names
                    if expected_field_names
                    else True
                )
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

            if result_objects:
                InvestigationResult.objects.bulk_create(result_objects)
                logger.info(f"  → {source.name}: saved {len(result_objects)} results, {len(found_fields)} found")

            total_found += len(found_fields)

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
            f"Investigation #{investigation.pk} completed: "
            f"{investigation.status} — {total_found}/{total_expected} fields "
            f"({coverage:.1f}% coverage)"
        )

        return investigation
