"""
Seed the database with all 17 threat intelligence sources, their available fields,
and 8 default investigation profiles.

Usage:
    python manage.py seed_sources              # Create (skip existing)
    python manage.py seed_sources --reset      # Delete all and recreate
    python manage.py seed_sources --profiles   # Also create default profiles
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.sources.models import AvailableField, Source

from ._sources_part1 import SOURCES_PART1
from ._sources_part2 import SOURCES_PART2
from ._sources_part3 import DEFAULT_PROFILES, SOURCES_PART3

User = get_user_model()

ALL_SOURCES = SOURCES_PART1 + SOURCES_PART2 + SOURCES_PART3


class Command(BaseCommand):
    help = "Seed all 17 threat intelligence sources with their available fields."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete all existing sources and fields before seeding.",
        )
        parser.add_argument(
            "--profiles",
            action="store_true",
            help="Also create the 8 default investigation profiles.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            self.stdout.write(self.style.WARNING("Deleting all sources and fields..."))
            AvailableField.objects.all().delete()
            Source.objects.all().delete()
            self.stdout.write(self.style.SUCCESS("Deleted."))

        sources_created = 0
        sources_skipped = 0
        fields_created = 0

        for source_data in ALL_SOURCES:
            fields = source_data.pop("fields")
            slug = source_data["slug"]

            source, created = Source.objects.get_or_create(
                slug=slug,
                defaults=source_data,
            )

            if created:
                sources_created += 1
                self.stdout.write(f"  + Created source: {source.name}")
            else:
                sources_skipped += 1
                self.stdout.write(f"  = Skipped source: {source.name} (already exists)")
                # Put fields back for potential reuse
                source_data["fields"] = fields
                continue

            # Create available fields for this source
            field_objects = []
            for field_data in fields:
                field_objects.append(
                    AvailableField(
                        source=source,
                        ioc_type=field_data["ioc_type"],
                        normalized_name=field_data["normalized_name"],
                        api_field_path=field_data["api_field_path"],
                        classification=field_data["classification"],
                        data_type=field_data.get("data_type", "str"),
                        transform_function=field_data.get("transform_function", ""),
                        description=field_data.get("description", ""),
                    )
                )

            AvailableField.objects.bulk_create(field_objects)
            fields_created += len(field_objects)
            self.stdout.write(f"    └── {len(field_objects)} fields")

            # Put fields back in dict for potential reuse
            source_data["fields"] = fields

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Done! Sources: {sources_created} created, {sources_skipped} skipped. "
                f"Fields: {fields_created} created."
            )
        )

        # Optionally seed default profiles
        if options["profiles"]:
            self._seed_profiles()

    def _seed_profiles(self):
        """Create the 8 default investigation profiles."""
        from apps.profiles.models import (
            ExpectedField,
            InvestigationProfile,
            ProfileSourceConfig,
        )

        self.stdout.write("")
        self.stdout.write("Seeding default investigation profiles...")

        # Use the first superuser as owner, or first user
        admin = User.objects.filter(is_superuser=True).first()
        if not admin:
            admin = User.objects.first()
        if not admin:
            self.stdout.write(
                self.style.ERROR("No users found. Create a superuser first, then run with --profiles.")
            )
            return

        profiles_created = 0

        for profile_data in DEFAULT_PROFILES:
            profile, created = InvestigationProfile.objects.get_or_create(
                name=profile_data["name"],
                is_default=True,
                defaults={
                    "owner": admin,
                    "ioc_type": profile_data["ioc_type"],
                    "description": profile_data["description"],
                },
            )

            if not created:
                self.stdout.write(f"  = Skipped profile: {profile.name} (already exists)")
                continue

            profiles_created += 1
            self.stdout.write(f"  + Created profile: {profile.name}")

            # Add source configs
            for priority, source_slug in enumerate(profile_data["sources"], start=1):
                try:
                    source = Source.objects.get(slug=source_slug)
                except Source.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f"    ! Source '{source_slug}' not found, skipping")
                    )
                    continue

                psc = ProfileSourceConfig.objects.create(
                    profile=profile,
                    source=source,
                    priority=priority,
                )

                # Auto-add all available fields for this source+ioc_type as expected
                ioc_type = profile_data["ioc_type"]
                available = AvailableField.objects.filter(
                    source=source,
                    ioc_type=ioc_type,
                )
                field_objects = []
                for af in available:
                    field_objects.append(
                        ExpectedField(
                            profile_source=psc,
                            available_field=af,
                            is_required=(af.classification == "required"),
                        )
                    )
                ExpectedField.objects.bulk_create(field_objects)
                self.stdout.write(f"    └── {source.name}: {len(field_objects)} expected fields")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"Profiles: {profiles_created} created."))
