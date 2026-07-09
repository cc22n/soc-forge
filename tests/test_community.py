"""
Tests for the community knowledge base: sharing, dedup, and voting.
"""

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.community.models import CommunityIndicator, CommunityResult, ConfidenceVote
from apps.core.enums import InvestigationStatus, ResultStatus
from apps.investigations.models import Indicator, Investigation, InvestigationResult
from apps.users.models import UserReputation


def _make_investigation(user, source, ioc_value="8.8.8.8", field_name="abuse_confidence", value=42):
    indicator, _ = Indicator.objects.get_or_create(value=ioc_value, ioc_type="ip", defaults={"created_by": user})
    investigation = Investigation.objects.create(
        analyst=user,
        indicator=indicator,
        status=InvestigationStatus.COMPLETED,
        started_at=timezone.now(),
        completed_at=timezone.now(),
    )
    InvestigationResult.objects.create(
        investigation=investigation,
        source=source,
        field_name=field_name,
        value=value,
        status=ResultStatus.FOUND,
    )
    return investigation


@pytest.mark.django_db
class TestShareInvestigationDedup:

    def test_share_creates_community_result(self, auth_client, analyst_user, sample_sources):
        investigation = _make_investigation(analyst_user, sample_sources["abuseipdb"])

        response = auth_client.post(f"/community/share/{investigation.pk}/")

        assert response.status_code == 302
        ci = CommunityIndicator.objects.get(indicator=investigation.indicator)
        assert CommunityResult.objects.filter(
            community_indicator=ci, field_name="abuse_confidence"
        ).count() == 1

    def test_sharing_same_indicator_twice_does_not_duplicate(
        self, auth_client, analyst_user, admin_client, admin_user, sample_sources
    ):
        """Two different investigations of the same indicator, shared
        sequentially, must reuse the same CommunityResult row instead of
        creating a second one for the same field."""
        inv1 = _make_investigation(analyst_user, sample_sources["abuseipdb"])
        inv2 = _make_investigation(admin_user, sample_sources["abuseipdb"], value=99)

        auth_client.post(f"/community/share/{inv1.pk}/")
        admin_client.post(f"/community/share/{inv2.pk}/")

        ci = CommunityIndicator.objects.get(indicator__value="8.8.8.8")
        assert CommunityResult.objects.filter(
            community_indicator=ci, field_name="abuse_confidence"
        ).count() == 1

    def test_db_constraint_rejects_direct_duplicate_insert(self, analyst_user, sample_sources):
        """The unique constraint itself — the safety net share_investigation's
        get_or_create() depends on to stay race-safe under concurrency."""
        investigation = _make_investigation(analyst_user, sample_sources["abuseipdb"])
        ci = CommunityIndicator.objects.create(indicator=investigation.indicator, first_seen_by=analyst_user)
        CommunityResult.objects.create(
            community_indicator=ci, source=sample_sources["abuseipdb"],
            field_name="abuse_confidence", value=1, contributed_by=analyst_user,
        )
        with pytest.raises(IntegrityError):
            with transaction.atomic():
                CommunityResult.objects.create(
                    community_indicator=ci, source=sample_sources["abuseipdb"],
                    field_name="abuse_confidence", value=2, contributed_by=analyst_user,
                )

    def test_stale_result_is_refreshed_not_duplicated(self, auth_client, analyst_user, admin_client,
                                                        admin_user, sample_sources):
        source = sample_sources["abuseipdb"]  # default_ttl_seconds=43200 in conftest
        inv1 = _make_investigation(analyst_user, source, value=1)
        auth_client.post(f"/community/share/{inv1.pk}/")

        ci = CommunityIndicator.objects.get(indicator__value="8.8.8.8")
        existing = CommunityResult.objects.get(community_indicator=ci, field_name="abuse_confidence")
        # Force it to look stale relative to the source TTL
        CommunityResult.objects.filter(pk=existing.pk).update(
            contributed_at=timezone.now() - timezone.timedelta(days=365)
        )

        inv2 = _make_investigation(admin_user, source, value=2)
        admin_client.post(f"/community/share/{inv2.pk}/")

        results = CommunityResult.objects.filter(community_indicator=ci, field_name="abuse_confidence")
        assert results.count() == 1
        assert results.first().value == 2

    def test_already_shared_investigation_is_not_reshared(self, auth_client, analyst_user, sample_sources):
        investigation = _make_investigation(analyst_user, sample_sources["abuseipdb"])
        auth_client.post(f"/community/share/{investigation.pk}/")
        investigation.refresh_from_db()
        assert investigation.shared_to_community is True

        response = auth_client.post(f"/community/share/{investigation.pk}/")
        assert response.status_code == 302
        ci = CommunityIndicator.objects.get(indicator=investigation.indicator)
        assert CommunityResult.objects.filter(community_indicator=ci).count() == 1

    def test_sharing_updates_contributor_reputation(self, auth_client, analyst_user, sample_sources):
        investigation = _make_investigation(analyst_user, sample_sources["abuseipdb"])
        auth_client.post(f"/community/share/{investigation.pk}/")

        rep = UserReputation.objects.get(user=analyst_user)
        assert rep.total_contributions == 1


@pytest.mark.django_db
class TestCommunityVote:

    @pytest.fixture
    def community_result(self, analyst_user, sample_sources):
        investigation = _make_investigation(analyst_user, sample_sources["abuseipdb"])
        ci = CommunityIndicator.objects.create(indicator=investigation.indicator, first_seen_by=analyst_user)
        return CommunityResult.objects.create(
            community_indicator=ci, source=sample_sources["abuseipdb"],
            field_name="abuse_confidence", value=42, contributed_by=analyst_user,
        )

    def test_confirm_vote_increments_score(self, admin_client, community_result):
        response = admin_client.post(f"/community/vote/{community_result.pk}/confirm/")
        assert response.status_code == 302
        community_result.refresh_from_db()
        assert community_result.confidence_votes == 1

    def test_dispute_vote_decrements_score_and_reputation(self, admin_client, community_result, analyst_user):
        response = admin_client.post(f"/community/vote/{community_result.pk}/dispute/")
        assert response.status_code == 302
        community_result.refresh_from_db()
        assert community_result.confidence_votes == -1

        rep = UserReputation.objects.get(user=analyst_user)
        assert rep.disputed_contributions == 1

    def test_cannot_vote_on_own_contribution(self, auth_client, community_result):
        response = auth_client.post(f"/community/vote/{community_result.pk}/confirm/")
        assert response.status_code == 302
        community_result.refresh_from_db()
        assert community_result.confidence_votes == 0
        assert not ConfidenceVote.objects.filter(community_result=community_result).exists()

    def test_revoting_changes_vote_not_duplicates(self, admin_client, community_result):
        admin_client.post(f"/community/vote/{community_result.pk}/confirm/")
        admin_client.post(f"/community/vote/{community_result.pk}/dispute/")

        community_result.refresh_from_db()
        assert community_result.confidence_votes == -1
        assert ConfidenceVote.objects.filter(community_result=community_result).count() == 1

    def test_invalid_vote_type_rejected(self, admin_client, community_result):
        response = admin_client.post(f"/community/vote/{community_result.pk}/nonsense/")
        assert response.status_code == 302
        community_result.refresh_from_db()
        assert community_result.confidence_votes == 0
