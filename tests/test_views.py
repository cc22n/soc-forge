"""
Tests for Django views — authentication, page access, investigation submission.
"""

import pytest
from django.urls import reverse

from apps.investigations.models import Investigation
from apps.profiles.models import InvestigationProfile


@pytest.mark.django_db
class TestAuthentication:
    """Test that pages require authentication."""

    def test_dashboard_requires_login(self, client):
        response = client.get("/dashboard/")
        assert response.status_code == 302
        assert "/auth/login/" in response.url

    def test_home_loads_for_anonymous(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"SOC Forge" in response.content

    def test_investigations_requires_login(self, client):
        response = client.get("/investigations/")
        assert response.status_code == 302

    def test_sources_requires_login(self, client):
        response = client.get("/sources/")
        assert response.status_code == 302

    def test_profiles_requires_login(self, client):
        response = client.get("/profiles/")
        assert response.status_code == 302

    def test_community_requires_login(self, client):
        response = client.get("/community/")
        assert response.status_code == 302

    def test_login_page_loads(self, client):
        response = client.get("/auth/login/")
        assert response.status_code == 200

    def test_login_success(self, client, analyst_user):
        response = client.post("/auth/login/", {
            "username": "analyst1",
            "password": "TestPass1234!",
        })
        assert response.status_code == 302  # Redirect to dashboard


@pytest.mark.django_db
class TestDashboard:
    def test_dashboard_loads(self, auth_client):
        response = auth_client.get("/dashboard/")
        assert response.status_code == 200
        assert b"Dashboard" in response.content

    def test_home_redirects_authenticated(self, auth_client):
        response = auth_client.get("/")
        assert response.status_code == 302
        assert "/dashboard/" in response.url

    def test_dashboard_shows_stats(self, auth_client):
        response = auth_client.get("/dashboard/")
        assert b"Active Sources" in response.content or b"ACTIVE SOURCES" in response.content


@pytest.mark.django_db
class TestSourcesViews:
    def test_source_list_loads(self, auth_client, sample_sources):
        response = auth_client.get("/sources/")
        assert response.status_code == 200
        assert b"VirusTotal" in response.content

    def test_source_detail_loads(self, auth_client, sample_sources):
        response = auth_client.get("/sources/virustotal/")
        assert response.status_code == 200
        assert b"VirusTotal" in response.content

    def test_source_detail_404(self, auth_client):
        response = auth_client.get("/sources/nonexistent/")
        assert response.status_code == 404


@pytest.mark.django_db
class TestProfilesViews:
    def test_profile_list_loads(self, auth_client):
        response = auth_client.get("/profiles/")
        assert response.status_code == 200

    def test_profile_create_page_loads(self, auth_client):
        response = auth_client.get("/profiles/create/")
        assert response.status_code == 200

    def test_profile_create_submit(self, auth_client, analyst_user):
        response = auth_client.post("/profiles/create/", {
            "name": "Test Profile",
            "ioc_type": "ip",
            "description": "A test profile",
        })
        assert response.status_code == 302  # Redirect to edit sources
        assert InvestigationProfile.objects.filter(name="Test Profile").exists()

    def test_profile_create_no_name(self, auth_client):
        response = auth_client.post("/profiles/create/", {
            "name": "",
            "ioc_type": "ip",
        })
        assert response.status_code == 200  # Re-renders form with error

    def test_profile_detail_loads(self, auth_client, sample_profile):
        response = auth_client.get(f"/profiles/{sample_profile.pk}/")
        assert response.status_code == 200
        assert b"Test IP Profile" in response.content

    def test_profile_delete(self, auth_client, sample_profile):
        pk = sample_profile.pk
        response = auth_client.post(f"/profiles/{pk}/delete/")
        assert response.status_code == 302
        assert not InvestigationProfile.objects.filter(pk=pk).exists()

    def test_profile_clone(self, auth_client, sample_profile, analyst_user):
        response = auth_client.get(f"/profiles/{sample_profile.pk}/clone/")
        assert response.status_code == 302
        assert InvestigationProfile.objects.filter(name__contains="Copy").exists()


@pytest.mark.django_db
class TestInvestigationsViews:
    def test_investigation_list_loads(self, auth_client):
        response = auth_client.get("/investigations/")
        assert response.status_code == 200

    def test_new_investigation_page_loads(self, auth_client):
        response = auth_client.get("/investigations/new/")
        assert response.status_code == 200

    def test_investigation_requires_ioc(self, auth_client, sample_profile):
        response = auth_client.post("/investigations/new/", {
            "ioc_value": "",
            "profile_id": sample_profile.pk,
        })
        assert response.status_code == 200  # Re-renders with error

    def test_investigation_requires_profile(self, auth_client):
        response = auth_client.post("/investigations/new/", {
            "ioc_value": "8.8.8.8",
            "profile_id": "",
        })
        assert response.status_code == 200  # Re-renders with error


@pytest.mark.django_db
class TestCommunityViews:
    def test_community_search_loads(self, auth_client):
        response = auth_client.get("/community/")
        assert response.status_code == 200

    def test_community_search_with_query(self, auth_client):
        response = auth_client.get("/community/?q=8.8.8.8")
        assert response.status_code == 200


@pytest.mark.django_db
class TestModels:
    def test_user_roles(self, analyst_user, admin_user):
        assert analyst_user.is_analyst
        assert not analyst_user.is_admin
        assert admin_user.is_admin
        assert not admin_user.is_analyst

    def test_user_str(self, analyst_user):
        assert "analyst1" in str(analyst_user)

    def test_source_supports_ioc(self, sample_sources):
        vt = sample_sources["virustotal"]
        assert vt.supports_ioc_type("ip")
        assert vt.supports_ioc_type("hash_sha256")
        assert vt.supports_ioc_type("domain")

        abuse = sample_sources["abuseipdb"]
        assert abuse.supports_ioc_type("ip")
        assert not abuse.supports_ioc_type("domain")

    def test_profile_str(self, sample_profile):
        assert "Test IP Profile" in str(sample_profile)
