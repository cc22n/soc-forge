"""
SOC Forge URL Configuration.
Each app has its own urls.py, included here.
"""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("django.contrib.auth.urls")),
    path("api/", include("apps.api.urls")),
    path("sources/", include("apps.sources.urls")),
    path("profiles/", include("apps.profiles.urls")),
    path("investigations/", include("apps.investigations.urls")),
    path("community/", include("apps.community.urls")),
    path("", include("apps.users.urls")),
]

# Debug toolbar in development only
if settings.DEBUG:
    try:
        import debug_toolbar

        urlpatterns = [
            path("__debug__/", include(debug_toolbar.urls)),
        ] + urlpatterns
    except ImportError:
        pass

# Admin site customization
admin.site.site_header = "SOC Forge Administration"
admin.site.site_title = "SOC Forge"
admin.site.index_title = "SOC Forge — Control Panel"
