"""
Development settings for SOC Forge.
Extends base settings with debug tools and relaxed security.
"""

from .base import *  # noqa: F401,F403

# ============================================
# Debug
# ============================================
DEBUG = True

# ============================================
# Debug Toolbar
# ============================================
INSTALLED_APPS += ["debug_toolbar", "django_extensions"]  # noqa: F405
MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")  # noqa: F405
INTERNAL_IPS = ["127.0.0.1"]

# ============================================
# Email (console output in development)
# ============================================
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# ============================================
# Static files (no compression in dev)
# ============================================
STORAGES = {
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# ============================================
# Logging (more verbose in dev)
# ============================================
LOGGING["loggers"]["django.db.backends"] = {  # noqa: F405
    "handlers": ["console"],
    "level": "WARNING",  # Change to DEBUG to see SQL queries
}
