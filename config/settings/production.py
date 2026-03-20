"""
Production settings for SOC Forge.
Extends base settings with strict security and performance optimizations.
"""

from .base import *  # noqa: F401,F403

# ============================================
# Security
# ============================================
DEBUG = False
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ============================================
# Allowed Hosts (must be set in .env for production)
# ============================================
ALLOWED_HOSTS = env("ALLOWED_HOSTS")  # noqa: F405

# ============================================
# Email (configure real SMTP in production)
# ============================================
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", default="localhost")  # noqa: F405
EMAIL_PORT = env.int("EMAIL_PORT", default=587)  # noqa: F405
EMAIL_USE_TLS = True
