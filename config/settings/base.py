"""
Base settings for SOC Forge.
Shared across all environments (development, production).
"""

import os
from pathlib import Path

import environ

# ============================================
# Path Configuration
# ============================================
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APPS_DIR = BASE_DIR / "apps"

# ============================================
# Environment Variables
# ============================================
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
)
environ.Env.read_env(str(BASE_DIR / ".env"))

# ============================================
# Core Settings
# ============================================
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ============================================
# Application Definition
# ============================================
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "django_filters",
    "axes",
    "rest_framework",
    "rest_framework.authtoken",
]

LOCAL_APPS = [
    "apps.users",
    "apps.sources",
    "apps.profiles",
    "apps.investigations",
    "apps.community",
    "apps.api",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ============================================
# Middleware
# ============================================
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # SOC Forge security middleware
    "apps.users.security_middleware.SecurityHeadersMiddleware",
    "apps.users.security_middleware.IOCSanitizationMiddleware",
    "apps.users.security_middleware.RateLimitMiddleware",
    # SOC Forge audit middleware
    "apps.users.middleware.AuditMiddleware",
    # django-axes (must be after auth middleware)
    "axes.middleware.AxesMiddleware",
]

# ============================================
# Authentication
# ============================================
AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

LOGIN_URL = "/auth/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/auth/login/"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# ============================================
# Database
# ============================================
DATABASES = {
    "default": env.db("DATABASE_URL"),
}

# ============================================
# Templates
# ============================================
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ============================================
# Static Files
# ============================================
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# ============================================
# Internationalization
# ============================================
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ============================================
# Security (base — reinforced in production.py)
# ============================================
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_AGE = 28800  # 8 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# ============================================
# django-axes (brute force protection)
# ============================================
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = 1  # hours
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_RESET_ON_SUCCESS = True

# ============================================
# Threat Intelligence API Keys
# ============================================
# ============================================
# LLM — Multi-provider support
# LLM_PROVIDER: anthropic | openai | groq | grok | gemini  (default: anthropic)
# LLM_MODEL: optional override — leave blank to use each provider's default
# ============================================
LLM_PROVIDER = env("LLM_PROVIDER", default="anthropic")
LLM_MODEL = env("LLM_MODEL", default="")

ANTHROPIC_API_KEY = env("ANTHROPIC_API_KEY", default="")
OPENAI_API_KEY = env("OPENAI_API_KEY", default="")
GROQ_API_KEY = env("GROQ_API_KEY", default="")
GROK_API_KEY = env("GROK_API_KEY", default="")
GEMINI_API_KEY = env("GEMINI_API_KEY", default="")

# ============================================
# Threat Intelligence API Keys
# ============================================
THREAT_INTEL_KEYS = {
    "virustotal": env("VIRUSTOTAL_API_KEY", default=""),
    "abuseipdb": env("ABUSEIPDB_API_KEY", default=""),
    "shodan": env("SHODAN_API_KEY", default=""),
    "otx": env("OTX_API_KEY", default=""),
    "greynoise": env("GREYNOISE_API_KEY", default=""),
    "google_safebrowsing": env("GOOGLE_SAFEBROWSING_API_KEY", default=""),
    "hybrid_analysis": env("HYBRID_ANALYSIS_API_KEY", default=""),
    "securitytrails": env("SECURITYTRAILS_API_KEY", default=""),
    "abusech": env("ABUSECH_AUTH_KEY", default=""),
    "urlscan": env("URLSCAN_API_KEY", default=""),
    "pulsedive": env("PULSEDIVE_API_KEY", default=""),
    "criminal_ip": env("CRIMINAL_IP_API_KEY", default=""),
    "ipinfo": env("IPINFO_API_KEY", default=""),
    "ipqualityscore": env("IPQUALITYSCORE_API_KEY", default=""),
    "censys_id": env("CENSYS_API_ID", default=""),
    "censys_secret": env("CENSYS_API_SECRET", default=""),
}

# ============================================
# Celery
# ============================================
CELERY_BROKER_URL = env("REDIS_URL", default="redis://localhost:6379/0")
CELERY_RESULT_BACKEND = env("REDIS_URL", default="redis://localhost:6379/0")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_ROUTES = {
    "apps.investigations.tasks.run_investigation_task": {
        "queue": "full_investigation",
    },
}
CELERY_TASK_QUEUES_MAX_PRIORITY = 10
CELERY_TASK_DEFAULT_PRIORITY = 5

# ============================================
# Django REST Framework
# ============================================
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "60/minute",
    },
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

# ============================================
# Cache (LocMem by default; Redis if REDIS_URL is set)
# ============================================
_REDIS_URL = env("REDIS_URL", default="")
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
    "rate_limit": (
        {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": _REDIS_URL,
        }
        if _REDIS_URL
        else {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "rate_limit",
        }
    ),
}

# ============================================
# Logging
# ============================================
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {message}",
            "style": "{",
        },
        "security": {
            "format": "[{asctime}] SECURITY {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "security_console": {
            "class": "logging.StreamHandler",
            "formatter": "security",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "apps.users.security_middleware": {
            "handlers": ["security_console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
