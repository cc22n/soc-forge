"""
Celery configuration for SOC Forge.

Start worker:
    celery -A config worker -l info

Start with separate priority queues:
    celery -A config worker -l info -Q high_priority,full_investigation,celery
"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

app = Celery("soc_forge")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
