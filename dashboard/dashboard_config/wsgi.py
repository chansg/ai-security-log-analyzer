"""WSGI config for the dashboard project."""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dashboard_config.settings")
application = get_wsgi_application()
