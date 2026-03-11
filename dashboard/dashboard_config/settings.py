"""
Django settings for the Security Log Analyzer dashboard.

This dashboard reads alerts from the SQLite database produced by the
ML pipeline (data/alerts.db).  It does NOT modify that database --
it is strictly read-only.

Django's own internal tables (sessions, auth, etc.) live in a
separate database file (dashboard/db.sqlite3) so the pipeline and
the dashboard never interfere with each other.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# BASE_DIR points to the 'dashboard/' folder
BASE_DIR = Path(__file__).resolve().parent.parent

# PROJECT_ROOT points to the SecurityLogAnalyzer root (one level up)
# This is where data/alerts.db lives.
PROJECT_ROOT = BASE_DIR.parent

# This is the path to the alerts database produced by alert_manager.py.
# Views use this to query alert data.
ALERTS_DB_PATH = PROJECT_ROOT / "data" / "alerts.db"

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

SECRET_KEY = "django-insecure-dashboard-dev-only-change-in-production"
DEBUG = True
ALLOWED_HOSTS = ["*"]

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "alerts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "dashboard_config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "dashboard_config.wsgi.application"

# ---------------------------------------------------------------------------
# Database -- Django internals only (not alerts data)
# ---------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# ---------------------------------------------------------------------------
# Static files (CSS, JS)
# ---------------------------------------------------------------------------

STATIC_URL = "/static/"

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
