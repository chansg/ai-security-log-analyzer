"""URL configuration for the Security Log Analyzer dashboard."""

from django.urls import path, include

urlpatterns = [
    # All dashboard URLs are handled by the alerts app
    path("", include("alerts.urls")),
]
