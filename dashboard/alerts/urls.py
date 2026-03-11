"""
URL routing for the alerts dashboard app.

Three pages:
    /               Home page with summary stats and recent alerts
    /api/chart/     JSON endpoint for the Chart.js time-series chart
    /user/<name>/   Per-user drill-down page
"""

from django.urls import path
from . import views

urlpatterns = [
    # Home page -- summary dashboard
    path("", views.home, name="home"),

    # JSON API -- Chart.js fetches this to draw the time-series chart
    path("api/chart/", views.chart_data, name="chart_data"),

    # User drill-down -- shows all alerts for a specific user
    path("user/<str:username>/", views.user_detail, name="user_detail"),
]
