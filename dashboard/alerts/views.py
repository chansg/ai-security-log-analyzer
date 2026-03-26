"""
views.py -- Dashboard views for the Security Log Analyzer
==========================================================
These views read from the alerts SQLite database (data/alerts.db)
that was populated by alert_manager.py.  They do NOT use Django's
ORM -- instead they query the pipeline's database directly with
raw SQL via Python's built-in sqlite3 module.

Why raw SQL instead of Django models?
    The alerts table is created and managed by the ML pipeline
    (alert_manager.py), not by Django.  Using raw sqlite3 keeps the
    dashboard decoupled from the pipeline -- neither side needs to
    know about the other's internals.

Three views:
    home()        -- summary dashboard with stats, table, chart
    chart_data()  -- JSON API endpoint for Chart.js
    user_detail() -- per-user drill-down
"""

from __future__ import annotations

import sqlite3
from collections import Counter

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render


# ---------------------------------------------------------------------------
# Helper: connect to the alerts database
# ---------------------------------------------------------------------------

def get_alerts_db() -> sqlite3.Connection:
    """Open a read-only connection to the pipeline's alerts database.

    The database path comes from Django settings (ALERTS_DB_PATH),
    which points to data/alerts.db in the project root.

    We use row_factory = sqlite3.Row so that each result row behaves
    like a dictionary -- you can access columns by name (row["severity"])
    instead of by index (row[0]).

    Returns:
        An open sqlite3.Connection.  The caller should close it when done.
    """
    conn = sqlite3.connect(str(settings.ALERTS_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def query_all(sql: str, params: tuple = ()) -> list[dict]:
    """Run a SQL query and return all rows as a list of dicts.

    This is a convenience wrapper that handles opening and closing
    the database connection automatically.

    Args:
        sql:    A SQL SELECT query string.
        params: Tuple of parameters for the query (for ? placeholders).

    Returns:
        A list of dicts, one per row.
    """
    conn = get_alerts_db()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# View: Home page
# ---------------------------------------------------------------------------

def home(request):
    """Render the main dashboard page.

    Displays:
        - Total alert count
        - Breakdown by severity (critical / high / medium / low)
        - Breakdown by alert type (ML vs rule)
        - List of unique affected users (for the drill-down links)
        - Recent alerts table (all alerts, newest first)

    Template: alerts/home.html
    """
    # Fetch ALL alerts, newest first
    alerts = query_all("SELECT * FROM alerts ORDER BY id DESC")

    # --- Compute summary statistics ---

    total_alerts = len(alerts)

    # Count alerts per severity level.
    # Counter is a dict subclass that counts occurrences automatically.
    severity_counts = Counter(a["severity"] for a in alerts)

    # Count alerts per type (ml vs rule).
    type_counts = Counter(a["alert_type"] for a in alerts)

    # Build a sorted list of unique affected users for the drill-down
    # sidebar links.  We split on ", " because rule-engine alerts can
    # list multiple users in one field (e.g. "alice, bob, charlie").
    all_users = set()
    for a in alerts:
        if a["affected_user"]:
            for user in a["affected_user"].split(", "):
                all_users.add(user.strip())
    affected_users = sorted(all_users)

    # --- Build template context ---
    context = {
        "alerts": alerts,
        "total_alerts": total_alerts,
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "type_counts": {
            "ml": type_counts.get("ml", 0),
            "rule": type_counts.get("rule", 0),
        },
        "affected_users": affected_users,
    }

    return render(request, "alerts/home.html", context)


# ---------------------------------------------------------------------------
# View: Chart.js JSON API
# ---------------------------------------------------------------------------

def chart_data(request):
    """Return alert counts per date as JSON for Chart.js.

    Chart.js needs two arrays: labels (dates) and data (counts).
    We group alerts by the date portion of the timestamp and count
    how many alerts occurred each day.

    The frontend fetches this endpoint with JavaScript and uses it
    to draw a bar chart of anomaly detections over time.

    Returns:
        A JsonResponse with:
            labels: ["2026-03-01", "2026-03-02", ...]
            datasets: [
                {label: "ML Alerts",   data: [3, 1, ...], ...},
                {label: "Rule Alerts", data: [0, 2, ...], ...},
            ]
    """
    # Get all alerts sorted by timestamp
    alerts = query_all("SELECT * FROM alerts ORDER BY timestamp")

    # Group alert counts by date and type.
    # We extract just the date part (first 10 chars) from the timestamp
    # string, e.g. "2026-03-04 02:10:00" -> "2026-03-04".
    ml_by_date: dict[str, int] = {}
    rule_by_date: dict[str, int] = {}

    for a in alerts:
        date = a["timestamp"][:10] if a["timestamp"] else "unknown"

        if a["alert_type"] == "ml":
            ml_by_date[date] = ml_by_date.get(date, 0) + 1
        else:
            rule_by_date[date] = rule_by_date.get(date, 0) + 1

    # Merge all dates and sort them chronologically
    all_dates = sorted(set(list(ml_by_date.keys()) + list(rule_by_date.keys())))

    # Build the Chart.js-compatible data structure.
    # Each dataset is one "bar group" in the chart.
    return JsonResponse({
        "labels": all_dates,
        "datasets": [
            {
                "label": "ML Alerts",
                "data": [ml_by_date.get(d, 0) for d in all_dates],
                # Gold colour for ML alerts
                "backgroundColor": "rgba(212, 175, 55, 0.8)",
                "borderColor": "rgba(212, 175, 55, 1)",
                "borderWidth": 1,
            },
            {
                "label": "Rule Alerts",
                "data": [rule_by_date.get(d, 0) for d in all_dates],
                # Teal colour for rule alerts
                "backgroundColor": "rgba(0, 200, 180, 0.8)",
                "borderColor": "rgba(0, 200, 180, 1)",
                "borderWidth": 1,
            },
        ],
    })


# ---------------------------------------------------------------------------
# View: Per-user drill-down
# ---------------------------------------------------------------------------

def user_detail(request, username: str):
    """Render a page showing all alerts for a specific user.

    Since rule-engine alerts can list multiple users in the
    affected_user field (comma-separated), we use SQL LIKE to
    find any alert where the username appears anywhere in that field.

    Template: alerts/user_detail.html

    Args:
        request:  Django HTTP request.
        username: The username to filter alerts for.
    """
    # FIXME: LIKE with wildcards will match partial usernames too
    # e.g. searching for "ad" would match "admin" — not great
    # should probably normalise this into a separate table
    alerts = query_all(
        "SELECT * FROM alerts WHERE affected_user LIKE ? ORDER BY id DESC",
        (f"%{username}%",),
    )

    # Compute severity breakdown for this user's alerts
    severity_counts = Counter(a["severity"] for a in alerts)

    context = {
        "username": username,
        "alerts": alerts,
        "total_alerts": len(alerts),
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
    }

    return render(request, "alerts/user_detail.html", context)
