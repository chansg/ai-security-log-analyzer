"""
Custom template filters for the alerts dashboard.

Usage in templates:
    {% load alert_tags %}
    <span class="{{ alert.severity|severity_class }}">
"""

from django import template

register = template.Library()


@register.filter
def severity_class(value: str) -> str:
    """Map a severity string to a CSS class name for colour coding.

    Args:
        value: A severity string like "critical", "high", etc.

    Returns:
        A CSS class name, e.g. "severity-critical".
    """
    mapping = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
    }
    return mapping.get(value, "severity-low")
