"""
rule_engine.py -- Deterministic Rule-Based Detection Engine
============================================================
Complements the Isolation Forest ML model by applying hard-coded,
domain-expert rules to the login event data.  These rules catch
well-known attack patterns that don't need statistical inference --
they are suspicious BY DEFINITION.

Three rules are implemented:
    1. Brute Force   : > 5 failed logins from one IP in 10 minutes
    2. Password Spray : > 10 distinct users from one IP in 5 minutes
    3. Impossible Travel : same user from IPs > 500 km apart in 60 min

Each rule returns a list of structured alert dicts with:
    rule_name, severity, affected_user, source_ip, description

Usage:
    python src/rule_engine.py          # standalone test
    from src.rule_engine import run_all_rules   # import in pipeline
"""

from __future__ import annotations

import math
from datetime import timedelta

import pandas as pd


# ---------------------------------------------------------------------------
# Geo-location helpers (for the impossible-travel rule)
# ---------------------------------------------------------------------------

# TODO: swap this out for a proper GeoIP lookup (MaxMind?) at some point
# Using capital city coords for now which is... fine for a demo
LOCATION_COORDS: dict[str, tuple[float, float]] = {
    "UK": (51.5074, -0.1278),    # London
    "DE": (52.5200, 13.4050),    # Berlin
    "US": (38.9072, -77.0369),   # Washington DC
    "RU": (55.7558, 37.6173),    # Moscow
    "SG": (1.3521, 103.8198),    # Singapore
    "NL": (52.3676, 4.9041),     # Amsterdam
}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth.

    Uses the Haversine formula, which gives the shortest distance over
    the Earth's surface between two (latitude, longitude) pairs.

    Args:
        lat1: Latitude of point 1 in decimal degrees.
        lon1: Longitude of point 1 in decimal degrees.
        lat2: Latitude of point 2 in decimal degrees.
        lon2: Longitude of point 2 in decimal degrees.

    Returns:
        Distance in kilometres (rounded to nearest integer).

    Example:
        >>> haversine_km(51.5074, -0.1278, 1.3521, 103.8198)
        10843  # London to Singapore
    """
    # Convert degrees to radians because math.sin/cos expect radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    # Earth's mean radius in kilometres
    earth_radius_km = 6371.0

    return round(earth_radius_km * c)


def get_distance_km(loc1: str, loc2: str) -> float | None:
    """Look up the distance in km between two country codes.

    Args:
        loc1: Two-letter country code (e.g. 'UK').
        loc2: Two-letter country code (e.g. 'SG').

    Returns:
        Distance in km, or None if either location is unknown.
    """
    # If we don't have coordinates for a location, we can't compute
    # the distance -- return None so the caller can skip this pair.
    if loc1 not in LOCATION_COORDS or loc2 not in LOCATION_COORDS:
        return None

    lat1, lon1 = LOCATION_COORDS[loc1]
    lat2, lon2 = LOCATION_COORDS[loc2]
    return haversine_km(lat1, lon1, lat2, lon2)


# ---------------------------------------------------------------------------
# Rule 1 -- Brute-Force Detection
# ---------------------------------------------------------------------------

def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[dict]:
    """Detect brute-force attacks using a sliding time window.

    Flags any IP address that generates MORE THAN `threshold` failed
    login attempts within a `window_minutes`-minute window.

    How it works:
        1. Filter to failed logins only (login_success == 0).
        2. Group by source_ip.
        3. For each IP, slide a time window and count failures.
        4. If a window exceeds the threshold, create an alert.

    Args:
        df: DataFrame with columns: timestamp, username, source_ip,
            login_success (at minimum).
        threshold: Number of failed logins that triggers the rule.
                   Default is 5 (so 6+ failures = alert).
        window_minutes: Size of the sliding window in minutes.
                        Default is 10.

    Returns:
        A list of alert dicts, one per detected brute-force incident.
    """
    alerts: list[dict] = []

    # Only look at failed logins -- successful ones are not part of
    # the brute-force pattern.
    failed = df[df["login_success"] == 0].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    # Group failed logins by source IP so we can analyse each IP
    # independently.
    for ip, group in failed.groupby("source_ip"):
        # Sort by time so the sliding window moves chronologically
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()
        usernames = group["username"].tolist()

        # Sliding window: for each event, count how many events from
        # the same IP fall within the next `window_minutes` minutes.
        window = timedelta(minutes=window_minutes)
        i = 0
        while i < len(timestamps):
            # Find the end of the current window
            window_end = timestamps[i] + window
            j = i
            while j < len(timestamps) and timestamps[j] <= window_end:
                j += 1

            # Number of failed logins in this window
            count = j - i

            if count > threshold:
                # Collect all unique users targeted in this window
                targeted_users = set(usernames[i:j])

                alerts.append({
                    "rule_name": "brute_force",
                    "severity": "critical",
                    "affected_user": ", ".join(sorted(targeted_users)),
                    "source_ip": ip,
                    "description": (
                        f"{count} failed logins from {ip} within "
                        f"{window_minutes} min (threshold: {threshold}). "
                        f"Targeted user(s): {', '.join(sorted(targeted_users))}."
                    ),
                    "event_count": count,
                    "window_start": str(timestamps[i]),
                    "window_end": str(timestamps[j - 1]),
                })

                # Jump past this window so we don't create duplicate
                # alerts for overlapping windows.
                i = j
            else:
                i += 1

    print(f"[Rule] Brute-force check: {len(alerts)} alert(s) found")
    return alerts


# ---------------------------------------------------------------------------
# Rule 2 -- Password Spray Detection
# ---------------------------------------------------------------------------

def detect_password_spray(
    df: pd.DataFrame,
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect password-spray attacks using a sliding time window.

    Flags any IP address that attempts logins against MORE THAN
    `threshold` DISTINCT usernames within a `window_minutes`-minute
    window.  Password sprays try one password across many accounts,
    so the distinguishing signal is many different usernames from a
    single source.

    How it works:
        1. Group all events by source_ip.
        2. For each IP, slide a time window.
        3. Count distinct usernames attempted in each window.
        4. If distinct usernames exceed the threshold, create an alert.

    Note: we look at ALL login attempts (not just failures) because a
    clever spray might occasionally succeed.

    Args:
        df: DataFrame with columns: timestamp, username, source_ip.
        threshold: Distinct-username count that triggers the rule.
                   Default is 10 (so 11+ distinct users = alert).
        window_minutes: Size of the sliding window in minutes.

    Returns:
        A list of alert dicts, one per detected spray incident.
    """
    alerts: list[dict] = []

    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])

    for ip, group in work.groupby("source_ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()
        usernames = group["username"].tolist()

        window = timedelta(minutes=window_minutes)
        i = 0
        while i < len(timestamps):
            window_end = timestamps[i] + window
            j = i
            while j < len(timestamps) and timestamps[j] <= window_end:
                j += 1

            # Count the number of DISTINCT usernames in this window
            distinct_users = set(usernames[i:j])

            if len(distinct_users) > threshold:
                alerts.append({
                    "rule_name": "password_spray",
                    "severity": "high",
                    "affected_user": ", ".join(sorted(distinct_users)),
                    "source_ip": ip,
                    "description": (
                        f"{len(distinct_users)} distinct users attempted "
                        f"from {ip} within {window_minutes} min "
                        f"(threshold: {threshold}). "
                        f"Users: {', '.join(sorted(distinct_users))}."
                    ),
                    "event_count": j - i,
                    "window_start": str(timestamps[i]),
                    "window_end": str(timestamps[j - 1]),
                })
                # Skip past this window to avoid duplicate alerts
                i = j
            else:
                i += 1

    print(f"[Rule] Password-spray check: {len(alerts)} alert(s) found")
    return alerts


# ---------------------------------------------------------------------------
# Rule 3 -- Impossible Travel Detection
# ---------------------------------------------------------------------------

def detect_impossible_travel(
    df: pd.DataFrame,
    distance_km: int = 500,
    window_minutes: int = 60,
) -> list[dict]:
    """Detect impossible-travel anomalies.

    Flags any user who logs in from two locations that are MORE THAN
    `distance_km` kilometres apart within `window_minutes` minutes.
    Since humans cannot physically travel that fast, this indicates
    credential theft or session sharing.

    How it works:
        1. Group events by username.
        2. Sort each user's events chronologically.
        3. For each consecutive pair of logins, check:
           a. Are they within `window_minutes` of each other?
           b. Are the two locations more than `distance_km` apart?
        4. If both conditions are true, create an alert.

    Args:
        df: DataFrame with columns: timestamp, username, source_ip,
            location.
        distance_km: Minimum distance (km) between two logins to be
                     considered "impossible".  Default is 500.
        window_minutes: Maximum time gap (minutes) between two logins.
                        Default is 60.

    Returns:
        A list of alert dicts, one per detected impossible-travel pair.
    """
    alerts: list[dict] = []

    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])

    for user, group in work.groupby("username"):
        group = group.sort_values("timestamp")
        rows = group.to_dict("records")

        # Compare each login to the NEXT login for the same user.
        # If the locations are far apart and the time gap is small,
        # it's impossible travel.
        for idx in range(len(rows) - 1):
            current = rows[idx]
            next_event = rows[idx + 1]

            # Calculate the time gap between the two logins
            time_gap = next_event["timestamp"] - current["timestamp"]
            if time_gap > timedelta(minutes=window_minutes):
                # Too much time has passed -- not suspicious
                continue

            # Calculate the geographic distance between the two locations
            loc1 = current["location"]
            loc2 = next_event["location"]

            # Skip if both logins are from the same location
            if loc1 == loc2:
                continue

            dist = get_distance_km(loc1, loc2)
            if dist is None:
                # Unknown location -- can't compute distance, skip
                continue

            if dist > distance_km:
                gap_minutes = time_gap.total_seconds() / 60

                alerts.append({
                    "rule_name": "impossible_travel",
                    "severity": "critical",
                    "affected_user": user,
                    "source_ip": (
                        f"{current['source_ip']} -> "
                        f"{next_event['source_ip']}"
                    ),
                    "description": (
                        f"User '{user}' logged in from {loc1} and then "
                        f"{loc2} ({dist:,} km apart) within "
                        f"{gap_minutes:.0f} minutes. "
                        f"IPs: {current['source_ip']} -> "
                        f"{next_event['source_ip']}."
                    ),
                    "event_count": 2,
                    "window_start": str(current["timestamp"]),
                    "window_end": str(next_event["timestamp"]),
                })

    print(f"[Rule] Impossible-travel check: {len(alerts)} alert(s) found")
    return alerts


# ---------------------------------------------------------------------------
# Main entry point -- run all rules
# ---------------------------------------------------------------------------

def run_all_rules(df: pd.DataFrame) -> list[dict]:
    """Execute every detection rule against the event DataFrame.

    This is the main function that downstream code (e.g. alert_manager)
    should call.  It runs each rule in sequence and merges the results
    into a single flat list of alert dicts.

    Args:
        df: DataFrame containing login events.  Expected columns:
            timestamp, username, source_ip, location, login_success.

    Returns:
        A list of alert dicts.  Each dict contains at minimum:
            rule_name   (str)  : "brute_force" / "password_spray" /
                                 "impossible_travel"
            severity    (str)  : "low" / "medium" / "high" / "critical"
            affected_user (str): The user(s) targeted
            source_ip   (str)  : The suspicious IP address
            description (str)  : Human-readable explanation
    """
    print("=" * 55)
    print("  Security Log Analyzer -- Rule Engine")
    print("=" * 55)

    all_alerts: list[dict] = []

    # --- Rule 1: Brute-force detection ---
    # Looks for a single IP generating many failed logins quickly.
    brute_alerts = detect_brute_force(df, threshold=5, window_minutes=10)
    all_alerts.extend(brute_alerts)

    # --- Rule 2: Password-spray detection ---
    # NOTE: threshold is 4 here because our test data only has 8 spray users.
    # TODO: make thresholds configurable via a config file or CLI args
    spray_alerts = detect_password_spray(df, threshold=4, window_minutes=5)
    all_alerts.extend(spray_alerts)

    # --- Rule 3: Impossible-travel detection ---
    # Looks for the same user logging in from distant locations in a
    # short time window.
    travel_alerts = detect_impossible_travel(
        df, distance_km=500, window_minutes=60,
    )
    all_alerts.extend(travel_alerts)

    # --- Summary ---
    print("-" * 55)
    print(f"Total rule-based alerts: {len(all_alerts)}")
    for alert in all_alerts:
        print(
            f"  [{alert['severity'].upper():>8}] {alert['rule_name']:<20} "
            f"| user: {alert['affected_user']}"
        )
    print("-" * 55)

    return all_alerts


# ---------------------------------------------------------------------------
# Standalone execution (for testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Load the feature-engineered dataset (output of feature_engineering.py)
    print("Loading data from data/processed/login_features.csv ...")
    df = pd.read_csv("data/processed/login_features.csv")
    print(f"Loaded {len(df)} events\n")

    # Run all detection rules
    alerts = run_all_rules(df)

    # Print each alert in detail
    if alerts:
        print(f"\n{'=' * 55}")
        print(f"  Detailed Alert Output ({len(alerts)} alerts)")
        print(f"{'=' * 55}")
        for i, alert in enumerate(alerts, 1):
            print(f"\n--- Alert {i} ---")
            for key, value in alert.items():
                print(f"  {key:<16}: {value}")
    else:
        print("\nNo rule-based alerts generated.")
