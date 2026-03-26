"""
generate_sample_data.py — Synthetic Security Log Generator
===========================================================
Creates a realistic dataset of authentication (login) events for the
AI Security Log Analyzer pipeline.  The dataset contains a large body
of normal user activity mixed with four clearly labelled attack
scenarios so that downstream models can be trained and evaluated.

Attack types injected:
    - brute_force        : rapid failed logins from one IP against one user
    - password_spray     : one IP trying many different user accounts
    - impossible_travel  : same user from two distant locations within minutes
    - off_hours          : legitimate-looking logins at 2–4 AM

Every event carries an ``attack_type`` label column ("normal" for
baseline traffic) so we can measure model precision/recall per
category in the evaluation step.

Usage:
    python src/generate_sample_data.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

import pandas as pd


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def random_ip(private: bool = True) -> str:
    """Generate a random IP address string.

    Args:
        private: If True, returns an IP in the 192.168.1.x private range
                 (simulating internal corporate network traffic).
                 If False, returns a random public-looking IP address.

    Returns:
        A dotted-quad IP string, e.g. '192.168.1.42' or '87.120.55.12'.
    """
    if private:
        # Private IPs simulate devices on the internal corporate LAN
        return f"192.168.1.{random.randint(1, 254)}"
    # TODO: should probably exclude reserved ranges properly (RFC 5737 etc)
    return (
        f"{random.randint(11, 223)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )


# ---------------------------------------------------------------------------
# Normal (baseline) traffic
# ---------------------------------------------------------------------------

def generate_normal_events(num_rows: int = 1200) -> list[dict]:
    """Generate realistic normal login events across a 7-day window.

    Creates login events for five user profiles (alice, bob, charlie,
    admin, guest).  Timestamps are weighted toward business hours
    (6 AM – 5 PM) to simulate real office traffic, and about 94 % of
    logins succeed (the remaining 6 % are typos, expired passwords, etc.).

    Args:
        num_rows: Number of normal events to create.  Default is 1 200.

    Returns:
        A list of dicts, each representing one login event with keys:
        timestamp, username, source_ip, location, device, login_success,
        attack_type.
    """
    # ---- User profiles ----
    # Each user has a "home" location, a typical device, and an internal
    # IP prefix they connect from during normal work.
    users = {
        "alice":   {"location": "UK", "device": "Windows-Laptop",    "base_ip": "192.168.1."},
        "bob":     {"location": "UK", "device": "Desktop-PC",        "base_ip": "192.168.1."},
        "charlie": {"location": "DE", "device": "MacBook",           "base_ip": "192.168.1."},
        "admin":   {"location": "UK", "device": "Admin-Workstation", "base_ip": "10.0.0."},
        "guest":   {"location": "UK", "device": "Shared-Kiosk",      "base_ip": "192.168.1."},
    }

    # TODO: make the date range configurable instead of hardcoding
    base_time = datetime(2026, 3, 1, 0, 0, 0)
    rows: list[dict] = []

    for _ in range(num_rows):
        username = random.choice(list(users.keys()))
        profile = users[username]

        # Pick a random day inside the 7-day window (day 0 … day 6)
        day_offset = random.randint(0, 6)

        # Hour weights — heavily favour 6 AM – 5 PM (business hours).
        # Index 0 = midnight, index 23 = 11 PM.
        # Higher weight = more likely to be chosen.
        hour = random.choices(
            population=list(range(24)),
            weights=[
                1, 1, 1, 1, 1, 2,   # 00:00 – 05:00  (very rare)
                3, 6, 8, 10, 10, 9,  # 06:00 – 11:00  (ramp-up)
                9, 9, 9, 8, 8, 7,    # 12:00 – 17:00  (peak → wind-down)
                5, 4, 3, 2, 1, 1,    # 18:00 – 23:00  (evening, rare)
            ],
            k=1,
        )[0]
        minute = random.randint(0, 59)

        timestamp = base_time + timedelta(days=day_offset, hours=hour, minutes=minute)

        # 94 % of normal logins succeed; 6 % fail
        success = random.choices([1, 0], weights=[0.94, 0.06])[0]

        rows.append(
            {
                "timestamp": timestamp,
                "username": username,
                "source_ip": f"{profile['base_ip']}{random.randint(10, 80)}",
                "location": profile["location"],
                "device": profile["device"],
                "login_success": success,
                "attack_type": "normal",  # label for evaluation
            }
        )

    print(f"[+] Generated {len(rows)} normal login events")
    return rows


# ---------------------------------------------------------------------------
# Attack scenario 1 — Brute Force
# ---------------------------------------------------------------------------

def add_brute_force_attack(rows: list[dict]) -> None:
    """Inject a brute-force attack pattern into the event list.

    Simulates a single external IP rapidly trying to log in to the
    'admin' account many times in quick succession.  This is the
    classic brute-force pattern: many failed attempts from one IP
    against one user, ending with one eventual success (the attacker
    guessed the password).

    Pattern details:
        - 25 attempts total (24 failures + 1 success at the end)
        - 5-second intervals (automated tooling fires fast)
        - Occurs at 2:10 AM on March 4 (outside business hours)
        - Source IP is in the 185.220.x.x range (known Tor exit nodes)

    Args:
        rows: The event list to append attack events to (modified in place).
    """
    # ---- Attack parameters ----
    attacker_ip = "185.220.101.45"           # known-malicious IP range
    target_user = "admin"                     # high-value target account
    num_attempts = 25                         # 24 failures, then 1 success
    interval_seconds = 5                      # rapid-fire automated attempts
    start = datetime(2026, 3, 4, 2, 10, 0)   # 2:10 AM — outside office hours

    for i in range(num_attempts):
        # Every attempt fails except the very last one, where the
        # attacker finally guesses the correct password.
        success = 1 if i == num_attempts - 1 else 0

        rows.append(
            {
                "timestamp": start + timedelta(seconds=i * interval_seconds),
                "username": target_user,
                "source_ip": attacker_ip,
                "location": "RU",             # attack originates from Russia
                "device": "Unknown-Host",      # unrecognised device
                "login_success": success,
                "attack_type": "brute_force",  # label for evaluation
            }
        )

    print(
        f"[+] Added brute-force attack: {num_attempts} events "
        f"against '{target_user}' from {attacker_ip}"
    )


# ---------------------------------------------------------------------------
# Attack scenario 2 — Password Spray
# ---------------------------------------------------------------------------

def add_password_spray(rows: list[dict]) -> None:
    """Inject a password-spray attack pattern into the event list.

    Simulates an attacker trying the SAME common password against MANY
    different user accounts.  Unlike brute force (many passwords against
    one user), a password spray = one password against many users.
    The attacker spaces attempts ~25 seconds apart to stay below
    per-user lockout thresholds.

    Pattern details:
        - 8 different usernames targeted from a single external IP
        - All attempts fail (the common password was wrong)
        - 25-second gap between each attempt (evasion tactic)
        - Occurs at 1:30 AM on March 3

    Args:
        rows: The event list to append attack events to (modified in place).
    """
    # The attacker tries usernames harvested from an email directory or
    # LDAP dump — some are real employees, some are service accounts.
    spray_users = [
        "alice", "bob", "charlie", "guest",
        "admin", "service_desk", "david", "eve",
    ]
    attacker_ip = "198.51.100.77"
    interval_seconds = 25                      # slow to dodge per-user lockout
    start = datetime(2026, 3, 3, 1, 30, 0)    # 1:30 AM — off-hours

    for idx, user in enumerate(spray_users):
        rows.append(
            {
                "timestamp": start + timedelta(seconds=idx * interval_seconds),
                "username": user,
                "source_ip": attacker_ip,
                "location": "US",
                "device": "Unknown-Host",
                "login_success": 0,               # all attempts fail
                "attack_type": "password_spray",   # label for evaluation
            }
        )

    print(
        f"[+] Added password-spray attack: {len(spray_users)} users "
        f"targeted from {attacker_ip}"
    )


# ---------------------------------------------------------------------------
# Attack scenario 3 — Impossible Travel
# ---------------------------------------------------------------------------

def add_impossible_travel(rows: list[dict]) -> None:
    """Inject an impossible-travel anomaly into the event list.

    Creates two successful logins by the same user (alice) from two
    geographically distant locations (UK and Singapore) only 40 minutes
    apart.  Since the flight time between London and Singapore is
    ~13 hours, this is physically impossible and strongly suggests
    credential theft — someone else is using alice's account from a
    different country.

    Pattern details:
        - Login 1: alice in UK at 09:00 on March 5 (normal)
        - Login 2: "alice" in Singapore at 09:40 on March 5 (suspicious)
        - Both logins succeed

    Args:
        rows: The event list to append attack events to (modified in place).
    """
    # Login 1 — alice logs in normally from her UK office
    rows.append(
        {
            "timestamp": datetime(2026, 3, 5, 9, 0, 0),
            "username": "alice",
            "source_ip": "192.168.1.24",          # her usual internal IP
            "location": "UK",
            "device": "Windows-Laptop",            # her usual device
            "login_success": 1,
            "attack_type": "impossible_travel",    # label for evaluation
        }
    )

    # Login 2 — only 40 minutes later, "alice" logs in from Singapore.
    # This is physically impossible.  The second login is likely an
    # attacker using stolen credentials from a different country.
    rows.append(
        {
            "timestamp": datetime(2026, 3, 5, 9, 40, 0),
            "username": "alice",
            "source_ip": "103.88.12.44",           # Singapore IP block
            "location": "SG",
            "device": "Unknown-Device",
            "login_success": 1,
            "attack_type": "impossible_travel",    # label for evaluation
        }
    )

    print(
        "[+] Added impossible-travel anomaly: "
        "alice in UK then SG within 40 minutes"
    )


# ---------------------------------------------------------------------------
# Attack scenario 4 — Off-Hours Logins
# ---------------------------------------------------------------------------

def add_off_hours_logins(rows: list[dict]) -> None:
    """Inject off-hours login events into the event list.

    Simulates logins between 2 AM and 4 AM for users who typically only
    log in during business hours.  Some events use the user's normal
    device and internal IP (could be a compromised insider or stolen VPN
    credentials), while one uses a foreign IP (more overtly suspicious).

    These are harder to detect than brute force because they LOOK
    legitimate — correct username, correct device, successful login —
    but the *timing* is abnormal for these users.

    Pattern details:
        - 4 events spread across different users and dates
        - All logins succeed (correct credentials)
        - Timestamps fall in the 2:00 AM – 4:00 AM window

    Args:
        rows: The event list to append off-hours events to (modified in place).
    """
    off_hours_events = [
        # bob never works at 3 AM, but here he is — possibly a stolen
        # VPN session being used by an attacker.
        {
            "timestamp": datetime(2026, 3, 2, 3, 5, 0),
            "username": "bob",
            "source_ip": "192.168.1.55",       # internal IP (looks legit)
            "location": "UK",
            "device": "Desktop-PC",            # bob's normal device
            "login_success": 1,
            "attack_type": "off_hours",        # label for evaluation
        },
        # charlie logging in at 2:22 AM from his normal MacBook — very
        # unusual for a user whose hours are 8 AM – 6 PM.
        {
            "timestamp": datetime(2026, 3, 4, 2, 22, 0),
            "username": "charlie",
            "source_ip": "192.168.1.30",       # internal IP
            "location": "DE",
            "device": "MacBook",               # charlie's normal device
            "login_success": 1,
            "attack_type": "off_hours",
        },
        # admin from a foreign IP at 3:17 AM — the most overtly
        # suspicious variant: wrong country AND wrong time.
        {
            "timestamp": datetime(2026, 3, 6, 3, 17, 0),
            "username": "admin",
            "source_ip": "45.77.12.9",         # Netherlands IP
            "location": "NL",
            "device": "Unknown-Device",
            "login_success": 1,
            "attack_type": "off_hours",
        },
        # alice at 2:48 AM — she normally works 9–5 UK hours.
        # Internal IP and correct device, so it looks genuine on
        # the surface — only the timestamp is the red flag.
        {
            "timestamp": datetime(2026, 3, 7, 2, 48, 0),
            "username": "alice",
            "source_ip": "192.168.1.24",       # alice's usual IP
            "location": "UK",
            "device": "Windows-Laptop",        # alice's usual device
            "login_success": 1,
            "attack_type": "off_hours",
        },
    ]

    # Append all off-hours events in one go
    rows.extend(off_hours_events)

    print(
        f"[+] Added {len(off_hours_events)} off-hours login events "
        f"(2 AM - 4 AM window)"
    )


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

def generate_login_data() -> pd.DataFrame:
    """Orchestrate the full synthetic-data generation pipeline.

    Generates a large body of normal login events, then layers four
    distinct attack patterns on top.  Returns a time-sorted DataFrame
    with every row carrying an ``attack_type`` label for downstream
    evaluation.

    Returns:
        A pandas DataFrame sorted by timestamp, with columns:
        timestamp, username, source_ip, location, device,
        login_success, attack_type.
    """
    print("=" * 55)
    print("  Security Log Analyzer -- Sample Data Generator")
    print("=" * 55)

    # Step 1: build the baseline of normal user activity
    rows = generate_normal_events()

    # Step 2: layer each attack pattern on top of the normal traffic
    add_brute_force_attack(rows)
    add_password_spray(rows)
    add_impossible_travel(rows)
    add_off_hours_logins(rows)

    # Step 3: convert to DataFrame and sort chronologically
    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Step 4: print a summary so the operator can verify the mix
    print("-" * 55)
    print("Event breakdown by attack_type:")
    print(df["attack_type"].value_counts().to_string())
    print(f"\nTotal events: {len(df)}")
    print("-" * 55)

    return df


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Fixed seed so every run produces the exact same dataset,
    # ensuring reproducibility across the entire pipeline.
    random.seed(42)

    df = generate_login_data()

    # Save to the standard raw-data location consumed by preprocess.py
    output_path = "data/raw/login_data.csv"
    df.to_csv(output_path, index=False)

    print(f"\n[OK] Sample data written to {output_path}")
    print(f"    Rows   : {len(df)}")
    print(f"    Columns: {list(df.columns)}")
