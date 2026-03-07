from __future__ import annotations

import random
from datetime import datetime, timedelta
import pandas as pd


def random_ip(private: bool = True) -> str:
    if private:
        return f"192.168.1.{random.randint(1, 254)}"
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_normal_events(num_rows: int = 1200) -> list[dict]:
    users = {
        "alice": {"location": "UK", "device": "Windows-Laptop", "base_ip": "192.168.1."},
        "bob": {"location": "UK", "device": "Desktop-PC", "base_ip": "192.168.1."},
        "charlie": {"location": "DE", "device": "MacBook", "base_ip": "192.168.1."},
        "admin": {"location": "UK", "device": "Admin-Workstation", "base_ip": "10.0.0."},
        "guest": {"location": "UK", "device": "Shared-Kiosk", "base_ip": "192.168.1."},
    }

    base_time = datetime(2026, 3, 1, 0, 0, 0)
    rows: list[dict] = []

    for _ in range(num_rows):
        username = random.choice(list(users.keys()))
        profile = users[username]

        day_offset = random.randint(0, 6)
        hour = random.choices(
            population=list(range(24)),
            weights=[1, 1, 1, 1, 1, 2, 3, 6, 8, 10, 10, 9, 9, 9, 9, 8, 8, 7, 5, 4, 3, 2, 1, 1],
            k=1,
        )[0]
        minute = random.randint(0, 59)

        timestamp = base_time + timedelta(days=day_offset, hours=hour, minutes=minute)

        success = random.choices([1, 0], weights=[0.94, 0.06])[0]

        rows.append(
            {
                "timestamp": timestamp,
                "username": username,
                "source_ip": f"{profile['base_ip']}{random.randint(10, 80)}",
                "location": profile["location"],
                "device": profile["device"],
                "login_success": success,
            }
        )

    return rows


def add_brute_force_attack(rows: list[dict]) -> None:
    start = datetime(2026, 3, 4, 2, 10, 0)
    for i in range(12):
        rows.append(
            {
                "timestamp": start + timedelta(seconds=i * 20),
                "username": "admin",
                "source_ip": "185.220.101.45",
                "location": "RU",
                "device": "Unknown-Host",
                "login_success": 0 if i < 11 else 1,
            }
        )


def add_impossible_travel(rows: list[dict]) -> None:
    rows.append(
        {
            "timestamp": datetime(2026, 3, 5, 9, 0, 0),
            "username": "alice",
            "source_ip": "192.168.1.24",
            "location": "UK",
            "device": "Windows-Laptop",
            "login_success": 1,
        }
    )
    rows.append(
        {
            "timestamp": datetime(2026, 3, 5, 9, 40, 0),
            "username": "alice",
            "source_ip": "103.88.12.44",
            "location": "SG",
            "device": "Unknown-Device",
            "login_success": 1,
        }
    )


def add_night_admin_activity(rows: list[dict]) -> None:
    rows.append(
        {
            "timestamp": datetime(2026, 3, 6, 3, 17, 0),
            "username": "admin",
            "source_ip": "45.77.12.9",
            "location": "NL",
            "device": "Unknown-Device",
            "login_success": 1,
        }
    )


def add_password_spray(rows: list[dict]) -> None:
    spray_users = ["alice", "bob", "charlie", "guest"]
    start = datetime(2026, 3, 3, 1, 30, 0)
    for idx, user in enumerate(spray_users):
        rows.append(
            {
                "timestamp": start + timedelta(seconds=idx * 25),
                "username": user,
                "source_ip": "198.51.100.77",
                "location": "US",
                "device": "Unknown-Host",
                "login_success": 0,
            }
        )


def generate_login_data() -> pd.DataFrame:
    rows = generate_normal_events()
    add_brute_force_attack(rows)
    add_impossible_travel(rows)
    add_night_admin_activity(rows)
    add_password_spray(rows)

    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    random.seed(42)
    df = generate_login_data()
    df.to_csv("data/raw/login_data.csv", index=False)
    print("Sample data written to data/raw/login_data.csv")
    print(df.tail(10))