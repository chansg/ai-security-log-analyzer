from __future__ import annotations

import random
from datetime import datetime, timedelta
import pandas as pd


def generate_login_data(num_rows: int = 1000) -> pd.DataFrame:
    users = ["alice", "bob", "charlie", "admin", "guest"]
    locations = ["UK", "US", "DE", "FR"]
    devices = ["Windows-Laptop", "MacBook", "Desktop-PC", "VPN-Client"]
    base_time = datetime(2026, 3, 1, 8, 0, 0)

    rows = []

    for _ in range(num_rows):
        timestamp = base_time + timedelta(minutes=random.randint(0, 60 * 24 * 7))
        username = random.choice(users)
        source_ip = f"192.168.1.{random.randint(1, 254)}"
        location = random.choice(locations)
        device = random.choice(devices)
        login_success = random.choices([1, 0], weights=[0.9, 0.1])[0]

        rows.append(
            {
                "timestamp": timestamp,
                "username": username,
                "source_ip": source_ip,
                "location": location,
                "device": device,
                "login_success": login_success,
            }
        )

    df = pd.DataFrame(rows)

    anomalies = [
        {
            "timestamp": datetime(2026, 3, 3, 3, 15, 0),
            "username": "admin",
            "source_ip": "203.0.113.50",
            "location": "RU",
            "device": "Unknown-Host",
            "login_success": 1,
        },
        {
            "timestamp": datetime(2026, 3, 4, 2, 10, 0),
            "username": "bob",
            "source_ip": "198.51.100.99",
            "location": "CN",
            "device": "Unknown-Device",
            "login_success": 0,
        },
    ]

    df = pd.concat([df, pd.DataFrame(anomalies)], ignore_index=True)
    return df.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    df = generate_login_data()
    df.to_csv("data/raw/login_data.csv", index=False)
    print("Sample data written to data/raw/login_data.csv")