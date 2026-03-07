from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "login_success",
    "is_night_login",
    "user_failed_count",
    "is_new_ip_for_user",
    "is_new_device_for_user",
]


def train() -> None:
    df = pd.read_csv("data/processed/login_features.csv")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=42,
    )

    model.fit(df[FEATURE_COLUMNS])
    joblib.dump(model, "models/isolation_forest.pkl")
    print("Model saved to models/isolation_forest.pkl")


if __name__ == "__main__":
    train()