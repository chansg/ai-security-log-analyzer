from __future__ import annotations

import pandas as pd


def load_and_preprocess(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["is_night_login"] = df["hour"].apply(lambda x: 1 if x < 6 or x > 22 else 0)
    return df


if __name__ == "__main__":
    df = load_and_preprocess("data/raw/login_data.csv")
    df.to_csv("data/processed/login_data_processed.csv", index=False)
    print("Processed data saved.")