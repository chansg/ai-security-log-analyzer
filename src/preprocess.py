from __future__ import annotations

import pandas as pd


def load_and_preprocess(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["date"] = df["timestamp"].dt.date.astype(str)
    df["is_night_login"] = df["hour"].apply(lambda x: 1 if x < 6 or x >= 23 else 0)

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    processed = load_and_preprocess("data/raw/login_data.csv")
    processed.to_csv("data/processed/login_data_processed.csv", index=False)
    print("Processed data saved to data/processed/login_data_processed.csv")