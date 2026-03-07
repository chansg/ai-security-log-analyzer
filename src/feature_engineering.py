from __future__ import annotations

import pandas as pd


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    feature_df = df.copy()

    feature_df["failed_login"] = 1 - feature_df["login_success"]
    feature_df["user_failed_count"] = feature_df.groupby("username")["failed_login"].cumsum()

    feature_df["is_new_ip_for_user"] = (
        feature_df.groupby("username")["source_ip"]
        .transform(lambda s: ~s.duplicated())
        .astype(int)
    )

    feature_df["is_new_device_for_user"] = (
        feature_df.groupby("username")["device"]
        .transform(lambda s: ~s.duplicated())
        .astype(int)
    )

    return feature_df


if __name__ == "__main__":
    df = pd.read_csv("data/processed/login_data_processed.csv")
    featured = build_features(df)
    featured.to_csv("data/processed/login_features.csv", index=False)
    print("Feature dataset saved.")