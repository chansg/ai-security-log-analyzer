from __future__ import annotations

import pandas as pd


def add_new_ip_flag(df: pd.DataFrame) -> pd.Series:
    seen_ips: dict[str, set[str]] = {}
    flags: list[int] = []

    for _, row in df.iterrows():
        user = row["username"]
        ip = row["source_ip"]

        if user not in seen_ips:
            seen_ips[user] = set()

        flags.append(0 if ip in seen_ips[user] else 1)
        seen_ips[user].add(ip)

    return pd.Series(flags, index=df.index)


def add_new_device_flag(df: pd.DataFrame) -> pd.Series:
    seen_devices: dict[str, set[str]] = {}
    flags: list[int] = []

    for _, row in df.iterrows():
        user = row["username"]
        device = row["device"]

        if user not in seen_devices:
            seen_devices[user] = set()

        flags.append(0 if device in seen_devices[user] else 1)
        seen_devices[user].add(device)

    return pd.Series(flags, index=df.index)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    feature_df = df.copy()

    feature_df["failed_login"] = 1 - feature_df["login_success"]
    feature_df["user_failed_count_total"] = feature_df.groupby("username")["failed_login"].cumsum()

    feature_df["ip_failed_count_total"] = feature_df.groupby("source_ip")["failed_login"].cumsum()

    feature_df["is_new_ip_for_user"] = add_new_ip_flag(feature_df)
    feature_df["is_new_device_for_user"] = add_new_device_flag(feature_df)

    feature_df["user_event_count"] = feature_df.groupby("username").cumcount() + 1

    return feature_df


if __name__ == "__main__":
    df = pd.read_csv("data/processed/login_data_processed.csv")
    featured = build_features(df)
    featured.to_csv("data/processed/login_features.csv", index=False)
    print("Feature dataset saved to data/processed/login_features.csv")