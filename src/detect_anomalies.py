from __future__ import annotations

import joblib
import pandas as pd


FEATURE_COLUMNS = [
    "hour",
    "day_of_week",
    "login_success",
    "is_night_login",
    "user_failed_count_total",
    "ip_failed_count_total",
    "is_new_ip_for_user",
    "is_new_device_for_user",
    "user_event_count",
]


def detect() -> None:
    df = pd.read_csv("data/processed/login_features.csv")
    model = joblib.load("models/isolation_forest.pkl")

    predictions = model.predict(df[FEATURE_COLUMNS])
    scores = model.decision_function(df[FEATURE_COLUMNS])

    df["anomaly"] = predictions
    df["anomaly_score"] = scores

    anomalies = df[df["anomaly"] == -1].copy()
    anomalies.to_csv("output/alerts.csv", index=False)

    # TODO: only printing first 20 anomalies in the report — fine for now but
    # should probably paginate or at least mention if there are more
    with open("output/anomaly_report.txt", "w", encoding="utf-8") as f:
        f.write("AI Security Log Analyzer Report\n")
        f.write("=" * 40 + "\n")
        f.write(f"Total events analysed: {len(df)}\n")
        f.write(f"Anomalies detected: {len(anomalies)}\n\n")

        for _, row in anomalies.head(20).iterrows():
            f.write(
                f"{row['timestamp']} | user={row['username']} | ip={row['source_ip']} "
                f"| location={row['location']} | device={row['device']} "
                f"| success={row['login_success']} | score={row['anomaly_score']:.4f}\n"
            )

    print("Anomaly detection complete. Results saved to output/.")


if __name__ == "__main__":
    detect()