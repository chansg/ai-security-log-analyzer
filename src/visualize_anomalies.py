from __future__ import annotations

import pandas as pd
import matplotlib.pyplot as plt


def main() -> None:
    # TODO: add severity breakdown to the chart (stacked bars by severity?)
    df = pd.read_csv("output/alerts.csv")
    if df.empty:
        print("No anomalies found.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    counts = df.groupby(df["timestamp"].dt.date).size()

    plt.figure(figsize=(10, 5))
    counts.plot(kind="bar")
    plt.title("Detected Anomalies by Date")
    plt.xlabel("Date")
    plt.ylabel("Number of Anomalies")
    plt.tight_layout()
    plt.savefig("output/anomalies_by_date.png")
    print("Saved chart to output/anomalies_by_date.png")


if __name__ == "__main__":
    main()