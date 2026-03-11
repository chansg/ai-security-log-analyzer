"""
evaluate.py -- Model Evaluation and Performance Metrics
========================================================
Uses the ``attack_type`` labels we embedded in Step 1 to measure how
well the Isolation Forest model detects each kind of attack.

The Isolation Forest is an UNSUPERVISED model -- it was never told what
an "attack" looks like.  It only learned what "normal" looks like and
flags anything that deviates.  This evaluation tells us:

    * Does the model catch brute-force attacks?
    * Does it catch password sprays?
    * Does it miss impossible-travel or off-hours logins?
    * How many false positives (normal events flagged as suspicious)?

Metrics produced:
    - Binary confusion matrix   (attack vs normal)
    - Per-attack-type detection rate
    - Precision, Recall, F1-score
    - Saved confusion-matrix image (output/confusion_matrix.png)

How to read the key metrics:
    Precision = Of everything the model flagged, what % was truly an attack?
                High precision = few false alarms.
    Recall    = Of all real attacks, what % did the model catch?
                High recall = few missed attacks.
    F1-score  = Harmonic mean of precision and recall (balances both).

Usage:
    python src/evaluate.py
"""

from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

# matplotlib is only used for saving the confusion-matrix image.
# We use the "Agg" backend so it works on servers without a display.
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Same feature list used by train_model.py and detect_anomalies.py.
# If you ever add or remove features, update ALL three files.
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

# File paths
FEATURES_PATH = "data/processed/login_features.csv"
MODEL_PATH = "models/isolation_forest.pkl"
CONFUSION_MATRIX_PATH = "output/confusion_matrix.png"


# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------

def build_ground_truth(df: pd.DataFrame) -> pd.Series:
    """Convert the ``attack_type`` column into a binary label.

    The Isolation Forest returns -1 (anomaly) or 1 (normal).
    To compare against it, we need the ground-truth labels in the
    same format:

        attack_type == "normal"  -->  1   (truly normal)
        attack_type != "normal"  -->  -1  (truly an attack)

    Args:
        df: DataFrame with an ``attack_type`` column.

    Returns:
        A pandas Series of 1 (normal) and -1 (attack) values,
        aligned with the DataFrame index.
    """
    # np.where is like an if/else applied to every row at once:
    #   if attack_type == "normal" -> 1, else -> -1
    return pd.Series(
        np.where(df["attack_type"] == "normal", 1, -1),
        index=df.index,
    )


def print_binary_metrics(y_true: pd.Series, y_pred: np.ndarray) -> None:
    """Print overall precision, recall, and F1 for the binary case.

    "Binary case" means we collapse all attack types into one class
    ("attack") and evaluate how well the model separates attacks from
    normal events.

    The ``pos_label=-1`` argument tells sklearn that -1 is the class
    we care about (i.e. "positive" = "detected as anomaly").

    Args:
        y_true: Ground-truth labels (1 = normal, -1 = attack).
        y_pred: Model predictions (1 = normal, -1 = anomaly).
    """
    # precision_recall_fscore_support returns four arrays: precision,
    # recall, f1, and support (count).  We ask for the "binary" average
    # with pos_label=-1 because we want metrics for the ATTACK class.
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=-1,
    )

    print("  Binary Classification (attack vs normal)")
    print(f"    Precision : {precision:.4f}")
    print(f"    Recall    : {recall:.4f}")
    print(f"    F1-score  : {f1:.4f}")
    print()

    # Also print the full sklearn classification report, which shows
    # metrics for BOTH classes (normal and anomaly).
    # target_names gives human-readable labels instead of -1 and 1.
    report = classification_report(
        y_true, y_pred,
        target_names=["Anomaly (-1)", "Normal (1)"],
        digits=4,
    )
    print("  Full Classification Report:")
    for line in report.split("\n"):
        print(f"    {line}")


def print_per_attack_detection(
    df: pd.DataFrame,
    y_pred: np.ndarray,
) -> None:
    """Show the model's detection rate for each individual attack type.

    For every attack category (brute_force, password_spray, etc.) we
    count how many events the model flagged as anomalous vs how many
    exist in total.  This tells us which attacks the model is good at
    catching and which ones it misses.

    Args:
        df:     DataFrame with an ``attack_type`` column.
        y_pred: Model predictions (-1 = anomaly, 1 = normal).
    """
    # Attach predictions to the DataFrame so we can group by attack_type
    work = df[["attack_type"]].copy()
    work["predicted"] = y_pred

    print("  Per-Attack-Type Detection Rates:")
    print(f"    {'Attack Type':<22} {'Detected':>8} {'Total':>6} {'Rate':>8}")
    print(f"    {'-' * 48}")

    # Get the unique attack types, putting "normal" last for readability
    attack_types = sorted(work["attack_type"].unique())
    if "normal" in attack_types:
        attack_types.remove("normal")
        attack_types.append("normal")

    for attack in attack_types:
        # Filter to just events of this attack type
        subset = work[work["attack_type"] == attack]
        total = len(subset)

        if attack == "normal":
            # For normal events, "detected" means the model CORRECTLY
            # classified them as normal (prediction == 1).
            # False positives are normal events flagged as anomaly.
            correctly_normal = (subset["predicted"] == 1).sum()
            false_positives = (subset["predicted"] == -1).sum()
            print(
                f"    {'normal':<22} "
                f"{correctly_normal:>8} "
                f"{total:>6} "
                f"{correctly_normal / total:>8.1%}"
            )
            print(
                f"      (false positives: {false_positives} normal events "
                f"incorrectly flagged)"
            )
        else:
            # For attack events, "detected" means the model flagged them
            # as anomalous (prediction == -1).  That's what we want.
            detected = (subset["predicted"] == -1).sum()
            missed = total - detected
            rate = detected / total if total > 0 else 0
            print(
                f"    {attack:<22} "
                f"{detected:>8} "
                f"{total:>6} "
                f"{rate:>8.1%}"
            )
            if missed > 0:
                print(f"      (missed {missed} events)")


def print_confusion_matrix(y_true: pd.Series, y_pred: np.ndarray) -> None:
    """Print and save a confusion matrix.

    A confusion matrix is a 2x2 table that shows:
                          Predicted Normal  |  Predicted Anomaly
        Actually Normal:      TN            |      FP
        Actually Attack:      FN            |      TP

    Where:
        TP = True Positive  = real attack, model caught it       (good)
        TN = True Negative  = normal event, model said normal    (good)
        FP = False Positive = normal event, model flagged it     (bad -- false alarm)
        FN = False Negative = real attack, model missed it       (bad -- missed attack)

    Args:
        y_true: Ground-truth labels (1 = normal, -1 = attack).
        y_pred: Model predictions (1 = normal, -1 = anomaly).
    """
    # labels=[-1, 1] ensures the matrix rows/columns are ordered:
    #   row 0 / col 0 = anomaly (-1)
    #   row 1 / col 1 = normal  (1)
    cm = confusion_matrix(y_true, y_pred, labels=[-1, 1])

    # Extract the four quadrants for the text summary
    tp = cm[0, 0]  # true positives  (attacks correctly detected)
    fn = cm[0, 1]  # false negatives (attacks missed)
    fp = cm[1, 0]  # false positives (normal events falsely flagged)
    tn = cm[1, 1]  # true negatives  (normal events correctly cleared)

    print("  Confusion Matrix:")
    print(f"    {'':>25} Predicted Anomaly  Predicted Normal")
    print(f"    {'Actually Attack':<25} {tp:>17}  {fn:>16}")
    print(f"    {'Actually Normal':<25} {fp:>17}  {tn:>16}")
    print()
    print(f"    True Positives  (TP) : {tp:>5}  (attacks caught)")
    print(f"    True Negatives  (TN) : {tn:>5}  (normals cleared)")
    print(f"    False Positives (FP) : {fp:>5}  (false alarms)")
    print(f"    False Negatives (FN) : {fn:>5}  (missed attacks)")

    # ---- Save a visual confusion-matrix image ----
    # This creates a colour-coded heatmap that is easier to read than
    # raw numbers, especially when presenting results.
    fig, ax = plt.subplots(figsize=(7, 5))

    # Use a blue colour map -- darker blue = higher count
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)

    # Label the axes
    classes = ["Attack\n(anomaly)", "Normal"]
    tick_marks = [0, 1]
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(classes, fontsize=11)
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(classes, fontsize=11)
    ax.set_xlabel("Predicted Label", fontsize=12)
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_title("Isolation Forest -- Confusion Matrix", fontsize=14)

    # Print the count numbers inside each cell of the heatmap
    # so you can read the exact values at a glance.
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center", fontsize=16,
                color="white" if cm[i, j] > thresh else "black",
            )

    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=150)
    plt.close()

    print(f"\n    Confusion matrix saved to {CONFUSION_MATRIX_PATH}")


# ---------------------------------------------------------------------------
# Main evaluation pipeline
# ---------------------------------------------------------------------------

def evaluate() -> None:
    """Run the complete model evaluation pipeline.

    Steps:
        1. Load the feature data (with attack_type labels)
        2. Load the trained Isolation Forest model
        3. Generate predictions for every event
        4. Build binary ground-truth labels from attack_type
        5. Print binary precision / recall / F1
        6. Print per-attack-type detection rates
        7. Print and save the confusion matrix
    """
    print("=" * 55)
    print("  Security Log Analyzer -- Model Evaluation")
    print("=" * 55)

    # ---- Step 1: Load data and model ----
    print("\n[1/4] Loading data and model ...")
    df = pd.read_csv(FEATURES_PATH)
    model = joblib.load(MODEL_PATH)
    print(f"       Events : {len(df)}")
    print(f"       Attacks: {(df['attack_type'] != 'normal').sum()}")
    print(f"       Normal : {(df['attack_type'] == 'normal').sum()}")

    # ---- Step 2: Generate predictions ----
    print("\n[2/4] Running model predictions ...")
    y_pred = model.predict(df[FEATURE_COLUMNS])
    y_true = build_ground_truth(df)

    total_flagged = (y_pred == -1).sum()
    print(f"       Model flagged {total_flagged} events as anomalous")

    # ---- Step 3: Print metrics ----
    print("\n[3/4] Computing evaluation metrics ...\n")
    print_binary_metrics(y_true, y_pred)
    print()
    print_per_attack_detection(df, y_pred)

    # ---- Step 4: Confusion matrix ----
    print("\n[4/4] Building confusion matrix ...\n")
    print_confusion_matrix(y_true, y_pred)

    print("\n" + "=" * 55)
    print("  Evaluation complete")
    print("=" * 55)


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    evaluate()
