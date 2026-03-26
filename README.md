# AI Security Log Analyzer

Detecting suspicious authentication behaviour using machine learning-driven anomaly detection.

![Dashboard](https://github.com/chansg/ai-security-log-analyzer/images/dashboard.png)

---

## Overview

AI Security Log Analyzer is a Python-based security analytics project designed to identify suspicious authentication activity using machine learning.

The system simulates authentication telemetry, processes login events into structured datasets, engineers behavioural security features, and applies an **Isolation Forest anomaly detection model** to identify unusual login behaviour. A **rule engine** provides deterministic, threshold-based detection alongside the ML model, and a **Django web dashboard** presents the combined results.

This project demonstrates how **security monitoring systems combine data engineering, feature analysis, and machine learning** to detect potential threats such as:

- Brute-force login attempts
- Password spraying
- Suspicious administrative activity
- Unusual login times
- New IP or device activity
- Impossible travel scenarios

The goal of this project is to replicate a simplified version of the **security analytics workflows used by modern SOC teams and security engineers**.

---

## Architecture

The pipeline follows a typical **security data processing workflow**:

```
Authentication Logs
│
▼
Data Generation / Ingestion
│
▼
Preprocessing & Feature Engineering
│
▼
Machine Learning Model (Isolation Forest)  +  Rule Engine
│
▼
Anomaly Detection & Alert Generation
│
▼
SQLite Database  /  JSON Export
│
▼
Django Web Dashboard
```

---

## Project Structure

```
SecurityLogAnalyzer/
│
├── run_pipeline.py                    # CLI entry point — run the full pipeline or individual stages
│
├── src/
│   ├── generate_sample_data.py        # Stage 1: Generate synthetic login data with attacks
│   ├── preprocess.py                  # Stage 2: Parse timestamps & extract temporal features
│   ├── feature_engineering.py         # Stage 3: Engineer behavioural features for the model
│   ├── train_model.py                 # Stage 4: Train the Isolation Forest model
│   ├── detect_anomalies.py            # Stage 5: Run anomaly detection and write reports
│   ├── alert_manager.py              # Stage 6: Combine ML + rule alerts, store in SQLite/JSON
│   ├── rule_engine.py                 # Rule-based detection (brute force, spray, impossible travel)
│   ├── evaluate.py                    # Stage 7: Evaluate model accuracy with ground-truth labels
│   └── visualize_anomalies.py         # Stage 8: Generate anomalies-by-date chart
│
├── dashboard/
│   ├── manage.py                      # Django management CLI
│   ├── dashboard_config/
│   │   ├── settings.py                # Django settings
│   │   ├── urls.py                    # URL routing
│   │   └── wsgi.py                    # WSGI entry point
│   └── alerts/
│       ├── views.py                   # Dashboard views (home, user detail, chart API)
│       ├── urls.py                    # App URL routing
│       ├── templates/alerts/          # HTML templates (base, home, user detail)
│       ├── static/css/style.css       # Dark-theme styling
│       └── templatetags/alert_tags.py # Custom template filters
│
├── data/
│   ├── raw/                           # Raw generated login data
│   ├── processed/                     # Preprocessed and feature-engineered data
│   ├── alerts.db                      # SQLite alert database
│   └── alerts.json                    # JSON alert export
│
├── models/
│   └── isolation_forest.pkl           # Trained Isolation Forest model
│
├── output/
│   ├── alerts.csv                     # ML-detected anomalies
│   ├── anomaly_report.txt             # Human-readable anomaly report
│   ├── anomalies_by_date.png          # Bar chart of anomalies by date
│   └── confusion_matrix.png           # Model evaluation heatmap
│
├── notebooks/                         # Jupyter notebooks for analysis
├── requirements.txt                   # Python dependencies
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/chansg/ai-security-log-analyzer.git
cd ai-security-log-analyzer

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Pipeline

The project includes a **CLI runner** (`run_pipeline.py`) that manages all pipeline stages. You no longer need to run each script manually in the correct order.

### Run the full pipeline

```bash
python run_pipeline.py
```

This executes all 8 stages sequentially:

| # | Stage | Description |
|---|-------|-------------|
| 1 | `generate` | Generate synthetic login data with injected attack scenarios |
| 2 | `preprocess` | Parse timestamps and extract temporal features |
| 3 | `features` | Engineer behavioural features for the ML model |
| 4 | `train` | Train the Isolation Forest anomaly-detection model |
| 5 | `detect` | Run anomaly detection and write reports to `output/` |
| 6 | `alerts` | Run ML + rule engine, store alerts in SQLite and JSON |
| 7 | `evaluate` | Evaluate model accuracy against ground-truth labels |
| 8 | `visualize` | Generate the anomalies-by-date bar chart |

If any stage fails, the pipeline stops immediately — later stages depend on earlier outputs.

### Run individual stages

```bash
python run_pipeline.py generate          # run only data generation
python run_pipeline.py train detect      # run training then detection
python run_pipeline.py alerts evaluate   # run alerts then evaluation
```

Stages always execute in the correct pipeline order regardless of the order you type them.

### Launch the web dashboard

```bash
python run_pipeline.py dashboard
```

This starts the Django development server at `http://127.0.0.1:8000`. Press `Ctrl+C` to stop.

### List available stages

```bash
python run_pipeline.py --list
```

---

## Detection Use Cases

The system generates and detects several security scenarios.

### Brute Force Attack

Repeated login failures against a privileged account.

Indicators:
- Rapid failed logins
- Multiple attempts from a single external IP

### Password Spraying

Multiple users targeted with a single password attempt.

Indicators:
- Same IP targeting multiple accounts
- Short time window of failed logins

### Impossible Travel

A user authenticates from two geographically distant locations within an unrealistic time window.

Indicators:
- New IP
- New device
- Rapid location change

### Suspicious Admin Login

Administrative account activity occurring at unusual hours or from unknown hosts.

Indicators:
- Late night login
- New device
- Unknown IP

---

## Feature Engineering

The project extracts behavioural features commonly used in security analytics.

| Feature | Description |
|---------|-------------|
| `hour` | Login time of day |
| `day_of_week` | Day the login occurred |
| `is_night_login` | Flag for unusual login hours |
| `user_failed_count_total` | Cumulative failed login attempts per user |
| `ip_failed_count_total` | Failed attempts from a specific IP |
| `is_new_ip_for_user` | Indicates if user logged in from a new IP |
| `is_new_device_for_user` | Indicates if device is new for that user |
| `user_event_count` | Number of events generated by user |

These features help model **normal behavioural baselines** for users and detect deviations.

---

## Machine Learning Model

The system uses an **Isolation Forest model** for anomaly detection.

Isolation Forest works by identifying data points that are easier to isolate from the majority of observations.

Key characteristics:

- Works well with **unlabeled data**
- Effective for **outlier detection**
- Common baseline model in **security anomaly detection systems**

Model parameters used:

```python
IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42
)
```

---

## Rule Engine

Alongside the ML model, a deterministic rule engine applies threshold-based detection:

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | > 5 failed logins from one IP within 10 minutes | CRITICAL |
| Password Spray | > 10 distinct users from one IP within 5 minutes | HIGH |
| Impossible Travel | Same user from locations > 500 km apart within 60 minutes | CRITICAL |

Both ML and rule-based alerts are combined into a single SQLite database and JSON export.

---

## Example Output

**Detected Alerts**

```
timestamp                | user  | source_ip      | location | device         | success | anomaly_score
2026-03-04 02:10:20      | admin | 185.220.101.45 | RU       | Unknown-Host   | 0       | -0.34
2026-03-05 09:40:00      | alice | 103.88.12.44   | SG       | Unknown-Device | 1       | -0.29
```

**Security Report**

```
AI Security Log Analyzer Report
================================

Total events analysed: 1200
Anomalies detected: 21

Detected suspicious events:
- Brute force pattern targeting admin
- Impossible travel for user alice
- Password spraying attempt
- Unusual admin activity
```

**Visualisation**

![Anomalies by Date](https://github.com/chansg/ai-security-log-analyzer/blob/master/output/anomalies_by_date.png)

---

## Web Dashboard

The Django dashboard provides a visual overview of all alerts:

- **Summary cards** — Total alerts, severity breakdown, ML vs rule counts
- **Time-series chart** — Alert volume over time (Chart.js)
- **Alerts table** — Sortable list with severity badges
- **User drill-down** — Click a user to see their specific alerts

---

## MITRE ATT&CK Mapping

Some detections relate to known MITRE ATT&CK techniques.

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1078.003 | Local Accounts |
| T1078.004 | Cloud Accounts |
| T1021 | Remote Services |

---

## Technologies Used

- Python
- Pandas
- NumPy
- Scikit-learn
- Matplotlib
- Django
- SQLite
- Chart.js

---

## Author

Chanveer S Grewal
