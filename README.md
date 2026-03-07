<h1>AI Security Log Analyzer</h1>
<h3>Run the full pipeline</h3>
python src/generate_sample_data.py <br>
python src/preprocess.py <br>
python src/feature_engineering.py <br>
python src/train_model.py <br>
python src/detect_anomalies.py <br>
<br>
You will have

- data/raw/login_data.csv

- data/processed/login_data_processed.csv

- data/processed/login_features.csv

- models/isolation_forest.pkl

- output/alerts.csv

- output/anomaly_report.txt

- output/anomalies_by_date.png

![description](https://github.com/chansg/ai-security-log-analyzer/blob/master/output/anomalies_by_date.png)
