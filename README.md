<h1>V1</h1>
<h3>Run the full pipeline</h3>
python src/generate_sample_data.py
python src/preprocess.py
python src/feature_engineering.py
python src/train_model.py
python src/detect_anomalies.py

You will have 
<ul>
    <tr>a generated security login dataset</tr>
    <tr>processed feature</tr>
    <tr>an anomaly detection model</tr>
    <tr>a CSV of suspicious events</tr>
    <tr>a text report</tr>
</ul>
