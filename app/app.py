import sys
import os
import json
import time
import csv
import io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'model'))
from flask import Flask, Response, render_template, request, jsonify
import joblib
from features import extract_features

app = Flask(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'dns_rf_model.pkl')
LOG_PATH   = os.path.join(os.path.dirname(__file__), '..', 'shared', 'dns_log.txt')
STATS_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'model_stats.json')

model = joblib.load(MODEL_PATH)
print("V2 Model loaded successfully.")

alert_store = []

def generate_events():
    lines_seen = 0
    while True:
        try:
            with open(LOG_PATH, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            time.sleep(0.3)
            continue
        new_lines = lines[lines_seen:]
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(',', 1)
            if len(parts) != 2:
                continue
            timestamp, domain = parts[0], parts[1]
            try:
                features = extract_features(domain)
                prediction = int(model.predict([features])[0])
                confidence = float(model.predict_proba([features])[0][prediction])
                confidence = round(confidence * 100, 1)
            except Exception:
                continue
            event = {
                'timestamp': timestamp,
                'domain': domain,
                'prediction': prediction,
                'label': 'TUNNEL' if prediction == 1 else 'NORMAL',
                'confidence': confidence
            }
            if prediction == 1:
                alert_store.append(event)
            yield f"data: {json.dumps(event)}\n\n"
        lines_seen = len(lines)
        time.sleep(0.3)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream')
def stream():
    return Response(generate_events(), mimetype='text/event-stream')

@app.route('/reset', methods=['POST'])
def reset():
    global alert_store
    alert_store = []
    open(LOG_PATH, 'w').close()
    return 'ok'

@app.route('/model-stats')
def model_stats():
    try:
        with open(STATS_PATH, 'r') as f:
            stats = json.load(f)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-alerts')
def download_alerts():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['timestamp', 'domain', 'label', 'confidence'])
    writer.writeheader()
    writer.writerows(alert_store)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=dns_alerts.csv'}
    )

if __name__ == '__main__':
    app.run(debug=False, threaded=True)