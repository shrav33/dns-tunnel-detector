import sys
import os
import json
import time
import csv
import io
import threading
from collections import defaultdict, deque
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'model'))
from flask import Flask, Response, render_template, request, jsonify
import joblib
from features import extract_features

app = Flask(__name__)

MODEL_PATH      = os.path.join(os.path.dirname(__file__), '..', 'model', 'dns_rf_model.pkl')
LOG_PATH        = os.path.join(os.path.dirname(__file__), '..', 'shared', 'dns_log.txt')
STATS_PATH      = os.path.join(os.path.dirname(__file__), '..', 'model', 'model_stats.json')
COMPARISON_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'comparison_results.json')
EVASION_PATH    = os.path.join(os.path.dirname(__file__), '..', 'model', 'evasion_results.json')
WHITELIST_PATH  = os.path.join(os.path.dirname(__file__), '..', 'whitelist.json')

model = joblib.load(MODEL_PATH)
print("V4 Model loaded successfully.")

# ── Load whitelist ──
def load_whitelist():
    try:
        with open(WHITELIST_PATH, 'r') as f:
            data = json.load(f)
        domains = set(data.get('domains', []))
        print(f"Whitelist loaded: {len(domains)} trusted domains")
        return domains
    except Exception as e:
        print(f"Whitelist not found: {e}")
        return set()

WHITELIST = load_whitelist()

def is_whitelisted(domain):
    domain = domain.strip().lower().rstrip('.')
    for trusted in WHITELIST:
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    return False

def get_registrar(domain):
    """Extract the registrar (last two parts) from a domain."""
    parts = domain.strip().lower().rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

# ── Session-level detection ──
SESSION_WINDOW   = 60    # seconds to look back
SESSION_THRESHOLD = 15   # queries to same registrar in window = tunnel
session_window   = defaultdict(deque)   # registrar -> deque of timestamps
session_lock     = threading.Lock()
session_alerts   = []                   # session-level detections
session_events   = deque(maxlen=500)    # SSE events for session alerts

def record_query(domain, timestamp_str):
    """Add query to session window and check threshold."""
    registrar = get_registrar(domain)

    # Skip whitelisted registrars
    if is_whitelisted(registrar) or is_whitelisted(domain):
        return None

    now = time.time()
    with session_lock:
        dq = session_window[registrar]
        dq.append(now)
        # Remove entries older than SESSION_WINDOW
        while dq and dq[0] < now - SESSION_WINDOW:
            dq.popleft()
        count = len(dq)

    if count >= SESSION_THRESHOLD:
        # Only fire once per registrar per 30 seconds
        already_alerted = any(
            a['registrar'] == registrar and
            time.time() - a['time'] < 30
            for a in session_alerts[-10:]
        )
        if not already_alerted:
            alert = {
                'timestamp': timestamp_str,
                'registrar': registrar,
                'count': count,
                'window': SESSION_WINDOW,
                'type': 'SESSION_TUNNEL'
            }
            session_alerts.append({**alert, 'time': time.time()})
            session_events.append(alert)
            print(f"[SESSION ALERT] {registrar} — {count} queries in {SESSION_WINDOW}s")
            return alert
    return None

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
            timestamp, domain = parts[0], parts[1].strip()

            # ── Whitelist check ──
            if is_whitelisted(domain):
                event = {
                    'timestamp': timestamp,
                    'domain': domain,
                    'prediction': -1,
                    'label': 'WHITELISTED',
                    'confidence': 100.0
                }
                yield f"data: {json.dumps(event)}\n\n"
                lines_seen += 1
                continue

            # ── Session-level detection ──
            session_alert = record_query(domain, timestamp)
            if session_alert:
                yield f"data: {json.dumps({**session_alert, 'prediction': 2})}\n\n"

            # ── Per-query ML classification ──
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
    global alert_store, session_alerts
    alert_store = []
    session_alerts = []
    with session_lock:
        session_window.clear()
    session_events.clear()
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

@app.route('/comparison-stats')
def comparison_stats():
    try:
        with open(COMPARISON_PATH, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/evasion-stats')
def evasion_stats():
    try:
        with open(EVASION_PATH, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/whitelist')
def get_whitelist():
    return jsonify({
        'count': len(WHITELIST),
        'domains': sorted(list(WHITELIST))
    })

@app.route('/session-alerts')
def get_session_alerts():
    return jsonify({
        'alerts': [
            {k: v for k, v in a.items() if k != 'time'}
            for a in session_alerts[-20:]
        ],
        'total': len(session_alerts),
        'threshold': SESSION_THRESHOLD,
        'window': SESSION_WINDOW
    })

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