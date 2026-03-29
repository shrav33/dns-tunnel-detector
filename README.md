# DNS Tunnel Detector

A machine learning system that detects DNS tunneling attacks in real time.
Built as a cybersecurity project demonstrating the attacker → victim → detector scenario.

## What it does

DNS tunneling is a technique attackers use to secretly send stolen data out of a
network by hiding it inside DNS queries — a protocol that is almost never blocked
by firewalls. This system uses a Random Forest ML model to detect those suspicious
queries in real time and display alerts on a live dashboard.

## Demo

The project runs as a three-role simulation:
- **Attacker** — a Python script simulating malware sending tunnel queries
- **Victim** — the local machine the attacker script runs on
- **Detector** — a Flask dashboard that catches tunnel queries as they arrive

## Project structure
```
dns-tunnel-detector/
├── generate_dataset.py   # generates labeled training data
├── attacker_sim.py       # simulates malware sending DNS tunnel queries
├── data/
│   └── dns_dataset.csv   # 1000 labeled DNS queries (700 normal, 300 tunnel)
├── model/
│   ├── features.py       # extracts 5 features from each domain name
│   ├── train.py          # trains the Random Forest model
│   └── rf_model.pkl      # saved trained model
├── shared/
│   └── dns_log.txt       # shared log file between attacker and detector
└── app/
    ├── app.py            # Flask backend with live SSE stream
    └── templates/
        └── index.html    # live dashboard UI
```

## How to run

**1. Clone the repository**
```
git clone https://github.com/shrav33/dns-tunnel-detector.git
cd dns-tunnel-detector
```

**2. Create and activate virtual environment**
```
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac / Linux
```

**3. Install libraries**
```
pip install pandas scikit-learn flask matplotlib seaborn joblib
```

**4. Generate dataset and train model**
```
python generate_dataset.py
python model/train.py
```

**5. Start the detector (Terminal 1)**
```
python app/app.py
```

**6. Start the attacker simulator (Terminal 2)**
```
python attacker_sim.py
```

**7. Open the dashboard**
```
http://127.0.0.1:5000
```

## Model performance

- **Accuracy:** 100% on generated dataset
- **Precision:** 1.00 (no false alarms)
- **Recall:** 1.00 (no missed tunnels)
- **Top features:** subdomain length (43.6%), digit ratio (30.5%), total length (19.2%)

## Features extracted per query

| Feature | Description |
|---|---|
| total_length | Total character count of domain |
| entropy | Randomness score — encoded data scores high |
| subdomain_count | Number of dots in domain |
| digit_ratio | Fraction of characters that are digits |
| subdomain_len | Length of the leftmost subdomain part |

## Future work (V2 roadmap)

- Retrain on real labeled dataset (CIRA-CIC-DoHBrw-2020)
- Add model comparison (Random Forest vs XGBoost vs Logistic Regression)
- Add entropy distribution charts to dashboard
- Test against evasion techniques

## Tech stack

Python · scikit-learn · Flask · pandas · HTML/CSS/JavaScript
```

---

After pasting and saving, run:
```
git add .
git commit -m "Add README"
git push