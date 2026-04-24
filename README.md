# DNS Tunnel Detection System

A real-time machine learning-based network security tool that detects DNS tunneling attacks — a technique used by attackers to covertly exfiltrate data and maintain backdoor access by hiding malicious traffic inside routine DNS queries.

## What it does

DNS tunneling exploits the fact that port 53 is left open by virtually every firewall. This system monitors DNS traffic in real time and classifies each query through a three-layer detection pipeline, alerting security analysts to suspicious activity through a live web dashboard.

## Three-layer detection

- **Layer 1 — Whitelist:** 39 trusted domains bypass ML classification entirely, eliminating false positives on known-good infrastructure
- **Layer 2 — ML Classification:** Random Forest model trained on 20 statistical features classifies each query as benign or tunnel with sub-100ms latency
- **Layer 3 — Session Detection:** 60-second sliding window tracks query frequency per registrar, fires alert when threshold of 15 is exceeded — catches evasion-style attacks that per-query ML misses entirely

## Model performance

Trained on the BCCC-CIC-Bell-DNS-2024 dataset — 4,153,762 real DNS traffic records from the Canadian Institute for Cybersecurity.

- Random Forest — 95.43% accuracy, ROC-AUC 0.9607 (production model)
- XGBoost — 93.82% accuracy, ROC-AUC 0.9458
- Logistic Regression — 88.38% accuracy, ROC-AUC 0.9049

## Evasion testing

Tested across 8 attack types and 1,600 domains:

- Hex encoded tunnel — 88% detected
- Obvious base64 tunnel — 62.5% detected
- Numeric tunnel — 42.5% detected
- Mimicry, short word, slow drip, two-word, three-word tunnels — 0% by ML alone, caught by session detection layer
- Average detection rate across all 8 types: 24.1%

## Project structure
dns-tunnel-detector/
├── app/
│   ├── app.py                  Flask backend — SSE streaming, detection pipeline
│   └── templates/index.html    Live dashboard — Chart.js, real-time alerts
├── model/
│   ├── train.py                Trains Random Forest on CIC dataset
│   ├── compare_models.py       Three-model comparison
│   ├── features.py             Extracts 20 features per DNS query
│   ├── model_stats.json        Accuracy, confusion matrix, feature importances
│   ├── comparison_results.json ROC curve data for all 3 models
│   └── evasion_results.json    8 attack type evasion test results
├── shared/dns_log.txt          Message bus between simulator and backend
├── whitelist.json              39 trusted domains
├── attacker_sim.py             Mixed benign + tunnel traffic simulator
├── evasion_tester.py           8 attack type evasion tester
├── session_test.py             Session detection validator
└── requirements.txt

> Note: trained model files (.pkl) and raw dataset CSVs are excluded due to file size limits. Download the dataset from Kaggle (BCCC-CIC-Bell-DNS-2024) and run model/train.py to regenerate.

## How to run

1. Clone the repo and activate virtual environment
2. Install dependencies: pip install -r requirements.txt
3. Download BCCC-CIC-Bell-DNS-2024 dataset from Kaggle into data/ folder
4. Train the model: python model/train.py
5. Start the detector: python app/app.py
6. Start the simulator: python attacker_sim.py
7. Open the dashboard: http://127.0.0.1:5000

## Dashboard features

- Live query log colour coded by classification — green normal, red ML tunnel, amber session tunnel, grey trusted
- ML tunnel alerts with domain name, timestamp, and confidence score
- Session tunnel alerts panel showing registrar and query count
- Feature importance chart, ROC curves for all 3 models
- Model comparison table, evasion attack results panel
- Reset session button and CSV alert export

## Tech stack

Python · Flask · scikit-learn · XGBoost · pandas · Scapy · Chart.js
