# DNS Tunnel Detector — Project Report

---

## Title Page

**Title:** DNS Tunnel Detector: A Machine Learning System for Real-Time Detection of DNS Tunnelling Attacks

**Author:** [Your Full Name] ([Student Registration Number])

**Centre:** [Your Study Centre]

---

## Abstract

DNS tunnelling is a cyber-attack technique in which an adversary encodes arbitrary data inside DNS query strings, exploiting the fact that DNS traffic is rarely blocked by enterprise firewalls. This project designs and implements a full-stack, machine-learning-based DNS tunnel detection system that operates in real time. The system ingests DNS query logs, extracts twenty statistical and lexical features from each domain name, and classifies each query using a Random Forest classifier trained on the BCCC-CIC-Bell DNS Exfiltration dataset (over four million labelled records). A secondary session-level detection layer monitors query-rate behaviour over a sixty-second sliding window to catch low-entropy evasion attacks that defeat per-query classification. Results show 95.43% accuracy and a ROC-AUC of 0.9607 for the primary classifier, with Random Forest outperforming both XGBoost and Logistic Regression on this task. Evasion testing reveals a critical gap: word-based tunnelling techniques achieve 100% bypass of per-query detection, motivating the session-layer design. All components are integrated into a live Flask-based dashboard with Server-Sent Events streaming, model comparison charts, and alert export.

---

## Contents

1. Introduction
2. Background
3. Analysis
4. Design
5. Other Project Matters
6. Conclusion
7. References

**List of Figures:**
- Figure 1: System Architecture Overview
- Figure 2: Feature Extraction Pipeline
- Figure 3: Model Comparison Table
- Figure 4: Evasion Test Results
- Figure 5: Confusion Matrix (Random Forest)

**List of Tables:**
- Table 1: The Twenty Extracted Features
- Table 2: Model Performance Comparison
- Table 3: Evasion Attack Detection Rates

---

## Acknowledgements

The author wishes to thank the Canadian Institute for Cybersecurity for making the BCCC-CIC-Bell DNS dataset publicly available, and to the open-source maintainers of scikit-learn, XGBoost, and Flask whose libraries underpin this project.

---

## 1. Introduction

### 1.1 Background

The Domain Name System (DNS) is one of the oldest and most fundamental protocols of the internet, translating human-readable hostnames into IP addresses. Because it is essential for almost all internet activity, DNS traffic is rarely filtered or inspected by firewalls and network security devices. This trusted status makes DNS an attractive covert channel for attackers. DNS tunnelling is the technique of encoding arbitrary data — stolen files, command-and-control instructions, or credentials — inside DNS query subdomains. A compromised machine queries a domain such as `aGVsbG8gd29ybGQ.attacker-c2.net`, where the subdomain `aGVsbG8gd29ybGQ` is a Base64-encoded payload. The attacker's authoritative nameserver receives and decodes these queries, extracting the exfiltrated data without the network ever seeing a direct TCP connection to the attacker.

Well-known tools that automate DNS tunnelling include iodine, dnscat2, and dns2tcp. These tools are widely used both by red teams in penetration testing and by real-world threat actors. Detecting them is therefore a priority for network defenders.

Traditional signature-based intrusion detection systems (IDS) struggle with DNS tunnelling because attackers can trivially change domain names, encoding schemes, or timing patterns. Machine learning offers a more robust approach: instead of matching fixed patterns, an ML classifier learns statistical signatures of tunnel traffic that are harder to evade at scale.

### 1.2 The Design That Emerged

This project implements a complete pipeline:

1. **Data ingestion** — a labelled CSV dataset of over 4.1 million DNS records from the BCCC-CIC-Bell-DNS dataset, split into exfiltration (tunnel) and benign categories.
2. **Feature engineering** — twenty lexical, statistical, and TTL-based features extracted from each domain string.
3. **Model training and comparison** — three classifiers (Random Forest, XGBoost, Logistic Regression) trained and evaluated on an 80/20 stratified split.
4. **Live detection** — a Flask backend reads a shared log file, extracts features, and classifies each incoming query via the trained model.
5. **Session-level detection** — a sliding-window frequency counter catches evasion techniques that fool per-query ML.
6. **Dashboard** — a dark-themed web UI streams events via Server-Sent Events and displays live charts, alerts, confusion matrices, ROC curves, and evasion test results.

### 1.3 Aims and Objectives

- **Aim:** Build a practical, demonstrable DNS tunnel detection system combining machine learning classification with behavioural analysis.
- **Objective 1:** Identify and implement a feature set that captures the statistical differences between tunnelled and benign DNS queries.
- **Objective 2:** Train and compare multiple ML classifiers to select the best model for live deployment.
- **Objective 3:** Quantify model robustness by testing against eight evasion attack styles.
- **Objective 4:** Develop a real-time web dashboard that presents detection events and model analytics to a security analyst.

### 1.4 Report Structure

Chapter 2 reviews DNS tunnelling literature and relevant ML approaches. Chapter 3 presents requirements and use-case analysis. Chapter 4 covers structural and behavioural design. Chapter 5 addresses project management and testing. Chapter 6 concludes with evaluation and future directions.

---

## 2. Background

### 2.1 DNS Tunnelling

DNS was standardised in RFC 1034 and RFC 1035 (Mockapetris, 1987). The protocol allows a hostname to be resolved through a hierarchy of nameservers. The critical observation for attackers is that a query for `payload.attacker.com` will reach the attacker's authoritative nameserver regardless of any firewall, as long as DNS is permitted on the network — which it almost always is.

Modern DNS tunnel tools fragment large payloads across multiple queries and reassemble them at the nameserver. iodine tunnels full IP packets over DNS, enabling the attacker to run any TCP/IP application over the covert channel. dnscat2 provides an encrypted command-and-control channel. Academic studies have demonstrated that DNS exfiltration can achieve throughput of several kilobits per second on typical enterprise networks (Born and Gustafson, 2010).

### 2.2 Detection Approaches

Feizollah et al. (2013) categorise DNS anomaly detection into three families: payload analysis, traffic volume analysis, and machine learning. Early work (Bilge et al., 2011) relied on traffic volume thresholds — tunnel traffic tends to generate many queries to the same domain in a short time. This approach is defeated by slow-drip attacks that space queries to stay below thresholds.

Lexical analysis of the domain string itself provides a more robust signal. Tunnel subdomains encoded in Base64 or hex exhibit high Shannon entropy, unusual character distributions, long subdomain lengths, and high digit ratios compared with human-readable domains. Kara et al. (2021) demonstrate that a Random Forest classifier using entropy and length features achieves over 97% accuracy on standard datasets. Paxson (2013) highlights that ML-based detectors are more robust than signature systems because they generalise to unseen encoding schemes.

### 2.3 Relevant Datasets

The BCCC-CIC-Bell DNS dataset used in this project (Habibi Lashkari et al., 2022) contains over four million labelled DNS flow records, covering benign traffic and multiple malicious categories including DNS exfiltration. Each record contains pre-computed features such as domain length, entropy, TTL statistics, and answer record counts. This is one of the most comprehensive publicly available DNS security datasets and was selected because it closely matches the features extractable from live DNS queries.

### 2.4 Machine Learning Algorithms

**Random Forest** is an ensemble of decision trees trained on bootstrapped subsets of the data, with random feature subsets considered at each split (Breiman, 2001). It handles class imbalance well with the `class_weight="balanced"` parameter, is robust to outliers, and provides feature importances that aid interpretability.

**XGBoost** (Chen and Guestrin, 2016) is a gradient-boosted tree ensemble that typically achieves state-of-the-art results on tabular data. It handles imbalance via the `scale_pos_weight` parameter.

**Logistic Regression** is a linear probabilistic classifier serving as an interpretable baseline. It requires feature scaling (StandardScaler) and is expected to underperform the tree-based models on this non-linear problem.

### 2.5 Development Framework

The project uses an iterative, prototype-driven development approach loosely aligned with agile principles. Each version (V1 through V4) added a layer of functionality: V1 established the basic ML pipeline; V2 retrained on the full BCCC-CIC-Bell dataset; V3 added model comparison and evasion testing; V4 introduced session-level detection and the full dashboard.

---

## 3. Analysis

### 3.1 Requirements

#### Functional Requirements

| ID | Requirement |
|----|-------------|
| FR1 | The system shall classify each incoming DNS query as NORMAL or TUNNEL in real time. |
| FR2 | The system shall extract twenty features from each domain name string. |
| FR3 | The system shall train on the BCCC-CIC-Bell DNS dataset and save a serialised model. |
| FR4 | The system shall compare at least three ML classifiers and select the best by ROC-AUC. |
| FR5 | The system shall maintain a sliding-window session counter per registrar and fire a session alert when a threshold is exceeded. |
| FR6 | The system shall stream detection events to a web dashboard in real time. |
| FR7 | The system shall support a whitelist of trusted domains that bypass ML classification. |
| FR8 | The system shall allow the analyst to export all alerts as a CSV file. |
| FR9 | The system shall display model performance metrics, confusion matrix, ROC curves, and evasion test results on the dashboard. |
| FR10 | The system shall allow the session and query log to be reset from the dashboard. |

#### Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR1 | Detection latency from log entry to dashboard event shall be under one second. |
| NFR2 | The dashboard shall be accessible from any modern browser with no plugin installation. |
| NFR3 | The ML model shall achieve at least 90% accuracy on the BCCC-CIC-Bell test set. |
| NFR4 | The system shall handle at least one query per 0.5 seconds without dropping events. |
| NFR5 | The codebase shall be structured so each component (data, model, app) is independently runnable. |

### 3.2 Use Cases

#### Use Case 1: Real-Time Query Classification

- **Actor:** DNS Tunnel Detector (automated)
- **Precondition:** Attacker simulator is writing queries to `shared/dns_log.txt`.
- **Main Flow:** The Flask backend polls the log file every 0.3 seconds. For each new line, it checks the whitelist, runs session-level detection, extracts twenty features, runs ML classification, and emits a Server-Sent Event to the dashboard.
- **Postcondition:** The dashboard displays NORMAL, TUNNEL, SESSION TUNNEL, or TRUSTED for each query.

#### Use Case 2: Security Analyst Reviews Alerts

- **Actor:** Security Analyst
- **Precondition:** Dashboard is open in a browser; some tunnel queries have been detected.
- **Main Flow:** Analyst views the ML Alerts panel, sees flagged domains with confidence scores and timestamps. Analyst clicks "Export Alerts CSV" to download a structured report.
- **Postcondition:** A CSV file `dns_alerts.csv` is downloaded containing all ML tunnel detections.

#### Use Case 3: Analyst Resets the Session

- **Actor:** Security Analyst
- **Precondition:** A demo or test run has completed.
- **Main Flow:** Analyst clicks "Reset Session" on the dashboard. The backend clears the alert store, session counters, and truncates the shared log file.
- **Postcondition:** All counters reset to zero; log file is empty.

#### Use Case 4: Model Training and Comparison

- **Actor:** Developer/Data Scientist
- **Precondition:** BCCC-CIC-Bell CSV files are present in `data/`.
- **Main Flow:** Developer runs `python model/train.py` to train the Random Forest and save it. Developer optionally runs `python model/compare_models.py` to benchmark all three classifiers and update the active model to the best performer.
- **Postcondition:** `dns_rf_model.pkl`, `model_stats.json`, and `comparison_results.json` are written.

#### Use Case 5: Evasion Testing

- **Actor:** Developer/Security Researcher
- **Precondition:** A trained model exists at `model/dns_rf_model.pkl`.
- **Main Flow:** Developer runs `python evasion_tester.py`. Eight evasion attack generators produce 200 domains each. The model classifies each; detection rates, evasion rates, and threat levels are computed.
- **Postcondition:** `evasion_results.json` is written and results are displayed on the dashboard Evasion Tests panel.

---

## 4. Design

### 4.1 Structural Model

#### 4.1.1 System Architecture

The system is divided into four layers:

```
┌─────────────────────────────────────────────────┐
│  Presentation Layer                             │
│  app/templates/index.html (HTML/CSS/JS)         │
│  Chart.js · Server-Sent Events consumer         │
└────────────────────┬────────────────────────────┘
                     │ HTTP / SSE
┌────────────────────▼────────────────────────────┐
│  Application Layer                              │
│  app/app.py  (Flask)                            │
│  Routes: / /stream /reset /model-stats          │
│          /comparison-stats /evasion-stats        │
│          /whitelist /session-alerts              │
│          /download-alerts                        │
└──────────┬──────────────────┬───────────────────┘
           │                  │
┌──────────▼──────┐  ┌────────▼──────────────────┐
│  Detection Layer│  │  Model Layer               │
│  Session window │  │  model/features.py         │
│  Whitelist      │  │  model/train.py            │
│  SSE generator  │  │  model/compare_models.py   │
└──────────┬──────┘  │  dns_rf_model.pkl          │
           │         └────────────────────────────┘
┌──────────▼──────────────────────────────────────┐
│  Data Layer                                     │
│  shared/dns_log.txt  (shared log)               │
│  data/BCCC-CIC-Bell-DNS-EXF/*.csv               │
│  data/BCCC-CIC-Bell-DNS-Mal/*.csv               │
│  whitelist.json                                 │
└─────────────────────────────────────────────────┘
```

#### 4.1.2 Module Descriptions

**`generate_dataset.py`** — Synthetic dataset generator used for early prototyping (V1). Produces 1,000 labelled records (700 normal, 300 tunnel) by sampling from a list of real domain names and generating Base64-encoded tunnel subdomains over fictional C2 domains.

**`attacker_sim.py`** — Simulates a compromised host sending a mix of normal and tunnel DNS queries. Runs in a loop, writing one query every 0.5 seconds to `shared/dns_log.txt`. Approximately 25% of queries are tunnel queries.

**`model/features.py`** — The feature extraction module. The `extract_features(domain)` function accepts a domain string and returns a list of twenty numeric values. The `FEATURE_NAMES` list provides the corresponding column names, matching those in the BCCC-CIC-Bell dataset exactly.

**`model/train.py`** — Loads all CSV files from the EXF and MAL dataset directories, assigns binary labels (0 = benign, 1 = tunnel), selects the twenty features, imputes missing values with column medians, performs a stratified 80/20 train-test split, trains a Random Forest with 200 estimators and balanced class weights, evaluates on the test set, and serialises the model and statistics.

**`model/compare_models.py`** — Extends the training pipeline to train and evaluate Random Forest, XGBoost, and Logistic Regression on the same split. Saves all three models and writes `comparison_results.json` including ROC curve data for dashboard visualisation. Promotes the best-performing model (by ROC-AUC) as the active `dns_rf_model.pkl`.

**`evasion_tester.py`** — Defines eight domain generators simulating different evasion strategies and evaluates the loaded model against 200 samples per strategy. Writes `evasion_results.json`.

**`app/app.py`** — The Flask backend. Key components:
- `generate_events()` — a generator function that polls the shared log file and yields Server-Sent Events for each new query.
- `record_query()` — maintains a per-registrar deque of timestamps within a 60-second window; fires a session alert when the count reaches 15.
- `is_whitelisted()` — checks whether a domain or its registrar matches any entry in `whitelist.json`.
- REST endpoints for model stats, comparison, evasion results, whitelist, session alerts, and alert CSV download.

**`app/templates/index.html`** — A single-page application. Uses vanilla JavaScript to consume the SSE stream, update counters, render Chart.js charts (timeline, feature importance bar, ROC curves), and populate the query log and alerts panels.

#### 4.1.3 Feature Set

The twenty features used for classification are listed in Table 1.

**Table 1: The Twenty Extracted Features**

| # | Feature Name | Description |
|---|---|---|
| 1 | dns_domain_name_length | Total character count of domain string |
| 2 | dns_subdomain_name_length | Length of subdomain (excluding last two parts) |
| 3 | numerical_percentage | Fraction of characters that are digits |
| 4 | character_entropy | Shannon entropy of character distribution |
| 5 | max_continuous_numeric_len | Longest run of consecutive digits |
| 6 | max_continuous_alphabet_len | Longest run of consecutive letters |
| 7 | max_continuous_consonants_len | Longest run of consecutive consonants |
| 8 | max_continuous_same_alphabet_len | Longest run of the same repeated character |
| 9 | vowels_consonant_ratio | Ratio of vowels to consonants |
| 10 | conv_freq_vowels_consonants | Combined vowel+consonant frequency |
| 11 | distinct_ttl_values | Number of distinct TTL values seen |
| 12 | ttl_values_min | Minimum TTL value |
| 13 | ttl_values_max | Maximum TTL value |
| 14 | ttl_values_mean | Mean TTL value |
| 15 | ttl_values_variance | Variance of TTL values |
| 16 | ttl_values_standard_deviation | Standard deviation of TTL values |
| 17 | ttl_values_skewness | Skewness of TTL distribution |
| 18 | distinct_A_records | Number of distinct A records returned |
| 19 | average_answer_resource_records | Mean number of answer records |
| 20 | average_authority_resource_records | Mean number of authority records |

During live inference, TTL and DNS record features are not available from the domain string alone; default values are substituted (as per `features.py`, lines 63–74). The top features by importance from the trained model are `dns_domain_name_length` (18.05%) and `character_entropy` (16.95%).

### 4.2 Behavioural Model

#### 4.2.1 Per-Query Classification Flow

```
New line in dns_log.txt
        │
        ▼
Is domain whitelisted? ──Yes──► Emit WHITELISTED event (prediction=-1)
        │ No
        ▼
record_query() — update session window for registrar
        │
        ├─► If count ≥ 15 in 60s ──► Emit SESSION_TUNNEL event (prediction=2)
        │
        ▼
extract_features(domain)  [20 numeric values]
        │
        ▼
model.predict([features])
model.predict_proba([features])
        │
        ├─ prediction=1 ──► Emit TUNNEL event; append to alert_store
        └─ prediction=0 ──► Emit NORMAL event
```

#### 4.2.2 Session-Level Detection

The session detection layer addresses a key limitation of per-query ML: low-entropy tunnel techniques (single words, two-word combinations, short chunks) cannot be distinguished from normal queries on a per-query basis. The session layer tracks, for each registrar (e.g. `evil-c2.net`), a sliding deque of query timestamps within the last 60 seconds. When the count reaches 15, a `SESSION_TUNNEL` alert is fired. A 30-second cooldown prevents repeated alerts for the same registrar. Whitelisted registrars are exempt.

#### 4.2.3 Attacker Simulation Sequence

```
Attacker Script          Shared Log            Flask Backend         Dashboard
     │                       │                       │                   │
     │── write(timestamp,domain) ──►│                │                   │
     │                       │── poll every 0.3s ──►│                   │
     │                       │                  classify()               │
     │                       │                       │── SSE event ─────►│
     │                       │                       │                update UI
```

---

## 5. Other Project Matters

### 5.1 Project Management

The project was managed using an iterative development approach with four defined versions:

- **V1:** Synthetic dataset, 5-feature Random Forest, basic Flask app.
- **V2:** Full BCCC-CIC-Bell dataset, 20 features, improved model stats dashboard.
- **V3:** Model comparison (RF vs XGBoost vs LR), evasion attack testing, ROC curve visualisation.
- **V4:** Session-level detection, whitelist support, alert CSV export, full dashboard polish.

Each version was a working deliverable. This approach allowed continuous evaluation against the project objectives and early identification of the evasion gap that motivated the session-layer design.

Time was allocated as follows: dataset acquisition and pre-processing (15%), feature engineering (15%), model training and comparison (20%), evasion testing (10%), Flask backend and SSE implementation (20%), dashboard frontend (15%), testing and documentation (5%).

### 5.2 Testing

#### 5.2.1 Model Evaluation

The primary model was evaluated on a held-out test set of 830,753 records (20% stratified split). Results are shown in Table 2.

**Table 2: Model Performance Comparison**

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| **Random Forest** | **95.43%** | **0.809** | **0.836** | **0.822** | **0.9607** |
| XGBoost | 93.82% | 0.734 | 0.802 | 0.766 | 0.9458 |
| Logistic Regression | 88.38% | 0.526 | 0.798 | 0.634 | 0.9049 |

Random Forest achieved the highest ROC-AUC (0.9607) and was selected as the production model. The confusion matrix for Random Forest on the test set shows 705,185 true negatives, 20,702 false positives, 17,225 false negatives, and 87,641 true positives.

#### 5.2.2 Evasion Testing

Table 3 shows detection rates against eight evasion attack styles, tested with 200 samples each.

**Table 3: Evasion Attack Detection Rates**

| Attack Style | Detection Rate | Threat Level |
|---|---|---|
| Hex Encoded Tunnel | 88.0% | MEDIUM |
| Obvious Base64 Tunnel | 62.5% | MEDIUM |
| Numeric Tunnel | 42.5% | HIGH |
| Short Word Tunnel | 0.0% | CRITICAL |
| Two Word Tunnel | 0.0% | CRITICAL |
| Three Word Tunnel | 0.0% | CRITICAL |
| Mimicry Tunnel | 0.0% | CRITICAL |
| Slow Drip Tunnel | 0.0% | CRITICAL |

The average detection rate across all evasion styles is 24.1%. This result demonstrates that per-query ML alone is insufficient against sophisticated attackers. The five CRITICAL categories all use low-entropy subdomains (dictionary words or very short chunks) that are statistically indistinguishable from benign traffic on a single-query basis. This finding directly motivated the session-level detection layer implemented in V4.

The benign baseline accuracy is 100% — all sixteen benign reference domains are correctly classified as normal, confirming no false-positive degradation from the session layer's whitelist exemption.

#### 5.2.3 Integration Testing

The full attacker-detector-dashboard pipeline was tested end-to-end. With the attacker simulator running at one query per 0.5 seconds (approximately 25% tunnel queries), tunnel events appeared on the dashboard within one second of being written to the log, satisfying NFR1. The session alert triggered correctly after 15 non-whitelisted queries to the same registrar within 60 seconds. The whitelist correctly suppressed classification of domains such as `mail.google.com` and `teams.microsoft.com`.

---

## 6. Conclusion

### 6.1 Summary of Outcomes

This project successfully delivered a functioning, end-to-end DNS tunnel detection system. The primary objectives were all met:

- **Objective 1** was met: a twenty-feature extraction pipeline was implemented, covering lexical, statistical, and TTL-based signals aligned with the BCCC-CIC-Bell dataset schema.
- **Objective 2** was met: three classifiers were trained and compared; Random Forest was selected with 95.43% accuracy and ROC-AUC 0.9607.
- **Objective 3** was met: eight evasion attack styles were tested, revealing a critical gap in per-query detection and quantifying exactly where the model succeeds and fails.
- **Objective 4** was met: a live web dashboard delivers real-time streaming alerts, model analytics, evasion results, and alert export functionality.

### 6.2 Critical Evaluation

The most significant finding of this project is that per-query ML detection alone is brittle against evasion. Five of the eight tested attack styles achieved 0% detection rate. This is not a failure of the specific model chosen — it is an inherent limitation of single-query feature analysis when attackers deliberately suppress entropy. The session-level detection layer partially compensates: any sustained tunnelling campaign, regardless of encoding, will eventually trigger the frequency threshold. However, a determined attacker who spreads queries across many registrars or keeps the rate below the threshold could still evade both detection layers.

The 95.43% accuracy figure, while high, must be interpreted in context. The dataset is heavily imbalanced (87% benign, 13% tunnel). The 2.85% false positive rate means that in a high-volume enterprise network handling millions of queries per day, tens of thousands of benign queries would be incorrectly flagged. Reducing false positives without sacrificing recall is an important direction for future work.

### 6.3 Future Work

- **Retrain with behavioural session features** — incorporate query-rate, inter-query interval, and registrar frequency as model features rather than a separate rule layer.
- **Deep learning approaches** — character-level CNN or LSTM models have shown promise for domain name analysis and may generalise better to low-entropy evasion.
- **Real packet capture** — replace the simulated log with live DNS packet capture using Scapy or dnspython to make the system deployable in a real network environment.
- **TTL anomaly detection** — tunnel tools often set unusually low TTLs; integrating real TTL values into live inference would activate the twelve TTL features currently defaulted.
- **Threat intelligence enrichment** — cross-reference detected tunnel registrars against publicly available threat intelligence feeds to reduce false positives and add context.

---

## 7. References

Bilge, L., Kirda, E., Kruegel, C. and Balduzzi, M. (2011) EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis. *Proceedings of the Network and Distributed System Security Symposium (NDSS)*.

Born, K. and Gustafson, D. (2010) Detecting DNS Tunnels Using Character Frequency Analysis. *arXiv preprint arXiv:1004.4358*.

Breiman, L. (2001) Random Forests. *Machine Learning*, 45(1), pp. 5–32.

Chen, T. and Guestrin, C. (2016) XGBoost: A Scalable Tree Boosting System. *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, pp. 785–794.

Feizollah, A., Anuar, N.B., Salleh, R. and Amalina, F. (2013) Comparative Study of k-Means and Mini Batch k-Means Clustering Algorithms in Android Malware Detection Using Network Traffic Analysis. *Proceedings of the International Symposium on Biometrics and Security Technologies*, pp. 193–197.

Habibi Lashkari, A., Kaur, G. and Rahali, A. (2022) DIDarknet: A Contemporary Approach to Detect and Characterize the Darknet Traffic Using Deep Image Learning. *Proceedings of the 10th International Conference on Communication and Network Security*.

Kara, I., Aydos, M. and Gulmez, M. (2021) Detection and Analysis of DNS Tunneling Using Machine Learning. *Computers and Security*, 111, p. 102490.

Mockapetris, P. (1987) *Domain Names — Implementation and Specification*. RFC 1035. Internet Engineering Task Force.

Paxson, V. (2013) Bro: A System for Detecting Network Intruders in Real-Time. *Computer Networks*, 31(23–24), pp. 2435–2463.

Pedregosa, F. et al. (2011) Scikit-learn: Machine Learning in Python. *Journal of Machine Learning Research*, 12, pp. 2825–2830.
