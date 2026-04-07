
import os
import glob
import json
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    roc_curve
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
import joblib

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
EXF_DIR   = "data/BCCC-CIC-Bell-DNS-EXF"
MAL_DIR   = "data/BCCC-CIC-Bell-DNS-Mal"
MODEL_DIR = "model"

FEATURES = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "numerical_percentage",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
    "distinct_ttl_values",
    "ttl_values_min",
    "ttl_values_max",
    "ttl_values_mean",
    "ttl_values_variance",
    "ttl_values_standard_deviation",
    "ttl_values_skewness",
    "distinct_A_records",
    "average_answer_resource_records",
    "average_authority_resource_records",
]

# ─────────────────────────────────────────────
# STEP 1 — LOAD DATA (same as train.py)
# ─────────────────────────────────────────────
def load_folder(folder):
    dfs = []
    for f in glob.glob(os.path.join(folder, "*.csv")):
        try:
            df = pd.read_csv(f, low_memory=False)
            dfs.append(df)
        except Exception as e:
            print(f"  Skipped {os.path.basename(f)}: {e}")
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

print("=" * 60)
print("  V3 — Model Comparison")
print("  RF vs XGBoost vs Logistic Regression")
print("=" * 60)

print("\n[1/5] Loading data...")
df = pd.concat([load_folder(EXF_DIR), load_folder(MAL_DIR)], ignore_index=True)
print(f"  Total rows: {len(df)}")

df["binary_label"] = df["label"].apply(
    lambda x: 0 if str(x).strip().lower() == "benign" else 1
)

available = [f for f in FEATURES if f in df.columns]
X = df[available].copy()
y = df["binary_label"].copy()
X = X.apply(pd.to_numeric, errors='coerce')
X.fillna(X.median(), inplace=True)

print(f"  Features: {len(available)} | Samples: {len(X)}")
print(f"  Benign: {(y==0).sum()} | Tunnel: {(y==1).sum()}")

# ─────────────────────────────────────────────
# STEP 2 — TRAIN/TEST SPLIT
# ─────────────────────────────────────────────
print("\n[2/5] Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  Train: {len(X_train)} | Test: {len(X_test)}")

# Scale for Logistic Regression
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

# ─────────────────────────────────────────────
# STEP 3 — DEFINE MODELS
# ─────────────────────────────────────────────
models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    ),
    "XGBoost": XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=int((y==0).sum() / (y==1).sum()),
        use_label_encoder=False,
        eval_metric='logloss',
        n_jobs=-1,
        random_state=42,
        verbosity=0
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
}

# ─────────────────────────────────────────────
# STEP 4 — TRAIN AND EVALUATE ALL MODELS
# ─────────────────────────────────────────────
print("\n[3/5] Training and evaluating all models...")
results = {}
roc_data = {}
best_model_name = None
best_score = 0

for name, clf in models.items():
    print(f"\n  → Training {name}...")

    # LR uses scaled data
    if name == "Logistic Regression":
        clf.fit(X_train_scaled, y_train)
        y_pred = clf.predict(X_test_scaled)
        y_prob = clf.predict_proba(X_test_scaled)[:, 1]
    else:
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    roc  = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred)

    print(f"    Accuracy : {acc*100:.2f}%")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall   : {rec:.4f}")
    print(f"    F1 Score : {f1:.4f}")
    print(f"    ROC-AUC  : {roc:.4f}")

    results[name] = {
        "accuracy":  round(acc, 4),
        "precision": round(prec, 4),
        "recall":    round(rec, 4),
        "f1":        round(f1, 4),
        "roc_auc":   round(roc, 4),
        "confusion_matrix": cm.tolist()
    }

    # ROC curve data (sampled for dashboard)
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    step = max(1, len(fpr) // 100)
    roc_data[name] = {
        "fpr": [round(float(x), 4) for x in fpr[::step]],
        "tpr": [round(float(x), 4) for x in tpr[::step]],
        "auc": round(roc, 4)
    }

    # Save model
    model_file = name.lower().replace(" ", "_") + "_model.pkl"
    joblib.dump(clf, os.path.join(MODEL_DIR, model_file))
    print(f"    Saved to model/{model_file}")

    # Track best
    if roc > best_score:
        best_score = roc
        best_model_name = name


# STEP 5 — SAVE RESULTS

print(f"\n[4/5] Best model: {best_model_name} (ROC-AUC: {best_score:.4f})")

# Copy best model as active model
best_file = best_model_name.lower().replace(" ", "_") + "_model.pkl"
best_model = joblib.load(os.path.join(MODEL_DIR, best_file))
joblib.dump(best_model, os.path.join(MODEL_DIR, "dns_rf_model.pkl"))
print(f"  Active model updated to: {best_model_name}")

comparison = {
    "models": results,
    "roc_curves": roc_data,
    "best_model": best_model_name,
    "best_roc_auc": round(best_score, 4),
    "features_used": available
}

out_path = os.path.join(MODEL_DIR, "comparison_results.json")
with open(out_path, "w") as f:
    json.dump(comparison, f, indent=2)
print(f"  Results saved to model/comparison_results.json")

# ─────────────────────────────────────────────
# SUMMARY TABLE
# ─────────────────────────────────────────────
print("\n[5/5] Final comparison:")
print(f"\n  {'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'ROC-AUC':>10}")
print(f"  {'-'*75}")
for name, r in results.items():
    marker = " ← BEST" if name == best_model_name else ""
    print(f"  {name:<25} {r['accuracy']*100:>9.2f}% {r['precision']:>10.4f} {r['recall']:>10.4f} {r['f1']:>10.4f} {r['roc_auc']:>10.4f}{marker}")

print("\n" + "=" * 60)
print(f"  V3 Complete! Best model: {best_model_name}")
print("=" * 60)