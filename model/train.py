
import os
import glob
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, roc_auc_score
)
from sklearn.preprocessing import LabelEncoder
import joblib
import json
import warnings
warnings.filterwarnings('ignore')

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
EXF_DIR   = "data/BCCC-CIC-Bell-DNS-EXF"   # tunneling files
MAL_DIR   = "data/BCCC-CIC-Bell-DNS-Mal"   # benign + other files
MODEL_DIR = "model"
os.makedirs(MODEL_DIR, exist_ok=True)

# Features we will use — DNS-level features that work for live capture too
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
# STEP 1 — LOAD ALL FILES
# ─────────────────────────────────────────────
def load_folder(folder, label_override=None):
    """Load all CSVs in a folder and optionally override the label column."""
    dfs = []
    files = glob.glob(os.path.join(folder, "*.csv"))
    print(f"  Found {len(files)} files in {folder}")
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            if label_override:
                df["label"] = label_override
            dfs.append(df)
            print(f"    Loaded {os.path.basename(f)}: {df.shape[0]} rows")
        except Exception as e:
            print(f"    Skipped {os.path.basename(f)}: {e}")
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

print("=" * 55)
print("  DNS Tunnel Detector — V2 Training Script")
print("=" * 55)

print("\n[1/6] Loading EXF (tunneling) data...")
df_exf = load_folder(EXF_DIR)
print(f"  Total EXF rows: {len(df_exf)}")

print("\n[2/6] Loading MAL folder (benign + malware + phishing + spam)...")
df_mal = load_folder(MAL_DIR)
print(f"  Total MAL rows: {len(df_mal)}")

# ─────────────────────────────────────────────
# STEP 2 — COMBINE AND LABEL
# ─────────────────────────────────────────────
print("\n[3/6] Combining and labelling...")

df = pd.concat([df_exf, df_mal], ignore_index=True)
print(f"  Combined shape: {df.shape}")
print(f"  Label value counts:\n{df['label'].value_counts()}")

# Binary label: Benign = 0, everything else (tunnel/exfil) = 1
df["binary_label"] = df["label"].apply(
    lambda x: 0 if str(x).strip().lower() == "benign" else 1
)
print(f"\n  Binary label distribution:")
print(f"    Benign (0): {(df['binary_label'] == 0).sum()}")
print(f"    Tunnel (1): {(df['binary_label'] == 1).sum()}")

# ─────────────────────────────────────────────
# STEP 3 — FEATURE SELECTION & CLEANING
# ─────────────────────────────────────────────
print("\n[4/6] Preparing features...")

# Keep only numeric feature columns that exist
available = [f for f in FEATURES if f in df.columns]
missing   = [f for f in FEATURES if f not in df.columns]
if missing:
    print(f"  Warning — features not found (will skip): {missing}")

X = df[available].copy()
y = df["binary_label"].copy()

# Convert any non-numeric to NaN and fill
X = X.apply(pd.to_numeric, errors='coerce')
X.fillna(X.median(), inplace=True)

print(f"  Features used: {len(available)}")
print(f"  Total samples: {len(X)}")

# Save feature list for live inference
with open(os.path.join(MODEL_DIR, "feature_list.json"), "w") as fp:
    json.dump(available, fp)
print(f"  Feature list saved to model/feature_list.json")

# ─────────────────────────────────────────────
# STEP 4 — TRAIN / TEST SPLIT
# ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n  Train size: {len(X_train)} | Test size: {len(X_test)}")

# ─────────────────────────────────────────────
# STEP 5 — TRAIN RANDOM FOREST
# ─────────────────────────────────────────────
print("\n[5/6] Training Random Forest...")
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced"   # handles class imbalance automatically
)
clf.fit(X_train, y_train)
print("  Training complete!")

# ─────────────────────────────────────────────
# STEP 6 — EVALUATE
# ─────────────────────────────────────────────
print("\n[6/6] Evaluating model...")
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

acc     = accuracy_score(y_test, y_pred)
roc     = roc_auc_score(y_test, y_prob)
cm      = confusion_matrix(y_test, y_pred)
report  = classification_report(y_test, y_pred, target_names=["Benign", "Tunnel"])

print(f"\n  Accuracy : {acc:.4f} ({acc*100:.2f}%)")
print(f"  ROC-AUC  : {roc:.4f}")
print(f"\n  Confusion Matrix:")
print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
print(f"\n  Classification Report:")
print(report)

# Feature importance
importances = pd.Series(clf.feature_importances_, index=available)
importances = importances.sort_values(ascending=False)
print("  Top 10 most important features:")
print(importances.head(10).to_string())

# ─────────────────────────────────────────────
# SAVE MODEL + STATS
# ─────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "dns_rf_model.pkl")
joblib.dump(clf, model_path)
print(f"\n  Model saved to {model_path}")

# Save stats for dashboard
stats = {
    "accuracy": round(acc, 4),
    "roc_auc": round(roc, 4),
    "confusion_matrix": cm.tolist(),
    "feature_importances": importances.to_dict(),
    "classification_report": report,
    "total_samples": len(X),
    "tunnel_samples": int((y == 1).sum()),
    "benign_samples": int((y == 0).sum()),
    "features_used": available
}
stats_path = os.path.join(MODEL_DIR, "model_stats.json")
with open(stats_path, "w") as fp:
    json.dump(stats, fp, indent=2)
print(f"  Stats saved to {stats_path}")

print("\n" + "=" * 55)
print("  V2 Training Complete!")
print(f"  Accuracy: {acc*100:.2f}%  |  ROC-AUC: {roc:.4f}")
print("=" * 55)