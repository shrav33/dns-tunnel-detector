import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from features import extract_features, FEATURE_NAMES

print("Loading dataset...")
df = pd.read_csv("data/dns_dataset.csv")

print(f"Loaded {len(df)} rows — "
      f"{(df['label']==0).sum()} normal, "
      f"{(df['label']==1).sum()} tunnel")

print("\nExtracting features...")

X = df["domain"].apply(lambda d: extract_features(d))
X = pd.DataFrame(X.tolist(), columns=FEATURE_NAMES)

y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Train set: {len(X_train)} rows")
print(f"Test  set: {len(X_test)} rows")

print("\nTraining Random Forest (100 trees)...")

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("Training complete.")

print("\n--- RESULTS ---")

y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"Accuracy : {acc*100:.1f}%")

print("\nDetailed report:")
print(classification_report(y_test, y_pred,
      target_names=["Normal","Tunnel"]))

print("Confusion matrix:")
cm = confusion_matrix(y_test, y_pred)

print(f"  True  Negatives (normal, correct) : {cm[0][0]}")
print(f"  False Positives (false alarms)    : {cm[0][1]}")
print(f"  False Negatives (missed tunnels)  : {cm[1][0]}")
print(f"  True  Positives (tunnels caught)  : {cm[1][1]}")

print("\nFeature importance (which features matter most):")

for name, imp in sorted(zip(FEATURE_NAMES, model.feature_importances_),
                        key=lambda x: x[1], reverse=True):
    bar = "█" * int(imp * 40)
    print(f"  {name:<20} {imp:.3f}  {bar}")

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/rf_model.pkl")

print("\nModel saved to model/rf_model.pkl")
print("Step 3 complete.")