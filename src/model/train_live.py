"""Train the two models used for live detection.

Only 4 features are available live (see live_bridge.py), so this is
deliberately scoped to what volume-based features can actually support:

  1. live_detector.joblib   - binary BENIGN vs ATTACK. This is the verdict.
  2. live_classifier.joblib - names the attack type, but only for the
     classes it is actually precise on. Measured here, not assumed.

Trees are depth-capped so the saved models stay a few MB and can live in
the repo. Unlimited depth cost 83 MB and bought ~1 point of accuracy.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_score
import joblib

# A class is only reported by name if it clears this precision on the
# test set. Below it, the model cries wolf often enough to be useless.
PRECISION_THRESHOLD = 0.80

live_features = ['Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Average Packet Size']

df = pd.read_csv("data/processed/clean_for_training.csv", usecols=live_features + ['Label'])
df = df.sample(n=500000, random_state=42)

X = df[live_features]
y_type = df['Label']
y_binary = y_type.where(y_type == 'BENIGN', 'ATTACK')

X_train, X_test, ybin_train, ybin_test, ytype_train, ytype_test = train_test_split(
    X, y_binary, y_type, test_size=0.2, random_state=42)


def build():
    return RandomForestClassifier(
        n_estimators=50,
        max_depth=16,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
    )


# --- 1. binary detector: this produces the verdict -------------------------
print("Training binary detector...")
detector = build()
detector.fit(X_train, ybin_train)
joblib.dump(detector, "models/live_detector.joblib", compress=3)
print("Saved models/live_detector.joblib\n")
print(classification_report(ybin_test, detector.predict(X_test), digits=4, zero_division=0))


# --- 2. type classifier: names the attack, where it can be trusted ---------
print("Training attack type classifier...")
classifier = build()
classifier.fit(X_train, ytype_train)

precisions = precision_score(
    ytype_test, classifier.predict(X_test),
    labels=classifier.classes_, average=None, zero_division=0,
)
reliable_types = [
    label for label, p in zip(classifier.classes_, precisions)
    if label != 'BENIGN' and p >= PRECISION_THRESHOLD
]

# Ship the reliable list with the model so serving cannot drift from
# what was actually measured at training time.
joblib.dump(
    {"model": classifier, "reliable_types": reliable_types},
    "models/live_classifier.joblib",
    compress=3,
)
print("Saved models/live_classifier.joblib\n")
print(classification_report(ytype_test, classifier.predict(X_test), digits=4, zero_division=0))

print(f"Attack types reported by name (precision >= {PRECISION_THRESHOLD}):")
for label, p in zip(classifier.classes_, precisions):
    if label in reliable_types:
        print(f"  {label:<28} precision={p:.4f}")
print("\nSuppressed (shown only as generic ATTACK):")
for label, p in zip(classifier.classes_, precisions):
    if label != 'BENIGN' and label not in reliable_types:
        print(f"  {label:<28} precision={p:.4f}")
