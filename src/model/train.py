"""Train the 78 feature reference model.

Kept for comparison, not deployed. Most of its features come from
CICFlowMeter and cannot be computed from raw packets in real time, and the
result is 52 MB. src/model/train_live.py trains what actually ships.

    python src/model/train.py
"""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[2]
TRAINING_CSV = REPO_ROOT / "data" / "processed" / "clean_for_training.csv"
OUT = REPO_ROOT / "models" / "attack_detector.joblib"

SAMPLE_ROWS = 500_000
SEED = 42


def main():
    if not TRAINING_CSV.exists():
        raise SystemExit(f"Missing {TRAINING_CSV}. Build it with scripts/build_dataset.py.")

    df = pd.read_csv(TRAINING_CSV).sample(n=SAMPLE_ROWS, random_state=SEED)
    X_train, X_test, y_train, y_test = train_test_split(
        df.drop("Label", axis=1), df["Label"], test_size=0.2, random_state=SEED)
    print(f"Training on {len(X_train):,} rows, testing on {len(X_test):,}")

    model = RandomForestClassifier(
        n_estimators=100, random_state=SEED, n_jobs=-1, class_weight="balanced")
    model.fit(X_train, y_train)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUT)
    print(f"Saved {OUT.relative_to(REPO_ROOT)}")

    predictions = model.predict(X_test)
    print(f"\nAccuracy {accuracy_score(y_test, predictions):.4f}\n")
    print(classification_report(y_test, predictions, digits=4, zero_division=0))


if __name__ == "__main__":
    main()
