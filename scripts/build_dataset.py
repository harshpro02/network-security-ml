"""Turn the raw CICIDS2017 downloads into the training file.

Replaces two scripts that had to be run in the right order by hand.

    python scripts/build_dataset.py

Expects the raw CSVs in data/cicids2017/MachineLearningCVE/ and writes
data/processed/clean_for_training.csv, which is what train_live.py and the
day-held-out evaluation read.
"""
import glob
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW = REPO_ROOT / "data" / "cicids2017" / "MachineLearningCVE"
OUT = REPO_ROOT / "data" / "processed" / "clean_for_training.csv"


def load_raw():
    paths = sorted(glob.glob(str(RAW / "*.csv")))
    if not paths:
        sys.exit(f"No CSVs in {RAW}. Download CICIDS2017 there first.")

    frames = []
    for path in paths:
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        print(f"  {Path(path).name:<48} {len(df):>9,} rows")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def clean(df):
    """Three problems ship with this dataset and all three break training."""
    # The web attack labels contain a byte that is not valid UTF-8.
    df["Label"] = df["Label"].str.replace("\ufffd", "-", regex=False)

    # Rate columns divide by a duration that is sometimes zero.
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    before = len(df)
    df.dropna(inplace=True)
    print(f"  dropped {before - len(df):,} rows with missing or infinite values")
    return df


def main():
    print("Loading raw CSVs")
    df = load_raw()
    print(f"\nCombined: {len(df):,} rows")

    print("\nCleaning")
    df = clean(df)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)
    print(f"\nWrote {len(df):,} rows to {OUT.relative_to(REPO_ROOT)}")
    print("\nLabel breakdown")
    print(df["Label"].value_counts().to_string())


if __name__ == "__main__":
    main()
