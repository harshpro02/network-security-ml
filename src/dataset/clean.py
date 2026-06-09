import pandas as pd
import numpy as np

print("Loading combined dataset...")
df = pd.read_csv("data/processed/combined_cleaned.csv")
print(f"Loaded {len(df)} rows")

# Count infinity values
inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
print(f"Infinity values: {inf_count}")

# Count missing values
nan_count = df.isnull().sum().sum()
print(f"Missing values: {nan_count}")

# Step 1: Fix the broken character in Web Attack labels
df['Label'] = df['Label'].str.replace('�', '-', regex=False)
print("Fixed broken label characters")

# Step 2: Replace infinity with NaN (so we can handle all bad values together)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
print("Converted infinity to NaN")

# Step 3: Drop rows with any missing values
before = len(df)
df.dropna(inplace=True)
after = len(df)
print(f"Dropped {before - after} bad rows")
print(f"Remaining: {after} rows")
df.to_csv("data/processed/clean_for_training.csv", index=False)
print("\nSaved clean dataset to data/processed/clean_for_training.csv")
print("Ready for model training")