import pandas as pd 
import glob 

files = glob.glob("data/cicids2017/MachineLearningCVE/*.csv")

print(f"Found {len(files)} files:")
for f in files:
    print(f)

print("Loading all files... this takes a minute")

dataframes = []
for f in files:
    df = pd.read_csv(f)
    print(f"Loaded {f.split('/')[-1]}: {len(df)} rows")
    dataframes.append(df)

combined = pd.concat(dataframes, ignore_index=True)

print(f"\nCombined total: {len(combined)} rows")

combined.columns = combined.columns.str.strip()

print("\nColumn names cleaned")
print(f"Label column is now: '{[c for c in combined.columns if 'Label' in c][0]}'")
print("\n=== FULL WEEK ATTACK BREAKDOWN ===")
print(combined['Label'].value_counts())
combined.to_csv("data/processed/combined_cleaned.csv", index=False)
print("\nSaved combined dataset to data/processed/combined_cleaned.csv")