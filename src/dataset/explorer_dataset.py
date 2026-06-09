import pandas as pd
df = pd.read_csv("data/cicids2017/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv")

print(f"Loaded {len(df)} rows")
print(df.columns.tolist())
print(df[' Label'].value_counts())