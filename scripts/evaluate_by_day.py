"""Leave-one-day-out evaluation.

The random split shares near-identical burst records between train and test.
Each attack type in CICIDS2017 appears on exactly one day, so holding a day
out asks a harder and more honest question: can the binary detector call an
attack family it has never seen ATTACK?

Run for both feature sets to see whether the extra features generalise or
just memorise the lab setup (destination port is the suspect).
"""
import glob
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score

CURRENT = ['Flow Duration', 'Total Fwd Packets',
           'Total Length of Fwd Packets', 'Average Packet Size']

COMPUTABLE = CURRENT + [
    'Destination Port',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Flow Bytes/s', 'Flow Packets/s',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'Init_Win_bytes_forward', 'act_data_pkt_fwd', 'min_seg_size_forward',
]

cols = sorted(set(COMPUTABLE)) + ['Label']

frames = []
for path in sorted(glob.glob("data/cicids2017/MachineLearningCVE/*.csv")):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    df = df[cols].copy()
    df['Label'] = df['Label'].str.replace('�', '-', regex=False)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df['Day'] = os.path.basename(path).split('.')[0]
    frames.append(df)
    print(f"{df['Day'].iloc[0]:<48} {len(df):>8} rows  "
          f"{df['Label'].ne('BENIGN').sum():>7} attacks", flush=True)

data = pd.concat(frames, ignore_index=True)
data['Binary'] = data['Label'].where(data['Label'] == 'BENIGN', 'ATTACK')
del frames

folds = [d for d in data['Day'].unique() if data.loc[data.Day == d, 'Label'].ne('BENIGN').any()]


def build():
    return RandomForestClassifier(n_estimators=50, max_depth=16, random_state=42,
                                  n_jobs=-1, class_weight='balanced')


for label, feats in (("4 features (deployed)", CURRENT),
                     ("28 features", COMPUTABLE)):
    print(f"\n=== LEAVE-ONE-DAY-OUT: {label} ===", flush=True)
    print(f"{'held-out day':<48} {'attack recall':>14} {'benign recall':>14} {'accuracy':>10}")
    recalls = []
    for day in folds:
        train = data[data.Day != day]
        test = data[data.Day == day]
        if train.sample(n=min(400000, len(train)), random_state=42) is not None:
            train = train.sample(n=min(400000, len(train)), random_state=42)

        m = build().fit(train[feats], train['Binary'])
        pred = m.predict(test[feats])

        ar = recall_score(test['Binary'], pred, pos_label='ATTACK', zero_division=0)
        br = recall_score(test['Binary'], pred, pos_label='BENIGN', zero_division=0)
        acc = accuracy_score(test['Binary'], pred)
        recalls.append(ar)
        short = day.replace('-WorkingHours', '').replace('.pcap_ISCX', '')
        print(f"{short:<48} {ar:>13.3f} {br:>14.3f} {acc:>10.3f}", flush=True)
    print(f"{'mean attack recall':<48} {np.mean(recalls):>13.3f}")
