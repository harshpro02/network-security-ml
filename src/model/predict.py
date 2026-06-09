import joblib
import pandas as pd

model = joblib.load("models/attack_detector.joblib")
print("Model loaded")

df = pd.read_csv("data/processed/clean_for_training.csv")

attacks = df[df['Label'] != 'BENIGN']
sample = attacks.sample(n=10, random_state=1)

X_sample = sample.drop('Label', axis=1)
actual = sample['Label']

predictions = model.predict(X_sample)

for guess, real in zip(predictions, actual):
    print(f"Predicted: {guess}  |  Actual: {real}")