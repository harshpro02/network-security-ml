import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


df = pd.read_csv("data/processed/clean_for_training.csv")
df = df.sample(n=500000, random_state=42)
print(f"Sampled down to {len(df)} rows")
print(f"Loaded {len(df)} rows")
y = df['Label']
X = df.drop('Label', axis = 1)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"Training on {len(X_train)} rows, testing on {len(X_test)} rows")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
model.fit(X_train, y_train)
print("Training complete")
joblib.dump(model, "models/attack_detector.joblib")
print("Model saved")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Accuracy: {accuracy:.4f}")
print(classification_report(y_test, predictions))