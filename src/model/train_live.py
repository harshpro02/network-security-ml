import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv("data/processed/clean_for_training.csv")
df = df.sample(n=500000, random_state=42)

live_features = ['Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Average Packet Size']

X = df[live_features]
y = df['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
model.fit(X_train, y_train)


joblib.dump(model, "models/live_detector.joblib")
print("Live model saved")

predictions = model.predict(X_test)
print(classification_report(y_test, predictions))