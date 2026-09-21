import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


# ==================================================
# LOAD DATASET
# ==================================================

data = pd.read_csv("dataset.csv")

X = data["text"]
y = data["label"]


# ==================================================
# TEXT VECTORIZATION
# ==================================================

vectorizer = TfidfVectorizer()

X_vectorized = vectorizer.fit_transform(X)


# ==================================================
# TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.25,
    random_state=42
)


# ==================================================
# LOAD TRAINED MODEL
# ==================================================

model = joblib.load("phishing_model.pkl")


# ==================================================
# PREDICTION
# ==================================================

predictions = model.predict(X_test)


# ==================================================
# MODEL METRICS
# ==================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    pos_label="phishing",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    pos_label="phishing",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label="phishing",
    zero_division=0
)


# ==================================================
# CONFUSION MATRIX
# ==================================================

cm = confusion_matrix(
    y_test,
    predictions,
    labels=["legitimate", "phishing"]
)

true_negative = cm[0][0]
false_positive = cm[0][1]
false_negative = cm[1][0]
true_positive = cm[1][1]


# ==================================================
# DISPLAY RESULTS
# ==================================================

print()
print("======================================")
print("       MODEL EVALUATION")
print("======================================")

print(
    "Accuracy :",
    round(accuracy * 100, 2),
    "%"
)

print(
    "Precision:",
    round(precision * 100, 2),
    "%"
)

print(
    "Recall   :",
    round(recall * 100, 2),
    "%"
)

print(
    "F1 Score :",
    round(f1 * 100, 2),
    "%"
)


# ==================================================
# DISPLAY CONFUSION MATRIX
# ==================================================

print()
print("======================================")
print("       CONFUSION MATRIX")
print("======================================")

print(cm)

print()
print("True Negative :", true_negative)
print("False Positive:", false_positive)
print("False Negative:", false_negative)
print("True Positive :", true_positive)

print()
print("======================================")
print("       EVALUATION COMPLETED")
print("======================================")