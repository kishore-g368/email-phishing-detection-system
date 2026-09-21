import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
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
# CREATE ML MODELS
# ==================================================

models = {

    "Logistic Regression":
        LogisticRegression(),

    "Naive Bayes":
        MultinomialNB(),

    "Linear SVM":
        LinearSVC()

}


# ==================================================
# MODEL COMPARISON
# ==================================================

print()
print("==============================================")
print("       EMAIL PHISHING MODEL COMPARISON")
print("==============================================")

print()

for name, model in models.items():

    # Train model
    model.fit(
        X_train,
        y_train
    )

    # Prediction
    predictions = model.predict(
        X_test
    )

    # Metrics
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


    # Display
    print("----------------------------------------------")

    print(
        "Model     :",
        name
    )

    print(
        "Accuracy  :",
        round(accuracy * 100, 2),
        "%"
    )

    print(
        "Precision :",
        round(precision * 100, 2),
        "%"
    )

    print(
        "Recall    :",
        round(recall * 100, 2),
        "%"
    )

    print(
        "F1 Score  :",
        round(f1 * 100, 2),
        "%"
    )


print("----------------------------------------------")

print()
print("Model comparison completed successfully!")