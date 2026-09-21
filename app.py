from flask import Flask, render_template, request, redirect, url_for, session
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from url_analyzer import analyze_urls

from database import (
    create_database,
    save_scan,
    get_scan_history,
    get_scan_statistics,
    check_login
)


# ==================================================
# FLASK APPLICATION
# ==================================================

app = Flask(__name__)

app.secret_key = "phishing-detection-demo-secret-key"


# ==================================================
# CREATE DATABASE
# ==================================================

create_database()


# ==================================================
# LOAD TRAINED MODEL
# ==================================================

model = joblib.load("phishing_model.pkl")

vectorizer = joblib.load("vectorizer.pkl")


# ==================================================
# MODEL PERFORMANCE EVALUATION
# ==================================================

data = pd.read_csv("dataset.csv")

X = data["text"]

y = data["label"]


evaluation_vectorizer = TfidfVectorizer()

X_vectorized = evaluation_vectorizer.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.25,
    random_state=42
)


evaluation_model = joblib.load(
    "phishing_model.pkl"
)


predictions = evaluation_model.predict(
    X_test
)


# ==================================================
# METRICS
# ==================================================

accuracy = round(
    accuracy_score(
        y_test,
        predictions
    ) * 100,
    2
)


precision = round(
    precision_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0
    ) * 100,
    2
)


recall = round(
    recall_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0
    ) * 100,
    2
)


f1 = round(
    f1_score(
        y_test,
        predictions,
        pos_label="phishing",
        zero_division=0
    ) * 100,
    2
)


# ==================================================
# CONFUSION MATRIX
# ==================================================

cm = confusion_matrix(
    y_test,
    predictions,
    labels=[
        "legitimate",
        "phishing"
    ]
)


true_negative = int(
    cm[0][0]
)


false_positive = int(
    cm[0][1]
)


false_negative = int(
    cm[1][0]
)


true_positive = int(
    cm[1][1]
)


# ==================================================
# MULTIPLE MODEL COMPARISON
# ==================================================

comparison_models = {

    "Logistic Regression":
        LogisticRegression(),

    "Naive Bayes":
        MultinomialNB(),

    "Linear SVM":
        LinearSVC()
}


model_comparison = []


for name, comparison_model in comparison_models.items():


    comparison_model.fit(
        X_train,
        y_train
    )


    comparison_predictions = (
        comparison_model.predict(X_test)
    )


    comparison_accuracy = round(

        accuracy_score(
            y_test,
            comparison_predictions
        ) * 100,

        2
    )


    comparison_precision = round(

        precision_score(
            y_test,
            comparison_predictions,
            pos_label="phishing",
            zero_division=0
        ) * 100,

        2
    )


    comparison_recall = round(

        recall_score(
            y_test,
            comparison_predictions,
            pos_label="phishing",
            zero_division=0
        ) * 100,

        2
    )


    comparison_f1 = round(

        f1_score(
            y_test,
            comparison_predictions,
            pos_label="phishing",
            zero_division=0
        ) * 100,

        2
    )


    model_comparison.append({

        "name": name,

        "accuracy":
            comparison_accuracy,

        "precision":
            comparison_precision,

        "recall":
            comparison_recall,

        "f1":
            comparison_f1

    })


# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():


    email = request.form.get(
        "email"
    )


    password = request.form.get(
        "password"
    )


    user = check_login(
        email,
        password
    )


    if user:


        session["user_id"] = user[0]

        session["user_email"] = user[1]


        return redirect(
            url_for("home")
        )


    return render_template(

        "index.html",

        login_error=
        "Invalid email or password"

    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():


    session.clear()


    return redirect(
        url_for("home")
    )


# ==================================================
# HOME PAGE
# ==================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def home():


    result = None

    risk = None

    score = None

    email_text = ""

    url_results = []

    final_result = None

    final_risk = None

    final_score = None


    # ==================================================
    # EMAIL SCAN
    # ==================================================

    if request.method == "POST":


        email_text = request.form.get(
            "email",
            ""
        )


        if email_text.strip():


            # ------------------------------------------
            # MACHINE LEARNING ANALYSIS
            # ------------------------------------------

            email_vector = vectorizer.transform(
                [email_text]
            )


            result = model.predict(
                email_vector
            )[0]


            probability = (
                model.predict_proba(
                    email_vector
                )[0].max()
            )


            score = round(
                probability * 100,
                2
            )


            if result == "phishing":

                risk = "HIGH"

            else:

                risk = "LOW"


            # ------------------------------------------
            # URL ANALYSIS
            # ------------------------------------------

            url_results = analyze_urls(
                email_text
            )


            url_high = False

            url_medium = False


            for item in url_results:


                if item["risk"] == "HIGH":

                    url_high = True


                elif item["risk"] == "MEDIUM":

                    url_medium = True


            # ------------------------------------------
            # FINAL RISK ENGINE
            # ------------------------------------------

            if (
                result == "phishing"
                or url_high
            ):

                final_result = "PHISHING"

                final_risk = "HIGH"


            elif url_medium:

                final_result = "SUSPICIOUS"

                final_risk = "MEDIUM"


            else:

                final_result = "LEGITIMATE"

                final_risk = "LOW"


            # ------------------------------------------
            # FINAL SECURITY SCORE
            # ------------------------------------------

            if final_risk == "HIGH":

                final_score = max(
                    score,
                    85
                )


            elif final_risk == "MEDIUM":

                final_score = max(
                    score,
                    60
                )


            else:

                final_score = score


            # ------------------------------------------
            # URL RISK
            # ------------------------------------------

            if url_results:

                url_risk = (
                    url_results[0]["risk"]
                )

            else:

                url_risk = "NONE"


            # ------------------------------------------
            # SAVE SCAN
            # ------------------------------------------

            save_scan(

                email_text,

                result,

                score,

                url_risk,

                final_result,

                final_risk,

                final_score

            )


    # ==================================================
    # DASHBOARD STATISTICS
    # ==================================================

    total, phishing, suspicious, legitimate = (
        get_scan_statistics()
    )


    # ==================================================
    # SCAN HISTORY
    # ==================================================

    history = get_scan_history()


    # ==================================================
    # SEND DATA TO HTML
    # ==================================================

    return render_template(

        "index.html",

        result=result,

        risk=risk,

        score=score,

        email_text=email_text,

        url_results=url_results,

        final_result=final_result,

        final_risk=final_risk,

        final_score=final_score,

        total=total,

        phishing=phishing,

        suspicious=suspicious,

        legitimate=legitimate,

        history=history,

        accuracy=accuracy,

        precision=precision,

        recall=recall,

        f1=f1,

        true_negative=true_negative,

        false_positive=false_positive,

        false_negative=false_negative,

        true_positive=true_positive,

        model_comparison=model_comparison

    )


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )