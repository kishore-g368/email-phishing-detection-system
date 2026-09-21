from flask import Flask, render_template, request
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

from url_analyzer import analyze_urls

from database import (
    create_database,
    save_scan,
    get_scan_history,
    get_scan_statistics
)


app = Flask(__name__)


# ==================================================
# DATABASE
# ==================================================

create_database()


# ==================================================
# LOAD ML MODEL
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


evaluation_model = joblib.load("phishing_model.pkl")


predictions = evaluation_model.predict(X_test)


accuracy = round(
    accuracy_score(y_test, predictions) * 100,
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
# CONFUSION MATRIX

from sklearn.metrics import confusion_matrix

cm = confusion_matrix(
    y_test,
    predictions,
    labels=["legitimate", "phishing"]
)

true_negative = int(cm[0][0])
false_positive = int(cm[0][1])
false_negative = int(cm[1][0])
true_positive = int(cm[1][1])


# ==================================================
# HOME PAGE
# ==================================================

@app.route("/", methods=["GET", "POST"])
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
            # ML ANALYSIS
            # ------------------------------------------

            email_vector = vectorizer.transform(
                [email_text]
            )

            result = model.predict(
                email_vector
            )[0]


            probability = model.predict_proba(
                email_vector
            )[0].max()


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
            # COMBINED RISK ENGINE
            # ------------------------------------------

            if result == "phishing" or url_high:

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
            # SAVE SCAN HISTORY
            # ------------------------------------------

            if url_results:

                url_risk = url_results[0]["risk"]

            else:

                url_risk = "NONE"


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


        # ML result
        result=result,
        risk=risk,
        score=score,


        # Email
        email_text=email_text,


        # URL analysis
        url_results=url_results,


        # Final security result
        final_result=final_result,
        final_risk=final_risk,
        final_score=final_score,


        # Dashboard statistics
        total=total,
        phishing=phishing,
        suspicious=suspicious,
        legitimate=legitimate,


        # Scan history
        history=history,


        # Model performance
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive

    )


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )