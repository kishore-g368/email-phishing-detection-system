import re

SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "verification",
    "password",
    "account suspended",
    "account blocked",
    "click here",
    "login",
    "confirm",
    "bank",
    "winner",
    "prize",
    "claim",
    "security alert",
    "limited time"
]


def detect_phishing(email_text):
    text = email_text.lower()

    score = 0
    reasons = []

    # Check suspicious words
    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 1
            reasons.append("Suspicious word/phrase: " + word)

    # Check URLs
    urls = re.findall(r'https?://\S+|www\.\S+', text)

    if urls:
        score += 2
        reasons.append("Email contains a link")

    # Check IP address in URL
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'

    if re.search(ip_pattern, text):
        score += 3
        reasons.append("URL contains an IP address")

    # Determine risk
    if score >= 5:
        result = "PHISHING"
        risk = "HIGH"

    elif score >= 2:
        result = "SUSPICIOUS"
        risk = "MEDIUM"

    else:
        result = "LEGITIMATE"
        risk = "LOW"

    return result, risk, score, reasons