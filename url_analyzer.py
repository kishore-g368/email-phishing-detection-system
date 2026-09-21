
import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "confirm",
    "bank",
    "signin",
    "security"
]


def analyze_urls(text):

    urls = re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        text.lower()
    )

    results = []

    for url in urls:

        if url.startswith("www."):
            check_url = "http://" + url
        else:
            check_url = url

        parsed = urlparse(check_url)

        domain = parsed.netloc

        score = 0
        reasons = []

        # ==========================================
        # HTTPS CHECK
        # ==========================================

        if parsed.scheme == "http":

            score += 1

            reasons.append(
                "URL is not using HTTPS"
            )

        # ==========================================
        # IP ADDRESS CHECK
        # ==========================================

        ip_pattern = (
            r'^\d{1,3}(\.\d{1,3}){3}$'
        )

        if re.match(
            ip_pattern,
            domain
        ):

            score += 3

            reasons.append(
                "URL uses an IP address"
            )

        # ==========================================
        # @ SYMBOL
        # ==========================================

        if "@" in url:

            score += 2

            reasons.append(
                "URL contains @ symbol"
            )

        # ==========================================
        # URL LENGTH
        # ==========================================

        if len(url) > 75:

            score += 1

            reasons.append(
                "URL is unusually long"
            )

        # ==========================================
        # MANY SUBDOMAINS / DOTS
        # ==========================================

        dot_count = domain.count(".")

        if dot_count >= 3:

            score += 1

            reasons.append(
                "URL contains multiple subdomains"
            )

        # ==========================================
        # SUSPICIOUS KEYWORDS
        # ==========================================

        found_words = []

        for word in SUSPICIOUS_WORDS:

            if word in url:

                score += 1

                found_words.append(word)

        for word in found_words:

            reasons.append(
                "Suspicious word in URL: "
                + word
            )

        # ==========================================
        # DOMAIN LENGTH
        # ==========================================

        if len(domain) > 40:

            score += 1

            reasons.append(
                "Domain name is unusually long"
            )

        # ==========================================
        # FINAL URL RISK
        # ==========================================

        if score >= 5:

            risk = "HIGH"

        elif score >= 2:

            risk = "MEDIUM"

        else:

            risk = "LOW"

        # ==========================================
        # RESULT
        # ==========================================

        results.append({

            "url": url,

            "domain": domain,

            "score": score,

            "risk": risk,

            "reasons": reasons,

            "features": {

                "https": (
                    parsed.scheme == "https"
                ),

                "ip_address": bool(
                    re.match(
                        ip_pattern,
                        domain
                    )
                ),

                "url_length": len(url),

                "domain_length": len(domain),

                "dot_count": dot_count,

                "suspicious_keywords":
                    len(found_words)

            }

        })

    return results