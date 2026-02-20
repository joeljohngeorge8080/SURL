# app/intelligence/keyword_intelligence.py

PHISHING_KEYWORDS = [
    "verify account",
    "confirm identity",
    "update billing",
    "login immediately",
    "session expired",
    "account locked",
    "security alert",
    "suspend",
]

PAYMENT_KEYWORDS = [
    "pay now",
    "credit card",
    "debit card",
    "cvv",
    "billing address",
    "card number",
    "expiry date",
    "payment required",
]

ADULT_KEYWORDS = [
    "xxx",
    "porn",
    "explicit",
    "adult content",
]


def analyze_keywords(page_text: str) -> dict:
    """
    Scans rendered page text for suspicious keyword patterns.
    """

    lower_text = page_text.lower()

    phishing_hits = [kw for kw in PHISHING_KEYWORDS if kw in lower_text]
    payment_hits = [kw for kw in PAYMENT_KEYWORDS if kw in lower_text]
    adult_hits = [kw for kw in ADULT_KEYWORDS if kw in lower_text]

    return {
        "phishing_keywords": phishing_hits,
        "payment_keywords": payment_hits,
        "adult_keywords": adult_hits,
    }
