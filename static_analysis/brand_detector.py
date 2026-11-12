from urllib.parse import urlparse

import Levenshtein

from static_analysis.net_guard import registered_domain, split_host


# List of commonly impersonated brands
KNOWN_BRANDS = [
    "google",
    "paypal",
    "microsoft",
    "amazon",
    "apple",
    "facebook",
    "instagram",
    "bank",
    "netflix"
]


# Registered domains that belong to a listed brand but would otherwise score
# as look-alikes (e.g. "amazonaws" is 0.8 similar to "amazon").
BRAND_OWNED_DOMAINS = {
    "amazonaws.com",
    "microsoftonline.com",
    "googleusercontent.com",
    "paypalobjects.com",
}


def _best_brand(token):
    best_brand, best_score = None, 0.0
    for brand in KNOWN_BRANDS:
        score = Levenshtein.ratio(token, brand)
        if score > best_score:
            best_brand, best_score = brand, score
    return best_brand, best_score


def extract_domain_name(url):
    """Registered-domain label of the URL host: 'https://u@login.paypa1.co.uk:8443/'
    -> 'paypa1'. Ignores userinfo, port and subdomains."""
    host = urlparse(url).hostname or ""
    return split_host(host)[1] or host


def brand_check(url, similarity_threshold=0.8):
    """
    Detects possible brand impersonation using string similarity.

    Looks at the registered domain (paypa1.com) and, separately, at subdomain
    labels of a non-brand domain (paypal.evil.com, secure-paypal.verify.co.uk).
    """

    signals = {
        "brand_detected": None,
        "similarity_score": 0.0,
        "possible_impersonation": False
    }

    host = (urlparse(url).hostname or "").lower()
    subdomain, domain_name, _ = split_host(host)
    if not domain_name:
        return signals

    brand, score = _best_brand(domain_name)
    signals["brand_detected"], signals["similarity_score"] = brand, score

    # The brand's own registered domain (paypal.com, www.paypal.com) is legitimate.
    if domain_name in KNOWN_BRANDS or registered_domain(host) in BRAND_OWNED_DOMAINS:
        return signals

    if score >= similarity_threshold:
        signals["possible_impersonation"] = True
        return signals

    # Brand name used as a subdomain of someone else's domain.
    for label in filter(None, subdomain.split(".")):
        for token in [label, *label.split("-")]:
            brand, score = _best_brand(token)
            if score >= similarity_threshold:
                signals["brand_detected"], signals["similarity_score"] = brand, score
                signals["possible_impersonation"] = True
                return signals

    return signals


# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL for brand detection: ")
    print(brand_check(test_url))
