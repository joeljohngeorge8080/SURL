from urllib.parse import urlparse
import Levenshtein


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


def extract_domain_name(url):
    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(".")[0]


def brand_check(url, similarity_threshold=0.8):
    """
    Detects possible brand impersonation using string similarity.
    """

    signals = {
        "brand_detected": None,
        "similarity_score": 0.0,
        "possible_impersonation": False
    }

    domain_name = extract_domain_name(url)

    for brand in KNOWN_BRANDS:
        similarity = Levenshtein.ratio(domain_name, brand)

        if similarity > signals["similarity_score"]:
            signals["similarity_score"] = similarity
            signals["brand_detected"] = brand

    # Determine impersonation
    if (
        signals["similarity_score"] >= similarity_threshold
        and domain_name != signals["brand_detected"]
    ):
        signals["possible_impersonation"] = True

    return signals


# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL for brand detection: ")
    print(brand_check(test_url))
