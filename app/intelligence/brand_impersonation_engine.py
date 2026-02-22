# app/intelligence/brand_impersonation_engine.py

from typing import Dict, List
from urllib.parse import urlparse
from difflib import SequenceMatcher
import tldextract
from app.intelligence.redirect_intelligence import extract_root_domain


# ---------------------------------------------------
# OFFICIAL BRAND DATABASE
# ---------------------------------------------------

BRAND_DATABASE = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "github": ["github.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
}


# ---------------------------------------------------
# Character Normalization for Typosquatting
# ---------------------------------------------------

def normalize_domain(domain: str) -> str:
    """
    Normalize domain by replacing common typosquatting character substitutions.
    
    Examples:
        paypa1 → paypal
        microsof7 → microsoft
        amaz0n → amazon
    """
    substitution_map = {
        "0": "o",
        "1": "l",
        "3": "e",
        "@": "a",
        "$": "s",
        "5": "s",
        "7": "t"
    }

    normalized = ""
    for char in domain:
        normalized += substitution_map.get(char, char)

    return normalized


# ---------------------------------------------------
# Levenshtein Distance Calculation
# ---------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate edit distance between two strings.
    No external dependencies required.
    
    Distance ≤ 1 indicates likely typosquatting.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


# ---------------------------------------------------
# Utility: Typosquatting Similarity Check
# ---------------------------------------------------

def is_similar(a: str, b: str, threshold: float = 0.85) -> bool:
    return SequenceMatcher(None, a, b).ratio() >= threshold


OAUTH_PHRASES = [
    "sign in with",
    "continue with",
    "login with",
    "powered by",
]


# ---------------------------------------------------
# DOMAIN-LEVEL BRAND + TYPOSQUATTING DETECTION
# ---------------------------------------------------

def analyze_domain_brand_impersonation(url: str) -> Dict:

    result = {
        "brand_detected": None,
        "official_domains": [],
        "current_root_domain": None,
        "mismatch_detected": False,
        "typosquatting_detected": False,
        "logo_reference_detected": False,
        "risk_level": "None",
        "detection_source": "domain",
        "detection_method": None
    }

    if not url:
        return result

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    current_root = extract_root_domain(url)
    result["current_root_domain"] = current_root

    # Split hostname into tokens for granular matching
    tokens = []
    for token in hostname_lower.replace(".", "-").split("-"):
        if token:
            tokens.append(token)

    for brand, official_domains in BRAND_DATABASE.items():
        brand_lower = brand.lower()

        # Strategy 1: Exact brand keyword in domain
        if brand_lower in hostname_lower:
            result["brand_detected"] = brand
            result["official_domains"] = official_domains
            result["detection_method"] = "exact"

            if current_root not in official_domains:
                result["mismatch_detected"] = True
                result["risk_level"] = "High"

            return result

        # Strategy 2: Token-level matching with multiple detection methods
        for token in tokens:
            # Exact match on token
            if token == brand_lower:
                result["brand_detected"] = brand
                result["official_domains"] = official_domains
                result["detection_method"] = "exact"

                if current_root not in official_domains:
                    result["mismatch_detected"] = True
                    result["risk_level"] = "High"

                return result

            # Normalized match (typosquatting character substitutions)
            normalized_token = normalize_domain(token)
            if normalized_token == brand_lower:
                result["brand_detected"] = brand
                result["official_domains"] = official_domains
                result["typosquatting_detected"] = True
                result["mismatch_detected"] = True
                result["risk_level"] = "High"
                result["detection_method"] = "normalized"
                return result

            # Fuzzy match using Levenshtein distance (small edit distance)
            distance = levenshtein_distance(token, brand_lower)
            if distance <= 1:
                result["brand_detected"] = brand
                result["official_domains"] = official_domains
                result["typosquatting_detected"] = True
                result["mismatch_detected"] = True
                result["risk_level"] = "High"
                result["detection_method"] = "fuzzy"
                return result

        # Strategy 3: Domain-level typosquatting (falls back to SequenceMatcher)
        domain_without_tld = current_root.split(".")[0]

        if is_similar(domain_without_tld, brand_lower):
            result["brand_detected"] = brand
            result["official_domains"] = official_domains
            result["typosquatting_detected"] = True
            result["mismatch_detected"] = True
            result["risk_level"] = "High"
            result["detection_method"] = "fuzzy"
            return result

    return result


# ---------------------------------------------------
# PAGE-CONTENT BRAND + LOGO DETECTION
# ---------------------------------------------------

def analyze_page_brand_impersonation(url: str, page_text: str, title: str = "", headings: list = None) -> Dict:

    from app.intelligence.trusted_domains import BRAND_OFFICIAL_DOMAINS

    if headings is None:
        headings = []

    result = {
        "brand_detected": None,
        "current_root_domain": None,
        "mismatch_detected": False,
        "detection_source": "content",
        "detection_method": None,
        "official_domains": [],
    }

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(hostname)
    current_root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    result["current_root_domain"] = current_root

    text_lower = page_text.lower()
    title_lower = title.lower() if title else ""
    heading_text = " ".join(headings).lower() if headings else ""

    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():

        brand_lower = brand.lower()

        # Skip if domain already matches official
        if any(current_root.endswith(off) for off in official_domains):
            continue

        brand_occurrences = text_lower.count(brand_lower)

        # Brand must appear at least twice in content
        if brand_occurrences < 2:
            continue

        # Check if brand appears in identity elements
        identity_match = (
            brand_lower in title_lower
            or brand_lower in heading_text
        )

        if not identity_match:
            continue

        # Filter OAuth reference phrases
        oauth_flag = False
        for phrase in OAUTH_PHRASES:
            if f"{phrase} {brand_lower}" in text_lower:
                oauth_flag = True
                break

        if oauth_flag:
            continue

        # If reached here → impersonation
        result["brand_detected"] = brand
        result["mismatch_detected"] = True
        result["official_domains"] = official_domains
        result["detection_method"] = "identity_content"

        return result

    return result
