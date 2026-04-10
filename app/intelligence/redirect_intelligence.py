# app/intelligence/redirect_intelligence.py

import tldextract
from app.intelligence.trusted_domains import TRUSTED_REDIRECT_PLATFORMS


SUSPICIOUS_TLDS = {"tk", "xyz", "top", "gq", "ml", "cf"}


def extract_root_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return ""


def extract_tld(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        return ext.suffix
    except Exception:
        return ""


def analyze_redirect_chain(original_url: str, chain: list) -> dict:

    if not chain:
        return {
            "redirect_chain": [],
            "root_domains": [],
            "redirect_count": 0,
            "cross_root_detected": False,
            "suspicious_redirect_detected": False,
        }

    original_root = extract_root_domain(original_url)

    root_domains = []
    suspicious_tld_detected = False

    for url in chain:
        root = extract_root_domain(url)
        tld = extract_tld(url)

        if root and root not in root_domains:
            root_domains.append(root)

        if tld in SUSPICIOUS_TLDS:
            suspicious_tld_detected = True

    redirect_count = max(len(chain) - 1, 0)

    final_root = extract_root_domain(chain[-1])

    cross_root_detected = final_root != original_root

    suspicious_redirect_detected = False

    # 🔥 Intelligent Suspicion Logic
    if original_root not in TRUSTED_REDIRECT_PLATFORMS:

        if (
            redirect_count > 2
            and cross_root_detected
            and len(root_domains) > 2
        ):
            suspicious_redirect_detected = True

        if suspicious_tld_detected:
            suspicious_redirect_detected = True

    return {
        "redirect_chain": chain,
        "root_domains": root_domains,
        "redirect_count": redirect_count,
        "cross_root_detected": cross_root_detected,
        "suspicious_redirect_detected": suspicious_redirect_detected,
    }
