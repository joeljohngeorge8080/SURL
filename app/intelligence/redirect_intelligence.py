# app/intelligence/redirect_intelligence.py

from urllib.parse import urlparse
import tldextract


def extract_root_domain(url: str) -> str:
    """
    Extracts proper root domain using public suffix list.
    Example:
        https://mail.google.co.uk → google.co.uk
    """
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return ""


def analyze_redirect_chain(original_url: str, chain: list) -> dict:
    """
    Intelligent redirect analysis.

    Suspicious conditions:
        - More than 3 redirects AND multiple root domains
        - Final root domain differs from original root domain
    """

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

    for url in chain:
        root = extract_root_domain(url)
        if root and root not in root_domains:
            root_domains.append(root)

    redirect_count = max(len(chain) - 1, 0)

    final_root = extract_root_domain(chain[-1])

    cross_root_detected = final_root != original_root

    suspicious_redirect_detected = (
        redirect_count > 3 and len(root_domains) > 1
    ) or cross_root_detected

    return {
        "redirect_chain": chain,
        "root_domains": root_domains,
        "redirect_count": redirect_count,
        "cross_root_detected": cross_root_detected,
        "suspicious_redirect_detected": suspicious_redirect_detected,
    }
