# app/dynamic_analysis/network_monitor.py

from urllib.parse import urlparse
import tldextract
import ipaddress


def extract_root(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return ""


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except:
        return False


def analyze_post_requests(original_url: str, requests: list) -> dict:
    """
    Intelligent network exfiltration analysis.

    requests: list of dicts:
        {
            "method": "POST",
            "url": "...",
            "content_length": int
        }
    """

    original_root = extract_root(original_url)

    post_targets = []
    external_post_detected = False
    ip_post_detected = False
    suspicious_post_detected = False

    for req in requests:
        if req.get("method") != "POST":
            continue

        target_url = req.get("url")
        if not target_url:
            continue

        post_targets.append(target_url)

        parsed = urlparse(target_url)
        host = parsed.hostname or ""

        # 🚨 Direct IP submission
        if is_ip_address(host):
            ip_post_detected = True
            external_post_detected = True
            continue

        target_root = extract_root(target_url)

        # 🚨 Cross-root submission
        if target_root != original_root:
            external_post_detected = True

        # 🚨 Suspicious payload size
        content_length = req.get("content_length", 0)
        if content_length and content_length > 50000:
            suspicious_post_detected = True

    return {
        "post_requests_detected": len(post_targets) > 0,
        "external_post_detected": external_post_detected,
        "ip_post_detected": ip_post_detected,
        "suspicious_post_detected": suspicious_post_detected,
        "post_targets": post_targets
    }
