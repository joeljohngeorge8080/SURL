# app/dynamic_analysis/network_monitor.py

from urllib.parse import urlparse
import tldextract
import ipaddress

from app.intelligence.trusted_domains import TRUSTED_TELEMETRY_DOMAINS


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
    except Exception:
        return False


def is_trusted_telemetry(domain: str) -> bool:
    if not domain:
        return False

    domain_lower = domain.lower()

    for trusted in TRUSTED_TELEMETRY_DOMAINS:
        trusted_lower = trusted.lower()
        if domain_lower == trusted_lower or domain_lower.endswith("." + trusted_lower):
            return True

    return False


def analyze_post_requests(original_url: str, requests: list) -> dict:
    """
    Safe network exfiltration analysis.
    """

    original_root = extract_root(original_url)

    post_targets = []
    external_post_detected = False
    ip_post_detected = False
    suspicious_post_detected = False
    post_requests_detected = False

    for req in requests:

        if req.get("method") != "POST":
            continue

        post_requests_detected = True

        target_url = req.get("url")
        if not target_url:
            continue

        try:
            parsed = urlparse(target_url)
            host = parsed.hostname or ""
            target_root = extract_root(target_url)
        except Exception:
            continue

        # 🚨 Direct IP submission
        if is_ip_address(host):
            ip_post_detected = True
            external_post_detected = True
            post_targets.append(target_url)
            continue

        # 🚨 Cross-root submission (not trusted telemetry)
        if target_root != original_root:
            if not is_trusted_telemetry(target_root):
                external_post_detected = True
                post_targets.append(target_url)

        # 🚨 Suspicious payload size
        try:
            content_length = int(req.get("content_length", 0))
            if content_length > 50000:
                suspicious_post_detected = True
        except Exception:
            pass

    return {
        "post_requests_detected": post_requests_detected,
        "external_post_detected": external_post_detected,
        "ip_post_detected": ip_post_detected,
        "suspicious_post_detected": suspicious_post_detected,
        "post_targets": post_targets
    }