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
    except:
        return False


def is_trusted_telemetry(domain: str) -> bool:
    """
    Check if domain is in trusted telemetry whitelist.
    Compares root domains safely.
    """
    if not domain:
        return False
    
    domain_lower = domain.lower()
    
    for trusted in TRUSTED_TELEMETRY_DOMAINS:
        trusted_lower = trusted.lower()
        # Exact match or subdomain match
        if domain_lower == trusted_lower or domain_lower.endswith("." + trusted_lower):
            return True
    
    return False


def analyze_post_requests(original_url: str, requests: list) -> dict:
    """
    Intelligent network exfiltration analysis with trusted domain filtering.

    Detects suspicious POST requests while excluding known telemetry services.

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

        # 🚨 Direct IP submission is always suspicious
        if is_ip_address(host):
            ip_post_detected = True
            external_post_detected = True
            continue

        target_root = extract_root(target_url)

        # Cross-root submission: only flag if not in trusted list
        if target_root != original_root:
            # Check against trusted telemetry domains
            if not is_trusted_telemetry(target_root):
                external_post_detected = True

        # 🚨 Suspicious payload size (50KB+)
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
