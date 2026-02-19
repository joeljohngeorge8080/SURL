from datetime import datetime
import time
import uuid
import ipaddress
import socket
from urllib.parse import urlparse

from app.core.logger import logger

from app.dynamic_analysis.sandbox_runner import run_dynamic_analysis

from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score
from scoring_engine.explanation import generate_explanation
from scoring_engine.pbh_fingerprint import generate_pbh_fingerprint
from static_analysis.url_normalizer import normalize_url, validate_domain


ENGINE_VERSION = "1.0"


# ==========================================================
# IP ADDRESS DETECTION
# ==========================================================
def is_ip_address(url: str) -> bool:
    """
    Check if a URL directly contains an IP address (not a domain).
    Returns True if the URL's hostname is a valid IP address.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


# ==========================================================
# PRIVATE IP DETECTION
# ==========================================================
def is_private_ip(url: str) -> bool:
    """
    Detect if the URL resolves to a private or loopback IP.
    Blocks:
        10.x.x.x
        172.16.x.x – 172.31.x.x
        192.168.x.x
        127.x.x.x
        localhost
    """

    try:
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return False

        # Direct IP
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            pass  # Not an IP, continue

        # DNS resolution
        try:
            resolved_ip = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved_ip)
            return ip.is_private or ip.is_loopback
        except Exception:
            return False

    except Exception as e:
        logger.warning(f"Private IP check failed: {str(e)}")
        return False


# ==========================================================
# MAIN SCAN FUNCTION
# ==========================================================
async def scan_url(url: str) -> dict:

    request_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(f"[{request_id}] Scan initiated | Raw Input: {url}")

    try:

        # --------------------------------------------------
        # STEP 1 — NORMALIZATION
        # --------------------------------------------------
        url = normalize_url(url)
        logger.info(f"[{request_id}] Normalized URL: {url}")

        parsed = urlparse(url)
        domain = parsed.netloc

        if not validate_domain(domain):
            logger.warning(f"[{request_id}] Invalid domain format")

            return {
                "url": url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine_version": ENGINE_VERSION,
                "risk_score": 0,
                "severity": "Low",
                "transport_risk": 0,
                "phishing_risk": 0,
                "confidence_score": 0,
                "pbh_fingerprint": "",
                "binary_pattern": "",
                "executive_summary": "Invalid domain format. Please enter a valid domain.",
                "detailed_analysis": []
            }

        # --------------------------------------------------
        # BLOCK PRIVATE IP
        # --------------------------------------------------
        if is_private_ip(url):
            logger.warning(f"[{request_id}] Private IP blocked: {domain}")

            return {
                "url": url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine_version": ENGINE_VERSION,
                "risk_score": 0,
                "severity": "Low",
                "transport_risk": 0,
                "phishing_risk": 0,
                "confidence_score": 0,
                "pbh_fingerprint": "",
                "binary_pattern": "",
                "executive_summary": "Private IP addresses (e.g., 192.168.x.x, 10.x.x.x) cannot be scanned by SURL.",
                "detailed_analysis": []
            }

        # 🚨 PUBLIC IP URL DETECTION (Phishing Risk)
        if is_ip_address(url):
            logger.warning(f"[{request_id}] Public IP-based URL detected: {domain}")

        # --------------------------------------------------
        # STEP 2 — STATIC ANALYSIS
        # --------------------------------------------------
        logger.info(f"[{request_id}] Running static analysis")
        static_results = run_static_analysis(url)

        # --------------------------------------------------
        # STEP 3 — RISK SCORING
        # --------------------------------------------------
        logger.info(f"[{request_id}] Calculating risk score")
        score_result = calculate_risk_score(static_results)

        # --------------------------------------------------
        # STEP 4 — PBH FINGERPRINT
        # --------------------------------------------------
        logger.info(f"[{request_id}] Generating PBH fingerprint")
        pbh_result = generate_pbh_fingerprint(static_results)

        # --------------------------------------------------
        # STEP 5 — EXPLANATION
        # --------------------------------------------------
        logger.info(f"[{request_id}] Generating explanation")
        explanation_result = generate_explanation(static_results, score_result)

        # --------------------------------------------------
        # STEP 6 — FINAL REPORT
        # --------------------------------------------------
        final_report = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engine_version": ENGINE_VERSION,

            "risk_score": score_result.get("risk_score", 0),
            "severity": score_result.get("severity", "Low"),

            "transport_risk": score_result.get("transport_risk", 0),
            "phishing_risk": score_result.get("phishing_risk", 0),

            "confidence_score": score_result.get("confidence_score", 0),

            "pbh_fingerprint": pbh_result.get("fingerprint", ""),
            "binary_pattern": pbh_result.get("binary_pattern", ""),

            "executive_summary": explanation_result.get("executive_summary", ""),
            "detailed_analysis": explanation_result.get("detailed_analysis", [])
        }

        duration = round(time.time() - start_time, 3)

        logger.info(
            f"[{request_id}] Completed | "
            f"Score: {final_report['risk_score']} | "
            f"Severity: {final_report['severity']} | "
            f"Duration: {duration}s"
        )

        return final_report

    except Exception as e:
        duration = round(time.time() - start_time, 3)

        logger.error(
            f"[{request_id}] Scan failed after {duration}s | Error: {str(e)}"
        )
        raise


# ==========================================================
# DYNAMIC SCAN ONLY
# ==========================================================
async def run_dynamic_scan(url: str) -> dict:
    """
    Runs dynamic sandbox only.
    Returns dynamic analysis report.
    """
    dynamic_results = await run_dynamic_analysis(url)

    return {
        "url": url,
        "dynamic_analysis": dynamic_results,
        "dynamic_risk_score": dynamic_results.get("dynamic_risk_score")
    }
