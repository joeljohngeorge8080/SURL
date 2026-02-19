from datetime import datetime
import time
import uuid

from app.core.logger import logger

from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score
from scoring_engine.explanation import generate_explanation
from scoring_engine.pbh_fingerprint import generate_pbh_fingerprint
from static_analysis.url_normalizer import normalize_url, validate_domain


ENGINE_VERSION = "1.0"


def scan_url(url: str) -> dict:
    """
    Main orchestration function for URL scanning.

    Pipeline:
        1. URL Normalization & Validation
        2. Static Analysis
        3. Risk Scoring
        4. Behavioral Fingerprint (PBH)
        5. Explanation Generation
        6. Final Structured Report
    """

    request_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(f"[{request_id}] Scan initiated | Raw Input: {url}")

    try:
        # -------------------------
        # Step 1: Normalize URL
        # -------------------------
        url = normalize_url(url)
        logger.info(f"[{request_id}] Normalized URL: {url}")

        if not validate_domain(url):
            logger.warning(f"[{request_id}] Invalid domain format")

            return {
                "request_id": request_id,
                "url": url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine_version": ENGINE_VERSION,
                "risk_score": 0,
                "severity": "Low",
                "pbh_fingerprint": "",
                "binary_pattern": "",
                "executive_summary": "Invalid domain format. Please enter a valid domain.",
                "detailed_analysis": []
            }

        # -------------------------
        # Step 2: Static Analysis
        # -------------------------
        logger.info(f"[{request_id}] Running static analysis...")
        static_results = run_static_analysis(url)

        # -------------------------
        # Step 3: Risk Score
        # -------------------------
        logger.info(f"[{request_id}] Calculating risk score...")
        score_result = calculate_risk_score(static_results)

        # -------------------------
        # Step 4: PBH Fingerprint
        # -------------------------
        logger.info(f"[{request_id}] Generating behavioral fingerprint...")
        pbh_result = generate_pbh_fingerprint(static_results)

        # -------------------------
        # Step 5: Explanation Layer
        # -------------------------
        logger.info(f"[{request_id}] Generating explanation report...")
        explanation_result = generate_explanation(static_results, score_result)

        # -------------------------
        # Step 6: Final Report
        # -------------------------
        final_report = {
            "request_id": request_id,
            "url": url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engine_version": ENGINE_VERSION,
            "risk_score": score_result.get("risk_score"),
            "severity": score_result.get("severity"),
            "pbh_fingerprint": pbh_result.get("fingerprint"),
            "binary_pattern": pbh_result.get("binary_pattern"),
            "executive_summary": explanation_result.get("executive_summary"),
            "detailed_analysis": explanation_result.get("detailed_analysis", [])
        }

        duration = round(time.time() - start_time, 3)

        logger.info(
            f"[{request_id}] Scan completed | "
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
