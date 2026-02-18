from datetime import datetime

from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score
from scoring_engine.explanation import generate_explanation
from scoring_engine.pbh_fingerprint import generate_pbh_fingerprint
from static_analysis.url_normalizer import normalize_url, validate_domain

def run_full_scan(url: str):

    url = normalize_url(url)

    if not validate_domain(url):
        return {
            "error": "Invalid domain format. Please enter a valid domain (example.com)."
        }

    # continue scan normally...


ENGINE_VERSION = "1.0"


def scan_url(url: str) -> dict:
    """
    Main orchestration function for URL scanning.

    Pipeline:
        1. Static Analysis
        2. Risk Scoring
        3. Behavioral Fingerprint (PBH)
        4. Explanation Generation
        5. Final Structured Report

    Returns:
        dict: Structured security assessment report
    """

    # -------------------------
    # Step 1: Static Analysis
    # -------------------------
    static_results = run_static_analysis(url)

    # -------------------------
    # Step 2: Risk Score
    # -------------------------
    score_result = calculate_risk_score(static_results)

    # -------------------------
    # Step 3: PBH Fingerprint
    # -------------------------
    pbh_result = generate_pbh_fingerprint(static_results)

    # -------------------------
    # Step 4: Explanation Layer
    # -------------------------
    explanation_result = generate_explanation(static_results, score_result)

    # -------------------------
    # Step 5: Build Final Report
    # -------------------------
    final_report = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "engine_version": ENGINE_VERSION,
        "risk_score": score_result.get("risk_score"),
        "severity": score_result.get("severity"),
        "pbh_fingerprint": pbh_result.get("fingerprint"),
        "binary_pattern": pbh_result.get("binary_pattern"),
        "analysis": explanation_result.get("analysis")
    }

    return final_report
