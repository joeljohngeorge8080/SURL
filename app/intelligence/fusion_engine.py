def classify_fused_intelligence(static_results: dict, dynamic_results: dict) -> dict:

    signals = []

    static_suspicious = False
    dynamic_suspicious = False

    brand_info = dynamic_results.get("brand_impersonation", {})
    credential_info = dynamic_results.get("credential_analysis", {})

    # -------------------------
    # BRAND MISMATCH
    # -------------------------

    if brand_info.get("mismatch_detected"):
        static_suspicious = True
        signals.append(
            f"Brand impersonation detected: {brand_info.get('brand_detected')}"
        )

    if brand_info.get("typosquatting_detected"):
        static_suspicious = True
        signals.append("Typosquatting pattern detected")

    if brand_info.get("logo_reference_detected"):
        signals.append("Brand logo reference detected")

    # -------------------------
    # CREDENTIAL CONTEXT
    # -------------------------

    credential_present = credential_info.get("credential_fields_detected", False)

    # -------------------------
    # DYNAMIC CLASSIFICATION
    # -------------------------

    dynamic_classification = dynamic_results.get("classification", "")

    if dynamic_classification not in [
        "No Significant Dynamic Threats Detected",
        "External Telemetry Submission Detected",
        "Execution Error",
        ""
    ]:
        dynamic_suspicious = True
        signals.append(f"Dynamic behavior flagged: {dynamic_classification}")

    # -------------------------
    # PHISHING ESCALATION RULE
    # -------------------------

    if (
        brand_info.get("mismatch_detected")
        and credential_present
        and dynamic_suspicious
    ):
        signals.append("Phishing escalation triggered by brand mismatch, credential presence, and dynamic behavior")

    # HIGH
    if static_suspicious and dynamic_suspicious:
        return {
            "final_classification": "Confirmed Malicious Behavior",
            "final_confidence": "High",
            "fusion_signals": signals
        }

    # MEDIUM
    if static_suspicious or dynamic_suspicious:
        return {
            "final_classification": "Suspicious Activity Observed",
            "final_confidence": "Medium",
            "fusion_signals": signals
        }

    # LOW
    return {
        "final_classification": "No Significant Threat Detected",
        "final_confidence": "High",
        "fusion_signals": ["Static and dynamic analysis show no correlated threats."]
    }
