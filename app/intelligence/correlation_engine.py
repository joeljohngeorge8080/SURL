# app/intelligence/correlation_engine.py



def evaluate_credential_signal(credential_analysis: dict, _js_analysis: dict) -> bool:

    """
    Layer 1: Credential Signal
    """

    password_field = credential_analysis.get("credential_fields_detected", False)

    external_form = credential_analysis.get("external_form_action", False)
    ip_form = credential_analysis.get("ip_based_form_action", False)

    # JS-only signals must not trigger credential escalation.
    return password_field or external_form or ip_form



def evaluate_exfiltration_signal(
    credential_analysis: dict,
    network_exfiltration: dict,
) -> bool:
    """
    Layer 2: Data Exfiltration Signal
    """

    external_form = credential_analysis.get("external_form_action", False)
    ip_form = credential_analysis.get("ip_based_form_action", False)

    external_post = network_exfiltration.get("external_post_detected", False)
    ip_post = network_exfiltration.get("ip_post_detected", False)

    return external_form or ip_form or external_post or ip_post


def evaluate_infrastructure_signal(
    redirect_analysis: dict,
    keyword_hits: dict,
) -> bool:
    """
    Layer 3: Infrastructure Signal
    """

    cross_root = redirect_analysis.get("cross_root_detected", False)
    suspicious_redirect = redirect_analysis.get(
        "suspicious_redirect_detected", False
    )

    phishing_keywords = keyword_hits.get("phishing_keywords", [])

    return cross_root or suspicious_redirect or bool(phishing_keywords)


def strict_three_layer_correlation(
    redirect_analysis: dict,
    keyword_hits: dict,
    js_analysis: dict,
    credential_analysis: dict,
    network_exfiltration: dict,
) -> dict:
    """
    Strict 3-layer escalation engine.
    """

    credential_signal = evaluate_credential_signal(
        credential_analysis,
        js_analysis,
        network_exfiltration,
    )

    exfiltration_signal = evaluate_exfiltration_signal(
        credential_analysis, network_exfiltration
    )

    infrastructure_signal = evaluate_infrastructure_signal(
        redirect_analysis, keyword_hits
    )

    # STRICT ESCALATION
    if credential_signal and exfiltration_signal and infrastructure_signal:
        classification = "Credential Harvesting Infrastructure Detected"
        confidence = "High"

    elif credential_signal and exfiltration_signal:
        classification = "Suspicious Credential Submission Behavior"
        confidence = "Medium"

    else:
        classification = "No Significant Dynamic Threats Detected"
        confidence = "High"

    return {
        "classification": classification,
        "confidence": confidence,
        "signals": {
            "credential_signal": credential_signal,
            "exfiltration_signal": exfiltration_signal,
            "infrastructure_signal": infrastructure_signal,
        },
    }
