# app/intelligence/correlation_engine.py



def _safe_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def evaluate_credential_signal(credential_analysis: dict, js_analysis: dict) -> bool:

    """
    Layer 1: Credential Signal
    """
    credential_analysis = _safe_dict(credential_analysis)
    js_analysis = _safe_dict(js_analysis)

    password_field = credential_analysis.get("credential_fields_detected", False)
    credential_js = bool(js_analysis.get("credential_related", []))

    return bool(password_field or credential_js)


def evaluate_exfiltration_signal(
    credential_analysis: dict,
    network_exfiltration: dict,
) -> bool:
    """
    Layer 2: Data Exfiltration Signal
    """

    credential_analysis = _safe_dict(credential_analysis)
    network_exfiltration = _safe_dict(network_exfiltration)

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

    redirect_analysis = _safe_dict(redirect_analysis)
    keyword_hits = _safe_dict(keyword_hits)

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

    redirect_analysis = _safe_dict(redirect_analysis)
    keyword_hits = _safe_dict(keyword_hits)
    js_analysis = _safe_dict(js_analysis)
    credential_analysis = _safe_dict(credential_analysis)
    network_exfiltration = _safe_dict(network_exfiltration)

    credential_signal = evaluate_credential_signal(
        credential_analysis,
        js_analysis,
    )

    exfiltration_signal = evaluate_exfiltration_signal(
        credential_analysis, network_exfiltration
    )

    infrastructure_signal = evaluate_infrastructure_signal(
        redirect_analysis, keyword_hits
    )

    signals = []
    if credential_signal:
        signals.append("credential_signal")
    if exfiltration_signal:
        signals.append("exfiltration_signal")
    if infrastructure_signal:
        signals.append("infrastructure_signal")

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
        "signals": signals,
    }
