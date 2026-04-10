def classify_behavior(
    redirect_analysis: dict,
    keyword_hits: dict,
    js_analysis: dict,
    credential_analysis: dict,
    network_exfiltration: dict,
) -> tuple:

    phishing_keywords = keyword_hits.get("phishing_keywords", [])
    payment_keywords = keyword_hits.get("payment_keywords", [])
    adult_keywords = keyword_hits.get("adult_keywords", [])

    cross_root = redirect_analysis.get("cross_root_detected", False)
    suspicious_redirect = redirect_analysis.get("suspicious_redirect_detected", False)

    has_password = credential_analysis.get("credential_fields_detected", False)

    external_post = network_exfiltration.get("external_post_detected", False)
    ip_post = network_exfiltration.get("ip_post_detected", False)
    suspicious_post = network_exfiltration.get("suspicious_post_detected", False)

    high_risk_js = bool(js_analysis.get("high_risk"))

    # ===============================
    # 🚨 CRITICAL CORRELATIONS
    # ===============================

    if has_password and ip_post:
        return "IP-Based Credential Exfiltration Detected", "High"

    if has_password and external_post:
        return "Credential Data Exfiltration Detected", "High"

    if high_risk_js and external_post:
        return "Obfuscated Script With Data Exfiltration", "High"

    # ===============================
    # 🚨 STRONG PHISHING
    # ===============================

    if has_password and phishing_keywords:
        return "Login-Based Phishing Pattern Detected", "High"

    if suspicious_redirect and has_password:
        return "Multi-Stage Credential Harvesting Pattern", "High"

    if cross_root and has_password:
        return "Cross-Domain Credential Harvesting Pattern", "High"

    # ===============================
    # 🟡 MODERATE RISK
    # ===============================

    if suspicious_post and has_password:
        return "Suspicious Credential Submission Activity", "Medium"

    if suspicious_redirect and phishing_keywords:
        return "Redirect + Phishing Keyword Correlation", "Medium"

    if high_risk_js:
        return "Obfuscated Script Behavior Detected", "Medium"

    # ===============================
    # 🟣 CATEGORY CLASSIFICATION
    # ===============================

    if adult_keywords:
        return "Adult Content Site", "High"

    if payment_keywords and has_password:
        return "Payment Collection Portal", "Medium"

    # ===============================
    # DEFAULT
    # ===============================

    return "No Significant Dynamic Threats Detected", "High"
