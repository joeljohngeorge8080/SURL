def calculate_risk_score(static_results):
    """
    Calculates transport and phishing risk scores separately.
    Returns final normalized risk score (0-100).
    """

    transport_score = 0
    phishing_score = 0
    reasons = []

    # Extract analysis results
    protocol = static_results.get("protocol_check", {})
    tls = static_results.get("tls_analysis", {})
    lexical = static_results.get("lexical_analysis", {})
    html = static_results.get("html_analysis", {})
    whois = static_results.get("whois_analysis", {})
    brand = static_results.get("brand_analysis", {})

    # -------------------
    # TRANSPORT RISK (TLS + Protocol)
    # -------------------

    if not protocol.get("uses_https", True):
        transport_score += 15
        reasons.append("The URL does not use HTTPS.")

    if not tls.get("https_supported", True):
        transport_score += 30
        reasons.append("HTTPS not supported")

    elif not tls.get("certificate_valid", True):
        transport_score += 35
        reasons.append("Invalid or expired TLS certificate")

    if tls.get("self_signed_cert"):
        transport_score += 20
        reasons.append("Self-signed TLS certificate")

    if tls.get("domain_mismatch"):
        transport_score += 25
        reasons.append("TLS certificate domain mismatch")

    # -------------------
    # PHISHING RISK (Lexical + HTML + WHOIS + Brand)
    # -------------------

    suspicious_flags = [
        lexical.get("long_url"),
        lexical.get("contains_at_symbol"),
        lexical.get("encoded_url"),
        lexical.get("ip_based_url"),
        lexical.get("suspicious_keywords"),
        lexical.get("multiple_subdomains"),
    ]

    if any(suspicious_flags):
        phishing_score += 20
        reasons.append("Suspicious URL structure detected")

    if html.get("has_password_input") and html.get("external_form_action"):
        phishing_score += 40
        reasons.append("Credential harvesting behavior detected")

    if html.get("js_obfuscation_detected"):
        phishing_score += 25
        reasons.append("Obfuscated JavaScript detected")

    if not html.get("html_fetched", True):
        phishing_score += 20
        reasons.append("Website could not be fetched")

    if whois.get("new_domain"):
        phishing_score += 20
        reasons.append("Recently registered domain")

    if not whois.get("whois_found", True):
        phishing_score += 15
        reasons.append("WHOIS information unavailable")

    if brand.get("possible_impersonation"):
        phishing_score += 40
        reasons.append("Possible brand impersonation detected")

    # -------------------
    # NORMALIZE SCORES
    # -------------------
    # Keep individual scores for display, but cap them at 100
    transport_score = min(transport_score, 100)
    phishing_score = min(phishing_score, 100)

    # Final score is the combination, normalized to 0-100
    final_score = min(transport_score + phishing_score, 100)

    # Determine severity based on final score
    if final_score <= 20:
        severity = "Low"
    elif final_score <= 40:
        severity = "Medium"
    elif final_score <= 60:
        severity = "Medium-High"
    else:
        severity = "High"

    return {
        "risk_score": final_score,
        "severity": severity,
        "transport_risk": transport_score,
        "phishing_risk": phishing_score,
        "reasons": reasons,
    }


def generate_confidence_score(static_results):
    """
    Calculates confidence score (0-100) based on data availability.
    Higher score = more complete analysis with valid data.
    """

    confidence = 0
    max_confidence = 100

    # Check each module for data availability
    modules_checked = 0
    modules_successful = 0

    # TLS Analysis
    modules_checked += 1
    tls = static_results.get("tls_analysis", {})
    if tls and tls.get("https_supported") is not None:
        modules_successful += 1

    # Protocol Check
    modules_checked += 1
    protocol = static_results.get("protocol_check", {})
    if protocol and "uses_https" in protocol:
        modules_successful += 1

    # HTML Analysis
    modules_checked += 1
    html = static_results.get("html_analysis", {})
    if html and html.get("html_fetched"):
        modules_successful += 1

    # WHOIS Analysis
    modules_checked += 1
    whois = static_results.get("whois_analysis", {})
    if whois and whois.get("whois_found"):
        modules_successful += 1

    # Lexical Analysis
    modules_checked += 1
    lexical = static_results.get("lexical_analysis", {})
    if lexical:
        modules_successful += 1

    # Brand Detection
    modules_checked += 1
    brand = static_results.get("brand_analysis", {})
    if brand is not None:
        modules_successful += 1

    # Calculate confidence as percentage of successful modules
    if modules_checked > 0:
        confidence = int((modules_successful / modules_checked) * max_confidence)

    return min(confidence, 100)

