def calculate_risk_score(static_results):
    """
    Calculates phishing risk score (0–100) based on static analysis results.
    """

    score = 0
    reasons = []

    # -----------------------
    # EXTRACT RESULTS ONCE
    # -----------------------
    protocol = static_results.get("protocol_check", {})
    tls = static_results.get("tls_analysis", {})
    lexical = static_results.get("lexical_analysis", {})
    html = static_results.get("html_analysis", {})
    whois = static_results.get("whois_analysis", {})
    brand = static_results.get("brand_analysis", {})

    # -----------------------
    # PROTOCOL / TLS
    # -----------------------
    if not protocol.get("uses_https", True):
        score += 10
        reasons.append("The URL does not use HTTPS.")

    if tls.get("tls_supported") is False:
        score += 20
        reasons.append("The site does not properly support TLS.")

    if tls.get("self_signed_cert"):
        score += 15
        reasons.append("The site uses a self-signed TLS certificate.")

    if tls.get("domain_mismatch"):
        score += 20
        reasons.append("TLS certificate does not match the domain.")

    # -----------------------
    # LEXICAL ANALYSIS
    # -----------------------
    suspicious_lexical_flags = [
        lexical.get("long_url"),
        lexical.get("contains_at_symbol"),
        lexical.get("encoded_url"),
        lexical.get("ip_based_url"),
        lexical.get("suspicious_keywords"),
        lexical.get("multiple_subdomains"),
    ]

    if any(suspicious_lexical_flags):
        score += 15
        reasons.append("The URL contains suspicious lexical patterns.")

    # -----------------------
    # HTML ANALYSIS
    # -----------------------
    if html.get("has_password_input") and html.get("external_form_action"):
        score += 40
        reasons.append(
            "Credential form submits data to an external domain."
        )

    if html.get("js_obfuscation_detected"):
        score += 20
        reasons.append("Obfuscated JavaScript detected.")

    if not html.get("html_fetched", True):
        score += 25
        reasons.append(
            "The website could not be fetched, common for malicious domains."
        )

    # -----------------------
    # WHOIS ANALYSIS
    # -----------------------
    if whois.get("new_domain"):
        score += 20
        reasons.append("The domain was registered recently.")

    if not whois.get("whois_found", True):
        score += 20
        reasons.append("WHOIS information could not be retrieved.")

    # -----------------------
    # BRAND IMPERSONATION
    # -----------------------
    if brand.get("possible_impersonation"):
        score += 40
        reasons.append("Possible brand impersonation detected.")

    # -----------------------
    # TRUST SIGNAL AGGREGATION (ONCE)
    # -----------------------
    trust_signals = 0

    if tls.get("certificate_valid"):
        trust_signals += 1

    if whois.get("domain_age_days") and whois.get("domain_age_days") > 180:
        trust_signals += 1

    if html.get("html_fetched"):
        trust_signals += 1

    if trust_signals == 0:
        score += 20
        reasons.append(
            "The site lacks basic trust indicators such as TLS, domain history, or accessible content."
        )

    # -----------------------
    # NORMALIZATION
    # -----------------------
    score = max(0, min(score, 100))

    if score <= 20:
        severity = "Low"
    elif score <= 40:
        severity = "Medium"
    elif score <= 60:
        severity = "Medium-High"
    else:
        severity = "High"

    return {
        "risk_score": score,
        "severity": severity,
        "reasons": reasons,
    }
