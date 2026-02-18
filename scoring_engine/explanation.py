def generate_explanation(static_results, score_result):
    """
    Generates structured, defensive explanations
    based on static analysis and final risk score.
    """

    explanations = []

    protocol = static_results.get("protocol_check", {})
    tls = static_results.get("tls_analysis", {})
    lexical = static_results.get("lexical_analysis", {})
    html = static_results.get("html_analysis", {})
    whois = static_results.get("whois_analysis", {})
    brand = static_results.get("brand_analysis", {})

    # -------------------------
    # PROTOCOL / TLS
    # -------------------------
    if not protocol.get("uses_https", True):
        explanations.append({
            "indicator": "No HTTPS",
            "why_risky": "Unencrypted connections allow attackers to intercept or modify traffic.",
            "impact": "Sensitive data such as passwords may be exposed.",
            "recommendation": "Use HTTPS with a valid TLS certificate."
        })

    if tls.get("self_signed_cert"):
        explanations.append({
            "indicator": "Self-signed certificate",
            "why_risky": "Self-signed certificates are not verified by trusted authorities.",
            "impact": "Users cannot confirm the authenticity of the website.",
            "recommendation": "Obtain a certificate from a trusted Certificate Authority."
        })

    if tls.get("domain_mismatch"):
        explanations.append({
            "indicator": "TLS domain mismatch",
            "why_risky": "The certificate does not match the domain being accessed.",
            "impact": "This is commonly seen in phishing and impersonation attacks.",
            "recommendation": "Ensure the certificate matches the domain name exactly."
        })

    # -------------------------
    # LEXICAL ANALYSIS
    # -------------------------
    suspicious_flags = [
        lexical.get("long_url"),
        lexical.get("contains_at_symbol"),
        lexical.get("encoded_url"),
        lexical.get("ip_based_url"),
        lexical.get("suspicious_keywords"),
        lexical.get("multiple_subdomains"),
    ]

    if any(suspicious_flags):
        explanations.append({
            "indicator": "Suspicious URL structure",
            "why_risky": "Attackers often use complex or misleading URLs to hide malicious intent.",
            "impact": "Users may believe they are visiting a legitimate website.",
            "recommendation": "Verify the domain name carefully before interacting."
        })

    # -------------------------
    # HTML STRUCTURE
    # -------------------------
    if html.get("has_password_input") and html.get("external_form_action"):
        explanations.append({
            "indicator": "External credential submission",
            "why_risky": "Submitting credentials to an external domain is a common phishing technique.",
            "impact": "User credentials may be captured by attackers.",
            "recommendation": "Ensure form actions point only to trusted internal domains."
        })

    if html.get("js_obfuscation_detected"):
        explanations.append({
            "indicator": "Obfuscated JavaScript",
            "why_risky": "Obfuscation is often used to hide malicious behavior.",
            "impact": "Malicious scripts may execute without user awareness.",
            "recommendation": "Review JavaScript code and avoid unnecessary obfuscation."
        })

    if not html.get("html_fetched", True):
        explanations.append({
            "indicator": "Site not reachable",
            "why_risky": "Short-lived or malicious domains often become unavailable quickly.",
            "impact": "This may indicate temporary phishing infrastructure.",
            "recommendation": "Verify domain legitimacy before interacting."
        })

    # -------------------------
    # WHOIS
    # -------------------------
    if whois.get("new_domain"):
        explanations.append({
            "indicator": "Recently registered domain",
            "why_risky": "Phishing campaigns frequently use newly registered domains.",
            "impact": "Limited domain history reduces trustworthiness.",
            "recommendation": "Be cautious when interacting with new domains."
        })

    if not whois.get("whois_found", True):
        explanations.append({
            "indicator": "Missing WHOIS data",
            "why_risky": "Lack of domain registration transparency can indicate abuse.",
            "impact": "Domain ownership cannot be verified.",
            "recommendation": "Investigate domain ownership before trusting the site."
        })

    # -------------------------
    # BRAND IMPERSONATION
    # -------------------------
    if brand.get("possible_impersonation"):
        explanations.append({
            "indicator": "Brand impersonation detected",
            "why_risky": "Impersonating trusted brands is a common phishing strategy.",
            "impact": "Users may unknowingly disclose sensitive information.",
            "recommendation": "Access official websites directly instead of clicking links."
        })

    # -------------------------
    # FINAL SECURITY SUMMARY
    # -------------------------
    summary = {
        "risk_score": score_result.get("risk_score"),
        "severity": score_result.get("severity"),
        "analysis": explanations
    }

    return summary
