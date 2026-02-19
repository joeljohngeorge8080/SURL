def calculate_risk_score(static_results):
    """
    Strictly separates Transport Risk from Phishing Risk.
    
    Transport Risk: TLS, HTTPS, connection, fetch failures
    Phishing Risk: Lexical patterns, forms, domain age, brand impersonation
    
    Returns final normalized risk score (0-100) with confidence.
    """

    transport_score = 0
    phishing_score = 0
    reasons = []
    
    # Track indicators for confidence calculation
    transport_indicators = 0
    phishing_indicators = 0

    # Extract analysis results
    protocol = static_results.get("protocol_check", {})
    tls = static_results.get("tls_analysis", {})
    lexical = static_results.get("lexical_analysis", {})
    html = static_results.get("html_analysis", {})
    whois = static_results.get("whois_analysis", {})
    brand = static_results.get("brand_analysis", {})

    # ═══════════════════════════════════════════════════════════
    # TRANSPORT RISK ONLY
    # ═══════════════════════════════════════════════════════════
    
    # HTTPS Protocol Issues
    if not protocol.get("uses_https", True):
        transport_score += 15
        reasons.append("The URL does not use HTTPS")
        transport_indicators += 1

    # TLS/Certificate Issues
    if not tls.get("https_supported", True):
        transport_score += 30
        reasons.append("HTTPS not supported")
        transport_indicators += 1
    elif not tls.get("certificate_valid", True):
        transport_score += 35
        reasons.append("Invalid or expired TLS certificate")
        transport_indicators += 1

    if tls.get("tls_supported") is False:
        transport_score += 20
        reasons.append("TLS not supported")
        transport_indicators += 1

    if tls.get("self_signed_cert"):
        transport_score += 20
        reasons.append("Self-signed TLS certificate")
        transport_indicators += 1

    if tls.get("domain_mismatch"):
        transport_score += 25
        reasons.append("TLS certificate domain mismatch")
        transport_indicators += 1

    # Connection Failures (TRANSPORT, NOT PHISHING)
    if not html.get("html_fetched", True):
        transport_score += 25
        reasons.append("Website could not be fetched")
        transport_indicators += 1

    # Check for connection-specific errors in reasons
    if "Connection timed out" in str(static_results):
        transport_score += 30
        reasons.append("Connection timed out")
        transport_indicators += 1

    if "Domain unreachable or DNS resolution failed" in str(static_results):
        transport_score += 50
        reasons.append("Domain unreachable or DNS resolution failed")
        transport_indicators += 1

    # ═══════════════════════════════════════════════════════════
    # PHISHING RISK ONLY
    # ═══════════════════════════════════════════════════════════

    # Lexical Pattern Analysis
    if lexical.get("long_url"):
        phishing_score += 10
        reasons.append("Suspiciously long URL")
        phishing_indicators += 1

    if lexical.get("contains_at_symbol"):
        phishing_score += 15
        reasons.append("URL contains @ symbol")
        phishing_indicators += 1

    if lexical.get("encoded_url"):
        phishing_score += 15
        reasons.append("URL contains encoding")
        phishing_indicators += 1

    if lexical.get("ip_based_url"):
        phishing_score += 35
        reasons.append("IP-based URL detected (High Phishing Risk)")
        phishing_indicators += 1

    # 🧅 TOR HIDDEN SERVICE DETECTION
    if ".onion" in static_results.get("url", ""):
        phishing_score += 40
        reasons.append("Tor (.onion) hidden service detected")
        phishing_indicators += 1

    if lexical.get("suspicious_keywords"):
        phishing_score += 15
        reasons.append("Suspicious keywords detected")
        phishing_indicators += 1

    if lexical.get("multiple_subdomains"):
        phishing_score += 15
        reasons.append("Multiple subdomains detected")
        phishing_indicators += 1

    # HTML Behavioral Analysis
    if html.get("has_password_input") and html.get("external_form_action"):
        phishing_score += 40
        reasons.append("Credential harvesting behavior detected")
        phishing_indicators += 1

    if html.get("js_obfuscation_detected"):
        phishing_score += 25
        reasons.append("Obfuscated JavaScript detected")
        phishing_indicators += 1

    # WHOIS & Domain Intelligence
    if whois.get("new_domain"):
        phishing_score += 20
        reasons.append("Recently registered domain")
        phishing_indicators += 1

    if not whois.get("whois_found", True):
        phishing_score += 10
        reasons.append("WHOIS information unavailable")
        phishing_indicators += 1

    # Brand Impersonation
    if brand.get("possible_impersonation"):
        phishing_score += 40
        reasons.append("Possible brand impersonation detected")
        phishing_indicators += 1

    # ═══════════════════════════════════════════════════════════
    # NORMALIZE SCORES
    # ═══════════════════════════════════════════════════════════
    
    transport_score = min(transport_score, 100)
    phishing_score = min(phishing_score, 100)

    # Final score is the combination, clamped to 0-100
    final_score = max(0, min(transport_score + phishing_score, 100))

    # ═══════════════════════════════════════════════════════════
    # CONFIDENCE SCORE - DATA-DRIVEN MODEL
    # ═══════════════════════════════════════════════════════════
    
    # Count available data sources
    data_sources = 6
    available_sources = 0

    # Check each source for actual data availability
    if tls:
        available_sources += 1

    if protocol:
        available_sources += 1

    if lexical:
        available_sources += 1

    if html.get("html_fetched"):
        available_sources += 1

    if whois.get("whois_found"):
        available_sources += 1

    if brand is not None:
        available_sources += 1

    # Calculate confidence as percentage of available sources
    confidence_score = int((available_sources / data_sources) * 100)

    # ═══════════════════════════════════════════════════════════
    # SEVERITY CLASSIFICATION
    # ═══════════════════════════════════════════════════════════
    
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
        "confidence_score": confidence_score,
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


