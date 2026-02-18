import hashlib


def generate_pbh_fingerprint(static_results):
    """
    Generates a behavioral fingerprint based on
    detected security patterns.
    """

    protocol = static_results.get("protocol_check", {})
    tls = static_results.get("tls_analysis", {})
    lexical = static_results.get("lexical_analysis", {})
    html = static_results.get("html_analysis", {})
    whois = static_results.get("whois_analysis", {})
    brand = static_results.get("brand_analysis", {})

    # --------------------------
    # Convert behaviors to bits
    # --------------------------

    feature_bits = []

    # 1. No HTTPS
    feature_bits.append(1 if not protocol.get("uses_https", True) else 0)

    # 2. Self-signed certificate
    feature_bits.append(1 if tls.get("self_signed_cert") else 0)

    # 3. TLS domain mismatch
    feature_bits.append(1 if tls.get("domain_mismatch") else 0)

    # 4. Recently registered domain
    feature_bits.append(1 if whois.get("new_domain") else 0)

    # 5. Suspicious lexical patterns
    suspicious_lexical = any([
        lexical.get("long_url"),
        lexical.get("contains_at_symbol"),
        lexical.get("encoded_url"),
        lexical.get("ip_based_url"),
        lexical.get("suspicious_keywords"),
        lexical.get("multiple_subdomains"),
    ])
    feature_bits.append(1 if suspicious_lexical else 0)

    # 6. Password input present
    feature_bits.append(1 if html.get("has_password_input") else 0)

    # 7. External form submission
    feature_bits.append(1 if html.get("external_form_action") else 0)

    # 8. JavaScript obfuscation
    feature_bits.append(1 if html.get("js_obfuscation_detected") else 0)

    # 9. Brand impersonation
    feature_bits.append(1 if brand.get("possible_impersonation") else 0)

    # --------------------------
    # Convert to binary string
    # --------------------------

    binary_pattern = "".join(str(bit) for bit in feature_bits)

    # --------------------------
    # Hash the pattern
    # --------------------------

    fingerprint = hashlib.sha256(binary_pattern.encode()).hexdigest()

    return {
        "binary_pattern": binary_pattern,
        "fingerprint": fingerprint
    }
