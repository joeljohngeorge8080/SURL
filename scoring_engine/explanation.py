def generate_explanation(static_results, score_result):
    """
    Generates professional, structured security report explanation.
    """

    detailed_analysis = []

    for item in score_result.get("reasons", []):

        explanation_block = {
            "indicator": item,
            "severity": score_result.get("severity"),
            "report_paragraph": "",
            "remediation_strategy": "",
            "verification_strategy": ""
        }

        # Map indicators to detailed explanations
        if "HTTPS" in item or "not use HTTPS" in item:
            explanation_block["report_paragraph"] = (
                "The analyzed URL does not enforce HTTPS encryption. "
                "This exposes communications to potential interception via "
                "Man-in-the-Middle (MITM) attacks, allowing attackers to "
                "read or modify sensitive user data in transit."
            )
            explanation_block["remediation_strategy"] = (
                "Deploy a valid TLS certificate from a trusted Certificate Authority. "
                "Configure the web server to enforce HTTPS redirection and enable HSTS (HTTP Strict Transport Security)."
            )
            explanation_block["verification_strategy"] = (
                "Verify HTTPS deployment using a browser's certificate inspector or "
                "test the configuration using SSL Labs (ssllabs.com) for detailed analysis."
            )

        elif "TLS" in item or "self-signed" in item.lower():
            explanation_block["report_paragraph"] = (
                "The site either does not support TLS properly or uses a self-signed certificate. "
                "Self-signed certificates lack verification from a trusted authority, "
                "making them susceptible to impersonation attacks and spoofing."
            )
            explanation_block["remediation_strategy"] = (
                "Obtain a certificate from a recognized Certificate Authority (CA). "
                "Configure the web server with the proper certificate chain and ensure all intermediate certificates are installed."
            )
            explanation_block["verification_strategy"] = (
                "Use certificate checking tools to verify the certificate chain is complete. "
                "Test using online validators like Qualys SSL Labs or your browser's certificate inspector."
            )

        elif "certificate" in item.lower() and "mismatch" in item.lower():
            explanation_block["report_paragraph"] = (
                "The TLS certificate domain name does not match the requested URL. "
                "This mismatch indicates a potential domain spoofing or misconfiguration issue, "
                "allowing attackers to intercept encrypted communications."
            )
            explanation_block["remediation_strategy"] = (
                "Obtain a certificate that matches the domain name or use a wildcard/SAN certificate. "
                "Ensure the certificate Common Name (CN) or Subject Alternative Names (SANs) include the correct domain."
            )
            explanation_block["verification_strategy"] = (
                "Inspect the certificate in your browser to verify the domain matches. "
                "Use openssl or online tools to validate certificate details."
            )

        elif "credential" in item.lower() or "password" in item.lower() or "external form" in item.lower():
            explanation_block["report_paragraph"] = (
                "The website contains a credential input form that submits data to an external domain. "
                "This is a common phishing technique where legitimate-looking forms steal credentials "
                "by forwarding them to attacker-controlled servers."
            )
            explanation_block["remediation_strategy"] = (
                "Ensure all forms submit to the same domain as the website. "
                "Implement server-side validation and use CSRF tokens to prevent form hijacking."
            )
            explanation_block["verification_strategy"] = (
                "Inspect form elements using browser developer tools to verify the form action attribute. "
                "Test form submission and verify destination server logs."
            )

        elif "obfuscation" in item.lower() or "JavaScript" in item:
            explanation_block["report_paragraph"] = (
                "Obfuscated or heavily minified JavaScript code was detected on the page. "
                "While minification is normal, obfuscation is often used to hide malicious code execution, "
                "tracking scripts, or credential harvesting logic from detection."
            )
            explanation_block["remediation_strategy"] = (
                "Use only necessary JavaScript from trusted sources. "
                "Implement Content Security Policy (CSP) headers to restrict script execution. "
                "Regularly audit third-party scripts for malicious behavior."
            )
            explanation_block["verification_strategy"] = (
                "Use browser developer tools to inspect JavaScript sources. "
                "Analyze network requests to identify external script sources using tools like Charles Proxy or Fiddler."
            )

        elif "recently" in item.lower() or "domain was registered" in item.lower():
            explanation_block["report_paragraph"] = (
                "The domain was registered recently. "
                "New domains are frequently associated with phishing campaign infrastructure, "
                "malware distribution, and short-lived malicious operations designed to evade reputation systems."
            )
            explanation_block["remediation_strategy"] = (
                "Verify the domain owner's legitimacy through official channels. "
                "Cross-reference with known legitimate organizations before entering sensitive information."
            )
            explanation_block["verification_strategy"] = (
                "Check WHOIS data to confirm registration date and domain owner details. "
                "Validate domain reputation using VirusTotal, URLhaus, or similar threat intelligence platforms."
            )

        elif "HTML" in item or "fetched" in item.lower() or "could not be fetched" in item.lower():
            explanation_block["report_paragraph"] = (
                "The website content could not be retrieved or analyzed. "
                "This is common for malicious domains that are offline, blocked, or actively evading analysis. "
                "Some phishing sites disable content delivery to automated security scanners."
            )
            explanation_block["remediation_strategy"] = (
                "Attempt manual inspection in a controlled environment. "
                "Check if the domain is blocked by your network or security provider."
            )
            explanation_block["verification_strategy"] = (
                "Verify domain accessibility from your location. "
                "Use proxy services or VPNs to test from different geographic locations."
            )

        elif "WHOIS" in item or "could not be retrieved" in item.lower():
            explanation_block["report_paragraph"] = (
                "WHOIS information for this domain could not be retrieved. "
                "Missing or hidden WHOIS data indicates privacy protection or registration through privacy services, "
                "which is common for phishing and malicious domains."
            )
            explanation_block["remediation_strategy"] = (
                "Use alternative domain lookup services. "
                "Check domain age and reputation through threat intelligence feeds even without WHOIS data."
            )
            explanation_block["verification_strategy"] = (
                "Query multiple WHOIS servers and DNS databases. "
                "Cross-reference with DNS records and certificate transparency logs."
            )

        elif "trust indicator" in item.lower() or "lacks basic trust" in item.lower():
            explanation_block["report_paragraph"] = (
                "The site lacks basic trust indicators such as valid TLS certificate, sufficient domain age, "
                "or accessible content. This combination of missing security signals significantly increases "
                "the likelihood of malicious intent."
            )
            explanation_block["remediation_strategy"] = (
                "If this is your legitimate site, obtain a valid TLS certificate, establish domain history, "
                "and ensure proper server configuration. If assessing a suspicious site, avoid interaction."
            )
            explanation_block["verification_strategy"] = (
                "Perform comprehensive domain and server assessment. "
                "Review DNS records, certificate history, and historical web content via the Wayback Machine."
            )

        elif "impersonation" in item.lower():
            explanation_block["report_paragraph"] = (
                "The domain or content shows signs of brand impersonation. "
                "Attackers create lookalike domains and websites mimicking legitimate brands to deceive users "
                "into providing credentials or personal information."
            )
            explanation_block["remediation_strategy"] = (
                "If you represent the impersonated brand, report the domain to the brand owner and relevant authorities. "
                "Use domain takedown services and work with law enforcement if necessary."
            )
            explanation_block["verification_strategy"] = (
                "Compare the suspected site against the official brand website. "
                "Check domain registration details and verify with the brand owner."
            )

        elif "suspicious" in item.lower() or "lexical" in item.lower():
            explanation_block["report_paragraph"] = (
                "The URL contains suspicious patterns such as excessive subdomains, encoded characters, IP addresses, "
                "or suspicious keywords. These indicators are commonly used in phishing URLs to obfuscate the true destination."
            )
            explanation_block["remediation_strategy"] = (
                "Exercise caution when visiting URLs with unusual patterns. "
                "Verify URLs directly from official sources rather than clicking links in emails or messages."
            )
            explanation_block["verification_strategy"] = (
                "Analyze the URL structure for encoded characters or suspicious subdomains. "
                "Use URL analysis tools to decode and examine the URL components."
            )

        else:
            explanation_block["report_paragraph"] = (
                "The static analysis engine identified a risk indicator associated with phishing or malicious behavior patterns. "
                "While not definitive alone, combined indicators elevate overall threat probability. "
                f"Specific indicator: {item}"
            )
            explanation_block["remediation_strategy"] = (
                "Review the identified indicator carefully and cross-reference with threat intelligence sources. "
                "Apply appropriate security controls based on the specific risk identified."
            )
            explanation_block["verification_strategy"] = (
                "Re-run the SURL scan after remediation and validate changes. "
                "Monitor for similar patterns in future security assessments."
            )

        detailed_analysis.append(explanation_block)

    # If no reasons, provide general guidance
    if not detailed_analysis:
        detailed_analysis.append({
            "indicator": "No specific threats detected",
            "severity": score_result.get("severity"),
            "report_paragraph": (
                "The static analysis did not identify specific threat indicators. "
                "The URL appears to meet basic security standards."
            ),
            "remediation_strategy": (
                "Continue to monitor for emerging threats and keep the website updated with security patches."
            ),
            "verification_strategy": (
                "Perform periodic security assessments and vulnerability scanning."
            )
        })

    # Executive Summary
    executive_summary = (
        f"The analyzed URL received a risk score of {score_result.get('risk_score')} "
        f"with a severity classification of {score_result.get('severity')}. "
        "The evaluation was performed using static inspection, certificate validation, "
        "domain intelligence correlation, and heuristic rule-based scoring. "
        "The combined findings indicate the presence of one or more "
        "security risk indicators affecting the overall trust posture. "
        "This assessment should be combined with user awareness and additional dynamic analysis for comprehensive threat detection."
    )

    return {
        "executive_summary": executive_summary,
        "detailed_analysis": detailed_analysis
    }
