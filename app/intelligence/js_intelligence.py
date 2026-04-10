import re



def analyze_javascript(
    js_content: str,
    credential_analysis: dict = None,
    external_post_detected: bool = False,

) -> dict:
    """
    Improved JavaScript intelligence.
    Reduces false positives on legitimate sites.
    """

    findings = {
        "high_risk": [],
        "medium_risk": [],
        "credential_related": [],
        "summary": ""
    }

    if credential_analysis is None:
        credential_analysis = {}

    try:
        if not js_content or not isinstance(js_content, str):
            findings["summary"] = "No JavaScript content available."
            return findings

        if len(js_content) > 1_000_000:
            findings["summary"] = "JavaScript content too large for analysis."
            return findings

        js = js_content.lower()

        credential_analysis = credential_analysis or {}
        credential_fields_detected = credential_analysis.get("credential_fields_detected", False)
        external_form_action = credential_analysis.get("external_form_action", False)
        ip_based_form_action = credential_analysis.get("ip_based_form_action", False)
        strong_credential_context = (
            credential_fields_detected
            or external_post_detected
            or external_form_action
            or ip_based_form_action
        )

        # ==========================
        # STRICT HIGH RISK DETECTION
        # ==========================

        # Only high risk if eval(atob(...)) pattern exists
        if re.search(r"eval\s*\(\s*atob\s*\(", js):
            findings["high_risk"].append("eval_atob_execution")

        # Base64 long string executed inside eval
        if re.search(r'eval\s*\(\s*["\'][a-z0-9+/=]{100,}["\']\s*\)', js):
            findings["high_risk"].append("long_base64_eval")

        # External script injection
        if re.search(
            r'createelement\s*\(\s*["\']script["\']\).*src\s*=\s*["\']https?://',
            js
        ):
            findings["high_risk"].append("external_script_injection")

        # ==========================
        # CREDENTIAL RELATED
        # ==========================

        if re.search(r'addeventlistener\s*\(\s*["\']submit', js):
            findings["credential_related"].append("form_submit_listener")

        # If the caller already detected external POST exfiltration, flag it.
        external_post_pattern = re.findall(
            r"(?:fetch|axios\.post)\s*\(\s*[\"'](https?://[^\"']+)[\"']",
            js,
        )
        if external_post_detected and external_post_pattern:
            findings["credential_related"].append("external_post_submission")

        # Only detect password-field references when the DOM actually includes password inputs.
        if (
            credential_analysis.get("credential_fields_detected", False)
            and re.search(r"queryselector.*password", js)
        ):
            findings["credential_related"].append("password_field_reference")

        if findings["credential_related"] and not strong_credential_context:
            findings["credential_related"] = []
            findings["medium_risk"].append("credential_like_script_behavior")

        # ==========================
        # MEDIUM RISK
        # ==========================

        if re.search(r'window\.location\s*=\s*["\']https?://', js):
            findings["medium_risk"].append("window_redirect")

        if re.search(r"settimeout\s*\(", js):
            findings["medium_risk"].append("timeout_redirect")

        if re.search(
            r'createelement\s*\(\s*["\']script["\']',
            js
        ) and "external_script_injection" not in findings["high_risk"]:
            findings["medium_risk"].append("dynamic_script_injection")

        # JS engine must not independently escalate credential behavior.
        if findings["credential_related"] and not credential_analysis.get("credential_fields_detected", False):
            findings["medium_risk"].append("credential_like_script_behavior")

        # ==========================
        # SUMMARY
        # ==========================

        if findings["high_risk"]:
            findings["summary"] = "High-risk encoded script execution detected."
        elif findings["medium_risk"]:
            findings["summary"] = "Moderate dynamic script behavior observed."
        else:
            findings["summary"] = "No suspicious script patterns detected."

        return findings

    except Exception:
        return {
            "high_risk": [],
            "medium_risk": [],
            "credential_related": [],
            "summary": "JavaScript analysis failed safely."
        }
