import re


def analyze_javascript(js_content: str) -> dict:
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

    try:
        if not js_content or not isinstance(js_content, str):
            findings["summary"] = "No JavaScript content available."
            return findings

        if len(js_content) > 1_000_000:
            findings["summary"] = "JavaScript content too large for analysis."
            return findings

        js = js_content.lower()

        # ==========================
        # STRICT HIGH RISK DETECTION
        # ==========================

        # Only high risk if eval(atob(...)) pattern exists
        if re.search(r"eval\s*\(\s*atob\s*\(", js):
            findings["high_risk"].append("eval_atob_execution")

        # Base64 long string executed inside eval
        if re.search(r"eval\s*\(\s*['\"][a-z0-9+/=]{100,}['\"]\s*\)", js):
            findings["high_risk"].append("long_base64_eval")

        # External script injection
        if re.search(
            r"createelement\s*\(\s*['\"]script['\"]\).*src\s*=\s*['\"]https?://",
            js
        ):
            findings["high_risk"].append("external_script_injection")

        # ==========================
        # CREDENTIAL RELATED
        # ==========================

        if re.search(r"addeventlistener\s*\(\s*['\"]submit", js):
            findings["credential_related"].append("form_submit_listener")

        if re.search(r"fetch\s*\(.*method\s*:\s*['\"]post", js):
            findings["credential_related"].append("fetch_post_submission")

        if re.search(r"axios\.post", js):
            findings["credential_related"].append("axios_post_submission")

        if re.search(r"queryselector.*password", js):
            findings["credential_related"].append("password_field_reference")

        # ==========================
        # MEDIUM RISK
        # ==========================

        if re.search(r"window\.location\s*=\s*['\"]https?://", js):
            findings["medium_risk"].append("window_redirect")

        if re.search(r"settimeout\s*\(", js):
            findings["medium_risk"].append("timeout_redirect")

        if re.search(
            r"createelement\s*\(\s*['\"]script['\"]",
            js
        ) and "external_script_injection" not in findings["high_risk"]:
            findings["medium_risk"].append("dynamic_script_injection")

        # ==========================
        # SUMMARY
        # ==========================

        if findings["high_risk"]:
            findings["summary"] = "High-risk encoded script execution detected."
        elif findings["credential_related"]:
            findings["summary"] = "Credential-handling JavaScript behavior detected."
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