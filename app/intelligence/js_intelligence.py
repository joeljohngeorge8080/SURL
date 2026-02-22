import re
from urllib.parse import urlparse


def _extract_root_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip(".")
        if not hostname:
            return ""

        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def _is_external_url(target_url: str, original_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.hostname:
            return False

        target_root = _extract_root_domain(target_url)
        original_root = _extract_root_domain(original_url)

        return bool(target_root and original_root and target_root != original_root)
    except Exception:
        return False


def analyze_javascript(
    js_content: str,
    credential_analysis: dict = None,
    original_url: str = "",
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

        # Only credential signal if POST target appears external to the analyzed page domain.
        external_post_pattern = re.findall(
            r'(?:fetch|axios\.post)\s*\(\s*["\'](https?://[^"\']+)["\']',
            js,
        )
        if any(_is_external_url(target, original_url) for target in external_post_pattern):
            findings["credential_related"].append("external_post_submission")

        # Only detect password-field references when the DOM actually includes password inputs.
        if (
            credential_analysis.get("credential_fields_detected", False)
            and re.search(r"queryselector.*password", js)
        ):
            findings["credential_related"].append("password_field_reference")

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
