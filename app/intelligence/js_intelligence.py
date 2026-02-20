import re


def analyze_javascript(js_content: str) -> dict:
    findings = {
        "high_risk": [],
        "medium_risk": [],
        "credential_related": [],
        "summary": ""
    }

    if not js_content:
        findings["summary"] = "No JavaScript content available."
        return findings

    window_redirect = bool(re.search(r"window\.location", js_content))
    timeout_redirect = bool(re.search(r"setTimeout\s*\(", js_content))
    dynamic_script = bool(re.search(r"createElement\s*\(\s*['\"]script", js_content))

    password_listener = bool(re.search(r"querySelector.*password", js_content))
    form_submit_listener = bool(re.search(r"addEventListener\s*\(\s*['\"]submit", js_content))
    fetch_post = bool(re.search(r"fetch\s*\(.*method\s*:\s*['\"]POST", js_content))
    axios_post = bool(re.search(r"axios\.post", js_content))

    # -------------------------
    # High Risk Logic (STRICT)
    # -------------------------
    encoded_exec_pattern = r"(eval|Function)\s*\(\s*atob\s*\(\s*['\"][A-Za-z0-9+/=]{200,}['\"]\s*\)\s*\)"

    if re.search(encoded_exec_pattern, js_content):
        findings["high_risk"].append("encoded_eval_execution")

    # -------------------------
    # Credential Logic
    # -------------------------

    if password_listener or form_submit_listener:
        findings["credential_related"].append("credential_event_listener")

    if fetch_post or axios_post:
        findings["credential_related"].append("network_submission_logic")

    # -------------------------
    # Medium Behavior
    # -------------------------

    if window_redirect:
        findings["medium_risk"].append("window_redirect")

    if timeout_redirect:
        findings["medium_risk"].append("timeout_redirect")

    if dynamic_script:
        findings["medium_risk"].append("dynamic_script_injection")

    # -------------------------
    # Summary
    # -------------------------

    if findings["high_risk"]:
        findings["summary"] = "High-risk encoded script execution detected."
    elif findings["credential_related"]:
        findings["summary"] = "Credential-handling JavaScript behavior detected."
    elif findings["medium_risk"]:
        findings["summary"] = "Moderate dynamic script behavior observed."
    else:
        findings["summary"] = "No suspicious script patterns detected."

    return findings
