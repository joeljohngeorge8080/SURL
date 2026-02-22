# app/intelligence/credential_intelligence.py

from urllib.parse import urlparse
import tldextract
import ipaddress


def extract_root_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return ""


async def analyze_credentials(page, original_url: str) -> dict:
    """
    Safe credential harvesting detection.
    Never raises exception.
    """

    results = {
        "credential_fields_detected": False,
        "external_form_action": False,
        "ip_based_form_action": False,
        "hidden_inputs_detected": False,
        "autofocus_password": False,
    }

    try:
        original_root = extract_root_domain(original_url)

        try:
            forms = await page.query_selector_all("form")
        except Exception:
            forms = []

        for form in forms:

            try:
                inputs = await form.query_selector_all("input")
            except Exception:
                continue

            password_found = False
            hidden_found = False

            for input_tag in inputs:
                try:
                    input_type = await input_tag.get_attribute("type")
                    autofocus = await input_tag.get_attribute("autofocus")
                except Exception:
                    continue

                if input_type:
                    input_type = input_type.lower()

                    if input_type == "password":
                        results["credential_fields_detected"] = True
                        password_found = True

                        if autofocus is not None:
                            results["autofocus_password"] = True

                    if input_type == "hidden":
                        hidden_found = True

            # Only mark hidden inputs if password exists in same form
            if password_found and hidden_found:
                results["hidden_inputs_detected"] = True

            # ==========================
            # FORM ACTION ANALYSIS
            # ==========================
            try:
                action = await form.get_attribute("action")
            except Exception:
                action = None

            if action:
                try:
                    parsed = urlparse(action)

                    if parsed.hostname:
                        action_root = extract_root_domain(action)

                        if action_root and action_root != original_root:
                            results["external_form_action"] = True

                        # IP-based submission detection
                        try:
                            ipaddress.ip_address(parsed.hostname)
                            results["ip_based_form_action"] = True
                        except Exception:
                            pass

                except Exception:
                    pass

        return results

    except Exception:
        # Absolute safety net
        return {
            "credential_fields_detected": False,
            "external_form_action": False,
            "ip_based_form_action": False,
            "hidden_inputs_detected": False,
            "autofocus_password": False,
        }