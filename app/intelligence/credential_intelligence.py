# app/intelligence/credential_intelligence.py

from urllib.parse import urlparse
import tldextract


def extract_root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain


async def analyze_credentials(page, original_url: str) -> dict:
    """
    Deep credential harvesting detection.
    """

    results = {
        "credential_fields_detected": False,
        "external_form_action": False,
        "ip_based_form_action": False,
        "hidden_inputs_detected": False,
        "autofocus_password": False,
    }

    original_root = extract_root_domain(original_url)

    forms = await page.query_selector_all("form")

    for form in forms:

        inputs = await form.query_selector_all("input")

        for input_tag in inputs:
            input_type = await input_tag.get_attribute("type")
            input_name = await input_tag.get_attribute("name")
            autofocus = await input_tag.get_attribute("autofocus")

            if input_type and input_type.lower() == "password":
                results["credential_fields_detected"] = True

                if autofocus is not None:
                    results["autofocus_password"] = True

            if input_type and input_type.lower() == "hidden":
                results["hidden_inputs_detected"] = True

        action = await form.get_attribute("action")

        if action:
            parsed = urlparse(action)
            if parsed.hostname:
                action_root = extract_root_domain(action)

                if action_root != original_root:
                    results["external_form_action"] = True

                # Detect IP-based form submission
                try:
                    import ipaddress
                    ipaddress.ip_address(parsed.hostname)
                    results["ip_based_form_action"] = True
                except Exception:
                    pass

    return results
