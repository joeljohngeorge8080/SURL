import whois
from urllib.parse import urlparse
from datetime import datetime


def _extract_domain(value: str) -> str:
    """Return a normalized domain from either a URL or a raw hostname."""
    if not value:
        return ""

    cleaned_value = "".join(value.strip().split()).lower()
    if not cleaned_value:
        return ""

    candidate = cleaned_value
    if "://" not in cleaned_value:
        candidate = f"http://{cleaned_value}"

    parsed = urlparse(candidate)
    domain = parsed.hostname or parsed.netloc or cleaned_value

    if domain.startswith("www."):
        domain = domain[4:]

    return domain.strip(".")


def whois_check(url):
    """
    Performs WHOIS analysis on the domain.
    Returns domain age and registration signals.
    """

    signals = {
        "whois_found": False,
        "domain_age_days": None,
        "new_domain": False,
        "registrar": None
    }

    try:
        domain = _extract_domain(url)
        if not domain:
            return signals

        w = whois.whois(domain)
        signals["whois_found"] = True

        # Registrar
        signals["registrar"] = w.registrar

        # Creation date handling
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            signals["domain_age_days"] = age_days

            if age_days < 30:
                signals["new_domain"] = True

    except Exception:
        # Fail safely – WHOIS often fails
        return signals

    return signals


# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL for WHOIS check: ")
    print(whois_check(test_url))
