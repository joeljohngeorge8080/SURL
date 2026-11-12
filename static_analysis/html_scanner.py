# import webbrowser
# def url_go(url:str):
#     url="https://www.google.com"
#     webbrowser.open_new_tab(url)
#     webbrowser.open(url)
    
# link=input("Enter the link : ")

# if link[0:8]!="https://":
#     linkf="https://"
#     for ch in link:
#         linkf+=ch
#     url_go(linkf)
# else:
#     url_go(link)

    
import re
import warnings
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

from static_analysis.net_guard import is_private_ip, registered_domain

MAX_REDIRECTS = 5
FETCH_TIMEOUT = 5


class BlockedRedirect(Exception):
    """A redirect pointed at a non-public address or a non-HTTP scheme."""


def _get(url):
    """One hop, no automatic redirects. Falls back to verify=False on a bad
    certificate: TLS validity is scored separately by tls_checker, and phishing
    pages with broken certificates still need their HTML inspected."""
    try:
        return requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False)
    except requests.exceptions.SSLError:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False, verify=False)


def _fetch(url):
    """Follow redirects by hand so every hop is checked against the SSRF guard
    (the submitted URL is checked by the caller). Returns (response, final_url)."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        response = _get(current)
        location = response.headers.get("Location") if response.is_redirect else None
        if not location:
            return response, current
        nxt = urljoin(current, location)
        if urlparse(nxt).scheme not in ("http", "https") or is_private_ip(nxt):
            raise BlockedRedirect(nxt)
        current = nxt
    raise requests.exceptions.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects")


def _host(url):
    return (urlparse(url).hostname or "").lower()


def html_scan(url):
    """
    Performs static HTML inspection to detect phishing-related indicators.
    Does NOT execute JavaScript or render the page.
    Returns structured signals only.
    """

    signals = {
        "html_fetched": False,
        "has_form": False,
        "has_password_input": False,
        "external_form_action": False,
        "hidden_inputs_present": False,
        "hidden_elements_present": False,
        "js_obfuscation_detected": False,
        "external_script_loaded": False,
        "blocked_redirect": False,
    }

    # ---- Fetch HTML safely ----
    try:
        response, final_url = _fetch(url)
        html = response.text
        signals["html_fetched"] = True
    except BlockedRedirect:
        signals["blocked_redirect"] = True
        return signals
    except Exception:
        # Fail safely – no crash, no verdict
        return signals

    soup = BeautifulSoup(html, "html.parser")
    # Compare registered domains of the page we actually landed on, so
    # example.com -> www.example.com is not mistaken for an external target.
    page_domain = registered_domain(_host(final_url))

    # ---- Form analysis ----
    forms = soup.find_all("form")
    if forms:
        signals["has_form"] = True

    for form in forms:
        # Detect password field
        if form.find("input", {"type": "password"}):
            signals["has_password_input"] = True

        # Detect external form action
        action = form.get("action")
        if action:
            action_host = _host(urljoin(final_url, action))
            if action_host and registered_domain(action_host) != page_domain:
                signals["external_form_action"] = True

    # ---- Hidden inputs ----
    if soup.find("input", {"type": "hidden"}):
        signals["hidden_inputs_present"] = True

    # ---- Hidden elements via CSS ----
    hidden_elements = soup.find_all(
        style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)
    )
    if hidden_elements:
        signals["hidden_elements_present"] = True

    # ---- Static JavaScript inspection ----
    scripts = soup.find_all("script")
    for script in scripts:
        script_text = script.string or ""

        # Obfuscation patterns
        if re.search(r"eval\(|document\.write\(|atob\(|btoa\(", script_text):
            signals["js_obfuscation_detected"] = True

        # External script loading
        src = script.get("src")
        if src:
            src_host = _host(urljoin(final_url, src))
            if src_host and registered_domain(src_host) != page_domain:
                signals["external_script_loaded"] = True
    

    return signals




# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL to scan HTML: ")
    print(html_scan(test_url))


    
    

