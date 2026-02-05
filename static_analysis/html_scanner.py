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

    
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def html_scan(url):
    signals = {
        "html_fetched": False,
        "has_form": False,
        "has_password_input": False,
        "external_form_action": False,
        "hidden_inputs_present": False,
        "hidden_elements_present": False,
        "js_obfuscation_detected": False,
        "external_script_loaded": False
    }

    try:
        response = requests.get(url, timeout=5)
        signals["html_fetched"] = True
        html = response.text
    except Exception:
        return signals  # fail safely

    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc

    # -------- Form analysis --------
    forms = soup.find_all("form")
    if forms:
        signals["has_form"] = True

    for form in forms:
        # password field
        if form.find("input", {"type": "password"}):
            signals["has_password_input"] = True

        # form action domain
        action = form.get("action")
        if action:
            action_domain = urlparse(action).netloc
            if action_domain and action_domain != page_domain:
                signals["external_form_action"] = True

    # -------- Hidden inputs --------
    if soup.find("input", {"type": "hidden"}):
        signals["hidden_inputs_present"] = True

    # -------- Hidden elements (CSS) --------
    hidden_style = soup.find_all(
        style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)
    )
    if hidden_style:
        signals["hidden_elements_present"] = True

    # -------- JavaScript scanning --------
    scripts = soup.find_all("script")
    for script in scripts:
        script_text = script.string or ""
        if re.search(r"eval\(|document\.write\(|atob\(|btoa\(", script_text):
            signals["js_obfuscation_detected"] = True

        src = script.get("src")
        if src:
            src_domain = urlparse(src).netloc
            if src_domain and src_domain != page_domain:
                signals["external_script_loaded"] = True

    return signals


# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL to scan HTML: ")
    print(html_scan(test_url))


    
    

