from static_analysis.protocol_check import http_checker
from static_analysis.lexical_analyzer import lexical_analysis
from static_analysis.html_scanner import html_scan
from static_analysis.tls_checker import tls_check
from static_analysis.whois_checker import whois_check
from static_analysis.brand_detector import brand_check

from static_analysis.url_normalizer import normalize_url

def run_static_analysis(url):
    normalized = normalize_url(url)
    final_url = normalized["normalized_url"]

    results = {
        "url": final_url,
        "protocol_check": http_checker(final_url),
        "lexical_analysis": lexical_analysis(final_url),
        "html_analysis": html_scan(final_url),
        "tls_analysis": tls_check(final_url),
        "whois_analysis": whois_check(final_url),
        "brand_analysis": brand_check(final_url),
        "url_metadata": normalized
    }

    return results



# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Enter URL to run static analysis: ")
    output = run_static_analysis(test_url)

    print("\n===== STATIC ANALYSIS RESULTS =====\n")
    for module, result in output.items():
        print(f"{module}:")
        print(result)
        print()
