from protocol_check import http_checker
from lexical_analyzer import lexical_analysis
from html_scanner import html_scan
from tls_checker import tls_check
from whois_checker import whois_check
from brand_detector import brand_check


def run_static_analysis(url):
    """
    Runs all static analysis modules on a single URL
    and returns combined results.
    """

    results = {
        "url": url,
        "protocol_check": http_checker(url),
        "lexical_analysis": lexical_analysis(url),
        "html_analysis": html_scan(url),
        "tls_analysis": tls_check(url),
        "whois_analysis": whois_check(url),
        "brand_analysis": brand_check(url)
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
