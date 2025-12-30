import re

def lexical_analysis(url):
    """
    Performs lexical (string-based) analysis on a URL.
    No network calls. No browser. Regex-only checks.
    Returns signals for the scoring engine.
    """

    signals = {}

    # 1. URL length check
    signals["long_url"] = len(url) > 75

    # 2. '@' symbol check
    signals["contains_at_symbol"] = bool(re.search(r"@", url))

    # 3. Encoded characters check (%xx)
    signals["encoded_url"] = bool(re.search(r"%[0-9A-Fa-f]{2}", url))

    # 4. IP-based URL check
    signals["ip_based_url"] = bool(
        re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url)
    )

    # 5. Suspicious keywords
    signals["suspicious_keywords"] = bool(
        re.search(
            r"(login|verify|update|secure|bank|account|signin|password)",
            url,
            re.IGNORECASE
        )
    )

    # 6. Multiple subdomains (3 or more dots before TLD)
    signals["multiple_subdomains"] = bool(
        re.search(r"https?://([a-zA-Z0-9-]+\.){3,}", url)
    )

    return signals


# ---- local testing only ----
if __name__ == "__main__":
    test_url = input("Paste URL: ")
    print(lexical_analysis(test_url))


# example urls to check
# 1 https://www.google.com   --> Normal
# 2 https://example.com/%6C%6F%67%69%6E  -->Encoded Url
# 3 https://example.com@google.com  --> Usage of @
# 4 http://192.168.1.100/login     -->Ip based
# 5 https://secure-login-account-update.com  -->Suspcious_keyword
# 6 https://login.secure.verify.account.example.com --> Multiple subdomain
# 7 https://example.com/this/is/a/very/long/url/that/keeps/going/on/and/on/and/on/for/no-good-reason --> Long Url
# 8 http://192.168.0.10/%6C%6F%67%69%6E@secure.bank.verify.example.com -->Combination Url


# All url are checked 