KNOWN_BAD = {"malicious-example.com", "fake-login.net"}
KNOWN_GOOD = {"google.com", "microsoft.com", "amazon.com"}

def check_domain_reputation(domain):
    if domain in KNOWN_BAD:
        return "malicious"
    if domain in KNOWN_GOOD:
        return "trusted"
    return "unknown"
