import dns.resolver
from urllib.parse import urlparse
import ipaddress


def dns_check(url):
    """
    Performs DNS-based analysis of a domain.
    Extracts infrastructure-related signals.
    """

    signals = {
        "dns_resolves": False,
        "multiple_ip_addresses": False,
        "private_ip_detected": False,
        "mx_record_present": False,
        "ttl_low": False
    }

    try:
        domain = urlparse(url).hostname
        if not domain:
            return signals

        # ---- A record lookup ----
        answers = dns.resolver.resolve(domain, "A")
        signals["dns_resolves"] = True

        ip_list = []

        for answer in answers:
            ip = answer.address
            ip_list.append(ip)

            # Check private IP
            if ipaddress.ip_address(ip).is_private:
                signals["private_ip_detected"] = True

        # Multiple IPs (fast-flux indicator)
        if len(ip_list) > 1:
            signals["multiple_ip_addresses"] = True

        # TTL check (low TTL is suspicious)
        if answers.rrset.ttl < 300:
            signals["ttl_low"] = True

        # ---- MX record lookup ----
        try:
            dns.resolver.resolve(domain, "MX")
            signals["mx_record_present"] = True
        except Exception:
            signals["mx_record_present"] = False

    except Exception:
        # Fail safely
        return signals

    return signals


# ---- local testing ----
if __name__ == "__main__":
    test_url = input("Enter URL for DNS check: ")
    print(dns_check(test_url))
