import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


def tls_check(url):
    """
    Performs TLS certificate inspection for HTTPS URLs.
    Extracts certificate-related trust signals.
    """

    signals = {
        "tls_supported": False,
        "certificate_valid": False,
        "self_signed_cert": False,
        "domain_mismatch": False,
        "cert_expiry_days": None,
        "issuer": None
    }

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return signals

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                signals["tls_supported"] = True

                cert = ssock.getpeercert()

        # ---- Certificate fields ----
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        signals["issuer"] = issuer.get("organizationName")

        # Self-signed check
        if issuer == subject:
            signals["self_signed_cert"] = True

        # Domain mismatch
        common_name = subject.get("commonName")
        if common_name and hostname not in common_name:
            signals["domain_mismatch"] = True

        # Expiry check
        expiry_str = cert.get("notAfter")
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days

        signals["cert_expiry_days"] = days_left

        if days_left > 0:
            signals["certificate_valid"] = True

    except Exception:
        # Fail safely
        return signals

    return signals


# ---- local testing ----
if __name__ == "__main__":
    test_url = input("Enter HTTPS URL for TLS check: ")
    print(tls_check(test_url))
