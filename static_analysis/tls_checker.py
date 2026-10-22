import socket
import ssl
from datetime import datetime

# OpenSSL X509_V_ERR_* codes
SELF_SIGNED_VERIFY_CODES = {18, 19}   # DEPTH_ZERO_SELF_SIGNED_CERT, SELF_SIGNED_CERT_IN_CHAIN
HOSTNAME_MISMATCH_VERIFY_CODE = 62    # HOSTNAME_MISMATCH


def check_tls_certificate(domain: str) -> dict:

    result = {
        "https_supported": False,
        "certificate_valid": False,
        "expiry_date": None,
        "days_remaining": None,
        "self_signed_cert": False,
        "domain_mismatch": False,
        "error": None
    }

    try:
        # STRICT CONTEXT (real verification)
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                result["https_supported"] = True
                result["certificate_valid"] = True

                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )

                result["expiry_date"] = expiry_date.isoformat()
                result["days_remaining"] = (
                    expiry_date - datetime.utcnow()
                ).days

    except ssl.SSLCertVerificationError as e:
        # ssl.CertificateError is an alias of this class, so the specific
        # failure has to be read from OpenSSL's verify code.
        result["https_supported"] = True
        result["certificate_valid"] = False
        result["error"] = str(e)

        if e.verify_code in SELF_SIGNED_VERIFY_CODES:
            result["self_signed_cert"] = True
        elif e.verify_code == HOSTNAME_MISMATCH_VERIFY_CODE:
            result["domain_mismatch"] = True

    except Exception as e:
        result["error"] = str(e)

    return result
