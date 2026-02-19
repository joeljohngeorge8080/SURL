import socket
import ssl
from datetime import datetime


def check_tls_certificate(domain: str) -> dict:
    """
    Performs real TLS certificate validation.

    Returns:
        {
            "https_supported": bool,
            "certificate_valid": bool,
            "expiry_date": str | None,
            "days_remaining": int | None,
            "error": str | None
        }
    """

    result = {
        "https_supported": False,
        "certificate_valid": False,
        "expiry_date": None,
        "days_remaining": None,
        "error": None
    }

    try:
        context = ssl._create_unverified_context()


        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()
                result["https_supported"] = True

                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )

                result["expiry_date"] = expiry_date.isoformat()

                days_remaining = (expiry_date - datetime.utcnow()).days
                result["days_remaining"] = days_remaining

                if days_remaining > 0:
                    result["certificate_valid"] = True
                else:
                    result["certificate_valid"] = False

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"

    except Exception as e:
        result["error"] = f"Connection Error: {str(e)}"

    return result
