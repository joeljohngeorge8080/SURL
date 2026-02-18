from urllib.parse import urlparse

def normalize_url(url):
    """
    Ensures the URL has a scheme and is in a standard format.
    """

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    return {
        "original": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "normalized_url": url
    }
import re

def normalize_url(url: str) -> str:
    url = url.strip().lower()

    # Add https if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def validate_domain(url: str) -> bool:
    """
    Ensures valid domain format:
    example.com
    example.co.in
    example.onion
    """

    pattern = re.compile(
        r"^(https?:\/\/)?"
        r"([a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return bool(pattern.match(url))
