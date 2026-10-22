import re
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    # Only scheme and host are case-insensitive; path and query must keep
    # their case or the fetched page is not the one the user submitted.
    parts = urlsplit(url)
    return urlunsplit(parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()))


def validate_domain(url: str) -> bool:
    """
    Ensures valid domain format:
    example.com
    example.co.in
    example.onion
    """

    pattern = re.compile(
        r"^(https?://)?"
        r"([a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return bool(pattern.match(url))
