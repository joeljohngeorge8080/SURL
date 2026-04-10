import re


def normalize_url(url: str) -> str:
    url = url.strip().lower()

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
        r"^(https?://)?"
        r"([a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return bool(pattern.match(url))
