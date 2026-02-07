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
