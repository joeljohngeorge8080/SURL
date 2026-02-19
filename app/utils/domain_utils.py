# app/utils/domain_utils.py

from urllib.parse import urlparse

def extract_root_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    parts = hostname.split(".")
    
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    
    return hostname
