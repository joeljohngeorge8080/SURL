"""
Network guards shared by the static and dynamic analysers.

Lives in static_analysis (the lowest layer) so html_scanner and the sandbox
runner can use it without importing app.services.scan_orchestrator, which
imports both of them.
"""
import ipaddress
import logging
import socket
from functools import lru_cache
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger("SURL")  # configured by app.core.logger

# Bundled public-suffix snapshot only: never fetch the list over the network
# at scan time (deterministic, and works behind the egress firewall). No disk
# cache either: the container user has no writable home directory.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def is_private_ip(url: str) -> bool:
    """
    True if the URL points at, or resolves to, a non-public address
    (RFC1918, loopback, link-local/cloud metadata, 0.0.0.0, ...).
    """
    try:
        host = urlparse(url).hostname
        if not host:
            return False

        try:
            return not ipaddress.ip_address(host).is_global
        except ValueError:
            pass  # not an IP literal

        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False

        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if not ip.is_global:
                return True
        return False

    except Exception as e:
        logger.warning(f"Private IP check failed: {str(e)}")
        return False


@lru_cache(maxsize=1024)
def split_host(host: str):
    """Return (subdomain, domain, suffix) for a hostname, lowercased."""
    ext = _extract((host or "").lower().rstrip("."))
    return ext.subdomain, ext.domain, ext.suffix


def registered_domain(host: str) -> str:
    """'login.example.co.uk' -> 'example.co.uk'; falls back to the host itself."""
    _, domain, suffix = split_host(host)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return (host or "").lower().rstrip(".")
