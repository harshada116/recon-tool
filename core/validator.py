"""Target validation and SSRF protection for the recon tool.

Accepts either a bare domain ("example.com") or a full URL
("https://example.com/path") and normalizes both into a consistent
target descriptor. Domain-only modules (WHOIS, DNS) use the hostname;
network-facing modules (HTTP fingerprint, port scan) go through the
same private-IP guard used by the header analyzer.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class ValidationError(Exception):
    pass


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def extract_hostname(raw_target: str) -> str:
    """Pull a bare hostname out of either a domain or full URL."""
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValidationError("Target is empty.")

    if "://" in raw_target:
        hostname = urlparse(raw_target).hostname
    else:
        # Might be "example.com" or "example.com/path" without scheme.
        hostname = raw_target.split("/")[0].split(":")[0]

    if not hostname:
        raise ValidationError("Could not determine a hostname from the target.")

    hostname = hostname.lower().strip(".")
    if not _HOSTNAME_RE.match(hostname):
        raise ValidationError(f"'{hostname}' does not look like a valid domain.")

    return hostname


def resolve_and_guard(hostname: str) -> list:
    """Resolve hostname to IP(s), reject any private/internal results.

    Returns list of resolved IP strings if the host is safe to contact.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValidationError(f"Could not resolve host: {hostname}") from exc

    resolved_ips = sorted({info[4][0] for info in infos})
    if not resolved_ips:
        raise ValidationError(f"Could not resolve host: {hostname}")

    for ip_str in resolved_ips:
        if _is_private_ip(ip_str):
            raise ValidationError(
                "Target resolves to a private/internal address and cannot be scanned."
            )
    return resolved_ips


def validate_target(raw_target: str) -> dict:
    """Full validation pipeline. Returns a target descriptor dict."""
    hostname = extract_hostname(raw_target)
    resolved_ips = resolve_and_guard(hostname)

    # Build a normalized https URL for HTTP-facing modules.
    if "://" in raw_target:
        parsed = urlparse(raw_target)
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise ValidationError(f"Unsupported scheme: {parsed.scheme!r}.")
        url = raw_target
    else:
        url = f"https://{hostname}"

    return {
        "hostname": hostname,
        "url": url,
        "resolved_ips": resolved_ips,
    }


def guard_redirect_chain(response_history, final_url) -> None:
    from config import MAX_REDIRECTS

    if len(response_history) > MAX_REDIRECTS:
        raise ValidationError("Too many redirects.")
    parsed = urlparse(final_url)
    if parsed.hostname:
        resolve_and_guard(parsed.hostname)
