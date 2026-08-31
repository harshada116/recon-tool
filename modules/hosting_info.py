"""Hosting & network posture: netblock/ASN ownership, hosting company and
country, reverse DNS, DNSSEC status, and TLD classification.

All lookups here are passive/public (RDAP for the IP's netblock owner, a
PTR lookup for reverse DNS, a DNSKEY query for DNSSEC) — the same kind of
data a public "who hosts this" lookup site would show. Like the other
modules, any failure degrades to a partial result rather than raising.
"""

MODULE_NAME = "hosting_info"

# Coarse TLD categorisation for the report — not authoritative, just a
# friendly label next to the raw TLD.
_TLD_CATEGORIES = {
    "com": "Commercial entities (.com)",
    "org": "Non-profit organizations (.org)",
    "net": "Network infrastructure (.net)",
    "io": "Generic/tech-branded (.io)",
    "gov": "United States government (.gov)",
    "edu": "Educational institutions (.edu)",
    "mil": "United States military (.mil)",
    "app": "Applications (.app)",
    "dev": "Developer-branded (.dev)",
    "co": "Generic/company-branded (.co)",
}


def _reverse_dns(ip: str):
    import socket
    try:
        hostname, _aliases, _ips = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _dnssec_enabled(hostname: str):
    import dns.resolver
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 5
        answers = resolver.resolve(hostname, "DNSKEY")
        return len(answers) > 0
    except dns.resolver.NoAnswer:
        return False
    except Exception:  # noqa: BLE001 - NXDOMAIN, timeout, no DNSSEC support, etc.
        return None  # unknown, distinct from "confirmed absent"


def _rdap_netblock(ip: str):
    """Netblock owner / ASN / hosting org+country via RDAP. Returns dict or None."""
    try:
        from ipwhois import IPWhois
    except ImportError:
        return None
    try:
        result = IPWhois(ip).lookup_rdap(depth=1, rate_limit_timeout=5)
    except Exception:  # noqa: BLE001 - malformed RDAP, rate limit, network error
        return None

    network = result.get("network") or {}
    return {
        "netblock_owner": network.get("name"),
        "netblock_cidr": network.get("cidr"),
        "asn": result.get("asn"),
        "asn_description": result.get("asn_description"),
        "asn_country_code": result.get("asn_country_code"),
    }


def _tld_category(hostname: str):
    tld = hostname.rsplit(".", 1)[-1].lower()
    return _TLD_CATEGORIES.get(tld, f"Generic top-level domain (.{tld})")


def run(target: dict) -> dict:
    hostname = target["hostname"]
    resolved_ips = target.get("resolved_ips") or []
    ipv4 = next((ip for ip in resolved_ips if ":" not in ip), None)
    ipv6 = next((ip for ip in resolved_ips if ":" in ip), None)
    primary_ip = ipv4 or ipv6

    if not primary_ip:
        return {
            "module": MODULE_NAME, "status": "error", "data": {},
            "findings": [], "error": "No resolved IP address available for hosting lookup.",
        }

    rdap = _rdap_netblock(primary_ip)
    reverse_dns = _reverse_dns(primary_ip)
    dnssec_enabled = _dnssec_enabled(hostname)

    data = {
        "ipv4_address": ipv4,
        "ipv6_address": ipv6,
        "reverse_dns": reverse_dns,
        "netblock_owner": (rdap or {}).get("netblock_owner"),
        "netblock_cidr": (rdap or {}).get("netblock_cidr"),
        "asn": (rdap or {}).get("asn"),
        "asn_description": (rdap or {}).get("asn_description"),
        "hosting_country": (rdap or {}).get("asn_country_code"),
        "dnssec_enabled": dnssec_enabled,
        "tld_category": _tld_category(hostname),
    }

    findings = []
    if dnssec_enabled is False:
        findings.append({
            "id": "dnssec_not_enabled", "severity": "low",
            "title": "DNSSEC is not enabled",
            "detail": "No DNSKEY record was found for this domain. Without DNSSEC, "
                      "DNS responses for this domain cannot be cryptographically "
                      "validated, leaving resolvers reliant on unsigned answers.",
            "category": "Hosting & Network",
        })
    if reverse_dns and hostname not in reverse_dns:
        findings.append({
            "id": "reverse_dns_shared_infra", "severity": "info",
            "title": "Reverse DNS points to shared hosting infrastructure",
            "detail": f"The PTR record for {primary_ip} resolves to '{reverse_dns}', "
                      "which does not match the scanned hostname — typical of "
                      "cloud/PaaS hosting where many customer domains share the "
                      "same underlying IP infrastructure.",
            "category": "Hosting & Network",
        })

    return {"module": MODULE_NAME, "status": "success", "data": data,
            "findings": findings, "error": None}
