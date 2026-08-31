"""Passive subdomain enumeration via certificate transparency logs (crt.sh)
and a small, fixed common-name wordlist checked against public DNS.

Both techniques are passive/observational: crt.sh just queries a public
log, and the wordlist check only asks public DNS "does this name resolve",
which is the same kind of lookup any browser performs.
"""

import requests

from config import COMMON_SUBDOMAINS

MODULE_NAME = "subdomain_enum"


def _from_crtsh(hostname: str) -> set:
    found = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{hostname}&output=json",
            timeout=10,
            headers={"User-Agent": "recon-tool/1.0"},
        )
        if resp.status_code == 200:
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(hostname):
                        found.add(name)
    except (requests.exceptions.RequestException, ValueError):
        pass  # crt.sh is best-effort; a failure here shouldn't fail the module
    return found


def _from_wordlist(hostname: str) -> set:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 3
    found = set()
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{hostname}"
        try:
            resolver.resolve(candidate, "A")
            found.add(candidate)
        except Exception:  # noqa: BLE001 - most will NXDOMAIN, that's expected
            continue
    return found


def run(target: dict) -> dict:
    hostname = target["hostname"]
    subdomains = set()
    subdomains |= _from_crtsh(hostname)
    subdomains |= _from_wordlist(hostname)
    subdomains.discard(hostname)  # don't list the apex as its own subdomain

    sorted_subs = sorted(subdomains)
    findings = []
    interesting_keywords = ("staging", "dev", "test", "admin", "internal", "vpn")
    interesting = [s for s in sorted_subs if any(k in s for k in interesting_keywords)]
    if interesting:
        findings.append({
            "id": "sensitive_subdomain_exposed", "severity": "medium",
            "title": "Potentially sensitive subdomains discovered",
            "detail": "Publicly discoverable subdomains suggest non-production "
                      "or administrative surfaces: " + ", ".join(interesting) + ".",
            "category": "Discovered Subdomains",
        })

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {"count": len(sorted_subs), "subdomains": sorted_subs},
        "findings": findings, "error": None,
    }
