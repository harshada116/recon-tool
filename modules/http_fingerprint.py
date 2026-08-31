"""HTTP-level fingerprinting: status, headers, redirects, cookies present."""

import requests

from config import REQUEST_TIMEOUT, USER_AGENT
from core.validator import guard_redirect_chain, ValidationError

MODULE_NAME = "http_fingerprint"


def run(target: dict) -> dict:
    url = target["url"]
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                             headers={"User-Agent": USER_AGENT})
    except requests.exceptions.RequestException as exc:
        return {"module": MODULE_NAME, "status": "error", "data": {},
                "findings": [], "error": f"HTTP request failed: {exc}"}

    try:
        guard_redirect_chain(resp.history, resp.url)
    except ValidationError as exc:
        return {"module": MODULE_NAME, "status": "error", "data": {},
                "findings": [], "error": str(exc)}

    findings = []
    server_hdr = resp.headers.get("Server")
    powered_by = resp.headers.get("X-Powered-By")
    if server_hdr and any(c.isdigit() for c in server_hdr):
        findings.append({
            "id": "verbose_server_banner", "severity": "low",
            "title": "Server header discloses version information",
            "detail": f"Server header value: '{server_hdr}'. Version-specific "
                      "banners make it easier to target known vulnerabilities "
                      "for that exact software version.",
            "category": "HTTP Surface",
        })
    if powered_by:
        findings.append({
            "id": "x_powered_by_disclosure", "severity": "low",
            "title": "X-Powered-By header discloses backend technology",
            "detail": f"X-Powered-By value: '{powered_by}'.",
            "category": "HTTP Surface",
        })

    redirect_chain = [{"url": r.url, "status": r.status_code} for r in resp.history]

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {
            "final_url": resp.url,
            "status_code": resp.status_code,
            "redirect_chain": redirect_chain,
            "server": server_hdr,
            "x_powered_by": powered_by,
            "cookie_names": [c.name for c in resp.cookies],
            "headers_sample": {k: v for k, v in list(resp.headers.items())[:25]},
        },
        "findings": findings, "error": None,
    }
