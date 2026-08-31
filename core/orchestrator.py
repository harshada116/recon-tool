"""Runs all recon modules against a validated target, isolating failures.

Unlike the header analyzer (single fast HTTP call feeds every module),
recon modules each make their own independent network calls with very
different runtimes, so every module gets submitted to the pool
independently rather than sharing one upstream fetch.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from config import MODULE_TIMEOUT
from modules import (
    whois_lookup, hosting_info, dns_enum, ssl_inspector, http_fingerprint,
    subdomain_enum, robots_sitemap, tech_detection, port_scan,
)

# Always-on modules, in report display order.
ANALYZER_MODULES = [
    whois_lookup,
    hosting_info,
    dns_enum,
    ssl_inspector,
    http_fingerprint,
    subdomain_enum,
    robots_sitemap,
    tech_detection,
]

# Gated: only added to the run when explicitly authorized (see app.py).
OPTIONAL_MODULES = {
    "port_scan": port_scan,
}


def _run_one(module, target):
    try:
        return module.run(target)
    except Exception as exc:  # noqa: BLE001 - isolate any module failure
        return {
            "module": getattr(module, "MODULE_NAME", module.__name__),
            "status": "error", "data": {}, "findings": [], "error": str(exc),
        }


def run_all(target: dict, options: dict = None) -> list:
    options = options or {}
    modules_to_run = list(ANALYZER_MODULES)

    if options.get("port_scan") and options.get("port_scan_authorized"):
        modules_to_run.append(OPTIONAL_MODULES["port_scan"])

    results = []
    with ThreadPoolExecutor(max_workers=max(1, len(modules_to_run))) as pool:
        futures = {pool.submit(_run_one, m, target): m for m in modules_to_run}
        for future, module in futures.items():
            try:
                results.append(future.result(timeout=MODULE_TIMEOUT))
            except FutureTimeoutError:
                results.append({
                    "module": getattr(module, "MODULE_NAME", module.__name__),
                    "status": "error", "data": {}, "findings": [],
                    "error": f"Module timed out after {MODULE_TIMEOUT}s",
                })

    order = {getattr(m, "MODULE_NAME", m.__name__): i for i, m in enumerate(modules_to_run)}
    results.sort(key=lambda r: order.get(r["module"], 999))
    return results
