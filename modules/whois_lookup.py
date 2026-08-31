"""WHOIS lookup module.

WHOIS servers are notoriously slow/rate-limited/inconsistent in format,
so this module is defensive: any failure degrades to a partial result
rather than raising.
"""

MODULE_NAME = "whois"


def _normalize_date(value):
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value else None


def _normalize_field(value):
    """Collapse a str-or-list-of-str field (e.g. status) to a clean string."""
    if isinstance(value, list):
        value = next((v for v in value if v), None)
    return str(value) if value else None


def run(target: dict) -> dict:
    import whois  # python-whois

    hostname = target["hostname"]
    try:
        w = whois.whois(hostname)
    except Exception as exc:  # noqa: BLE001
        return {
            "module": MODULE_NAME, "status": "error",
            "data": {}, "findings": [], "error": f"WHOIS lookup failed: {exc}",
        }

    if not w:
        return {
            "module": MODULE_NAME, "status": "error",
            "data": {}, "findings": [],
            "error": "No WHOIS record found (may be privacy-protected or a ccTLD "
                     "with a restricted registry).",
        }

    name_servers = [ns for ns in (w.get("name_servers") or []) if ns]
    data = {
        "registrar": w.get("registrar"),
        "creation_date": _normalize_date(w.get("creation_date")),
        "expiration_date": _normalize_date(w.get("expiration_date")),
        "updated_date": _normalize_date(w.get("updated_date")),
        "name_servers": sorted({ns.lower() for ns in name_servers}) if name_servers else [],
        "registrant_org": w.get("org") or w.get("registrant_org"),
        "status": _normalize_field(w.get("status")),
        "domain_name": _normalize_field(w.get("domain_name")) or hostname,
    }

    # python-whois's parser is tuned for .com/.net-style output and often
    # fails to extract "domain_name" specifically for ccTLDs, newer gTLDs,
    # and thin-registry responses -- even though it parsed everything else
    # fine. Gating success on domain_name alone caused many legitimate
    # lookups to be reported as "no record found". Instead, treat it as a
    # real record as long as we got *any* substantive field back.
    has_data = any([
        data["registrar"], data["creation_date"], data["expiration_date"],
        data["updated_date"], data["name_servers"], data["registrant_org"],
        data["status"], w.get("domain_name"),
    ])
    if not has_data:
        return {
            "module": MODULE_NAME, "status": "error",
            "data": {}, "findings": [],
            "error": "No WHOIS record found (may be privacy-protected or a ccTLD "
                     "with a restricted registry).",
        }

    findings = []
    from datetime import datetime, timezone
    exp = w.get("expiration_date")
    if isinstance(exp, list):
        exp = exp[0] if exp else None
    if exp:
        try:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            if days_left < 30:
                findings.append({
                    "id": "domain_expiring_soon",
                    "severity": "medium" if days_left > 0 else "high",
                    "title": "Domain registration expiring soon",
                    "detail": f"The domain is set to expire in {days_left} day(s). "
                              "An expired domain can be re-registered by a third party.",
                    "category": "Domain & Registration",
                })
        except (AttributeError, TypeError):
            pass

    return {"module": MODULE_NAME, "status": "success", "data": data,
            "findings": findings, "error": None}
