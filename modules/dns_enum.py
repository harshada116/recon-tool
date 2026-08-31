"""DNS record enumeration across common record types."""

from config import DNS_RECORD_TYPES

MODULE_NAME = "dns_enum"


def run(target: dict) -> dict:
    import dns.resolver

    hostname = target["hostname"]
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(hostname, rtype)
            records[rtype] = sorted(str(r).strip('"') for r in answers)
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {
                "module": MODULE_NAME, "status": "error", "data": {},
                "findings": [], "error": f"Domain '{hostname}' does not exist (NXDOMAIN).",
            }
        except Exception:  # noqa: BLE001 - individual record type failure, keep going
            records[rtype] = []

    findings = []
    txt_records = " ".join(records.get("TXT", []))
    if "v=spf1" not in txt_records:
        findings.append({
            "id": "missing_spf", "severity": "low",
            "title": "No SPF record found",
            "detail": "No SPF (v=spf1) TXT record was found. Without SPF, "
                      "receiving mail servers have no policy to check for "
                      "spoofed mail claiming to be from this domain.",
            "category": "DNS Infrastructure",
        })
    if not any("v=dmarc1" in t.lower() for t in records.get("TXT", [])):
        # DMARC lives at _dmarc.<domain>, not the apex TXT — check separately.
        try:
            import dns.resolver as _r
            dmarc_answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            has_dmarc = any("v=dmarc1" in str(a).lower() for a in dmarc_answers)
        except Exception:  # noqa: BLE001
            has_dmarc = False
        if not has_dmarc:
            findings.append({
                "id": "missing_dmarc", "severity": "low",
                "title": "No DMARC record found",
                "detail": "No DMARC record was found at _dmarc." + hostname + ". "
                          "Without DMARC, there's no policy telling receivers what "
                          "to do with mail that fails SPF/DKIM.",
                "category": "DNS Infrastructure",
            })

    if len(records.get("NS", [])) < 2:
        findings.append({
            "id": "single_nameserver", "severity": "low",
            "title": "Fewer than two authoritative nameservers",
            "detail": "Only one NS record was found, which is a single point "
                      "of failure for DNS resolution.",
            "category": "DNS Infrastructure",
        })

    return {"module": MODULE_NAME, "status": "success",
            "data": {"records": records}, "findings": findings, "error": None}
