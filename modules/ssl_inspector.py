"""TLS certificate inspection: chain, issuer, validity window, SANs."""

import socket
import ssl
from datetime import datetime, timezone

MODULE_NAME = "ssl_inspector"


def run(target: dict) -> dict:
    hostname = target["hostname"]
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        return {
            "module": MODULE_NAME, "status": "success",
            "data": {"verified": False, "verify_error": str(exc)},
            "findings": [{
                "id": "cert_verification_failed", "severity": "high",
                "title": "Certificate failed verification",
                "detail": f"TLS certificate could not be verified: {exc}",
                "category": "TLS/Certificate Posture",
            }],
            "error": None,
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {
            "module": MODULE_NAME, "status": "error", "data": {},
            "findings": [], "error": f"Could not establish TLS connection on port 443: {exc}",
        }

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    findings = []
    days_left = None

    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append({
                    "id": "cert_expired", "severity": "high",
                    "title": "TLS certificate has expired",
                    "detail": f"The certificate expired {abs(days_left)} day(s) ago.",
                    "category": "TLS/Certificate Posture",
                })
            elif days_left < 14:
                findings.append({
                    "id": "cert_expiring_soon", "severity": "medium",
                    "title": "TLS certificate expiring soon",
                    "detail": f"The certificate expires in {days_left} day(s).",
                    "category": "TLS/Certificate Posture",
                })
        except ValueError:
            pass

    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "id": "weak_tls_version", "severity": "high",
            "title": f"Server negotiated deprecated TLS version ({tls_version})",
            "detail": "TLS 1.0/1.1 are deprecated and considered insecure by "
                      "major browsers and standards bodies.",
            "category": "TLS/Certificate Posture",
        })

    sans = []
    for entry in cert.get("subjectAltName", []):
        if entry[0] == "DNS":
            sans.append(entry[1])

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {
            "verified": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject_cn": subject.get("commonName"),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "san_count": len(sans),
            "sans": sans,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
        },
        "findings": findings,
        "error": None,
    }
