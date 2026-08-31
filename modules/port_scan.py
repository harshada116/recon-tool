"""Optional, gated open-port scan against a small fixed port list.

This module only runs when explicitly enabled by the caller AND the
caller has passed an authorization confirmation flag — see app.py for
where that confirmation is collected from the user. It never accepts a
custom port range; the port list is fixed in config.py.
"""

import socket

from config import PORT_SCAN_PORTS, PORT_SCAN_TIMEOUT

MODULE_NAME = "port_scan"

COMMON_PORT_NAMES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def run(target: dict) -> dict:
    """Runs only if called explicitly by the orchestrator's gated path.
    See core/orchestrator.py: this module is excluded from ANALYZER_MODULES
    and only invoked when options['port_scan'] is True and authorized.
    """
    ip = target["resolved_ips"][0]
    open_ports = []

    for port in PORT_SCAN_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(PORT_SCAN_TIMEOUT)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({"port": port, "service": COMMON_PORT_NAMES.get(port, "unknown")})
        except OSError:
            continue

    findings = []
    risky_open = [p for p in open_ports if p["port"] in (21, 3306, 3389)]
    if risky_open:
        names = ", ".join(f"{p['port']}/{p['service']}" for p in risky_open)
        findings.append({
            "id": "risky_port_open", "severity": "medium",
            "title": "Administrative or database port reachable from the internet",
            "detail": f"The following ports responded to a connection attempt: {names}. "
                      "Exposing these directly to the internet increases attack surface.",
            "category": "Open Ports",
        })

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {"scanned_ports": PORT_SCAN_PORTS, "open_ports": open_ports},
        "findings": findings, "error": None,
    }
