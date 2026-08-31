"""Global configuration for the Web Application Reconnaissance Tool."""

import os

REQUEST_TIMEOUT = 8
MAX_REDIRECTS = 5
USER_AGENT = "ReconTool/1.0 (+authorized-recon; contact: set-your-contact-here)"

# Per-module timeout inside the orchestrator (defensive upper bound).
# Some modules (WHOIS, crt.sh) are naturally slower than others.
MODULE_TIMEOUT = 15

# DNS record types to enumerate
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Small, fixed common-subdomain wordlist for passive brute-force enumeration.
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "api", "dev", "staging", "test", "vpn", "admin", "portal", "app",
    "blog", "shop", "m", "cdn", "static", "assets", "docs", "support",
]

# Fixed, small port list for the optional/gated authorized port scan.
# Intentionally NOT user-configurable beyond enabling/disabling the scan.
PORT_SCAN_PORTS = [21, 22, 25, 80, 443, 3306, 3389, 8080, 8443]
PORT_SCAN_TIMEOUT = 1.5  # seconds per port

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
