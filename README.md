# Web Application Reconnaissance Tool

Passive collection of publicly available information about a target domain:
WHOIS, DNS, TLS certificate posture, HTTP fingerprint, subdomain discovery
(certificate transparency + common-name lookup), robots.txt/sitemap, and
technology detection — plus an optional, gated, authorized-only open-port
scan against a small fixed port list.

This is an **information-gathering** tool, not an exploitation tool. Every
technique used is passive/observational (the same kind of lookup a browser
or public registry performs), with one exception: the opt-in port scan,
which is explicitly gated behind a typed authorization confirmation and is
logged server-side.

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Visit `http://localhost:5001`.

## How a scan works

Because WHOIS and subdomain enumeration can be slow, scans run
asynchronously: `POST /scan` kicks off a background job and redirects to a
progress page that polls `/scan/<job_id>/status` until the report is ready.

```
POST /scan                       -> 302 to progress page
GET  /scan/<job_id>/status       -> {"status": "running", "modules_complete": 4, "modules_total": 7}
GET  /scan/<job_id>/report       -> full HTML report (once complete)
GET  /report/<job_id>/pdf        -> PDF download
```

JSON API equivalents are available under `/api/scan`, `/api/scan/<job_id>/status`,
and `/api/scan/<job_id>/report`.

## Authorized port scanning

The `port_scan` module never runs by default. To include it, the caller must:
1. Check the "authorized port scan" box, **and**
2. Re-type the exact target domain in the confirmation field.

The scan itself only ever touches a small, fixed set of common ports defined
in `config.py` — it does not accept a custom port range from the client, by
design.

## SSRF protection

Every target (domain or URL) is resolved and checked against private,
loopback, link-local, and reserved IP ranges before any module runs. HTTP
modules also re-validate the final URL after following redirects, so a
public domain that redirects to an internal address is still rejected.

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

All 47 tests run against mocked network calls (WHOIS, DNS, HTTP, crt.sh,
TLS sockets) — no real network access is required or attempted in tests.

## Project structure

See `core/orchestrator.py` for the module run order, `config.py` for all
tunables (timeouts, wordlists, port list), and `modules/` for each
reconnaissance module. Report grouping (by category, not by module) lives in
`core/report_builder.py`.
