"""Lightweight technology fingerprinting via headers, cookies, and markup
patterns — similar in spirit to Wappalyzer but with a small hand-rolled
signature table rather than a full external database."""

import re

import requests
from bs4 import BeautifulSoup

from config import REQUEST_TIMEOUT, USER_AGENT

MODULE_NAME = "tech_detection"

# (technology, category, matcher-function) — matcher receives (headers, cookies, html)
SIGNATURES = [
    ("WordPress", "CMS", lambda h, c, html: "wp-content" in html or "wp-includes" in html),
    ("Drupal", "CMS", lambda h, c, html: "Drupal.settings" in html or "sites/default/files" in html),
    ("Joomla", "CMS", lambda h, c, html: "com_content" in html or "Joomla!" in html),
    ("Shopify", "E-commerce", lambda h, c, html: "cdn.shopify.com" in html or "Shopify" in h.get("X-Shopify-Stage", "")),
    ("React", "JS Framework", lambda h, c, html: "__reactContainer" in html or "data-reactroot" in html or "react-dom" in html),
    ("Vue.js", "JS Framework", lambda h, c, html: "data-v-" in html or "__vue__" in html),
    ("Angular", "JS Framework", lambda h, c, html: "ng-version" in html or "ng-app" in html),
    ("jQuery", "JS Library", lambda h, c, html: "jquery" in html.lower()),
    ("Bootstrap", "CSS Framework", lambda h, c, html: "bootstrap" in html.lower()),
    ("PHP", "Language", lambda h, c, html: "PHPSESSID" in c or "php" in h.get("X-Powered-By", "").lower()),
    ("ASP.NET", "Framework", lambda h, c, html: "ASP.NET" in h.get("X-Powered-By", "") or "ASP.NET_SessionId" in c),
    ("Nginx", "Web Server", lambda h, c, html: "nginx" in h.get("Server", "").lower()),
    ("Apache", "Web Server", lambda h, c, html: "apache" in h.get("Server", "").lower()),
    ("Cloudflare", "CDN/Proxy", lambda h, c, html: "cloudflare" in h.get("Server", "").lower() or "cf-ray" in {k.lower() for k in h.keys()}),
    ("Google Analytics", "Analytics", lambda h, c, html: "google-analytics.com" in html or "gtag(" in html),
    ("Google Tag Manager", "Analytics", lambda h, c, html: "googletagmanager.com" in html),
]


def run(target: dict) -> dict:
    url = target["url"]
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.exceptions.RequestException as exc:
        return {"module": MODULE_NAME, "status": "error", "data": {},
                "findings": [], "error": f"Could not fetch page for fingerprinting: {exc}"}

    headers = resp.headers
    cookie_names = {c.name for c in resp.cookies}
    html = resp.text or ""

    # Also check meta generator tag explicitly (common, reliable signal)
    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": "generator"})
    generator_content = generator.get("content") if generator else None

    detected = []
    for name, category, matcher in SIGNATURES:
        try:
            if matcher(headers, cookie_names, html):
                detected.append({"name": name, "category": category})
        except Exception:  # noqa: BLE001
            continue

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {
            "detected": detected,
            "meta_generator": generator_content,
        },
        "findings": [], "error": None,
    }
