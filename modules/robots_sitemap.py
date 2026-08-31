"""Fetches robots.txt and sitemap.xml, extracts disallowed paths and URLs."""

import requests
from xml.etree import ElementTree

from config import REQUEST_TIMEOUT, USER_AGENT

MODULE_NAME = "robots_sitemap"


def _fetch_text(url: str):
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            return resp.text
    except requests.exceptions.RequestException:
        pass
    return None


def _parse_robots(text: str) -> dict:
    disallowed, sitemaps = [], []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    return {"disallowed_paths": disallowed, "sitemap_urls": sitemaps}


def _parse_sitemap(text: str) -> list:
    urls = []
    try:
        root = ElementTree.fromstring(text)
        for loc in root.iter():
            if loc.tag.endswith("loc") and loc.text:
                urls.append(loc.text.strip())
    except ElementTree.ParseError:
        pass
    return urls[:200]  # cap for report size


def run(target: dict) -> dict:
    base = target["url"].rstrip("/")
    robots_text = _fetch_text(f"{base}/robots.txt")
    findings = []

    robots_data = {"present": False, "disallowed_paths": [], "sitemap_urls": []}
    if robots_text:
        robots_data = {"present": True, **_parse_robots(robots_text)}
        interesting = [p for p in robots_data["disallowed_paths"]
                       if any(k in p.lower() for k in ("admin", "backup", "config", "private", "internal"))]
        if interesting:
            findings.append({
                "id": "interesting_disallowed_paths", "severity": "low",
                "title": "robots.txt discloses potentially sensitive paths",
                "detail": "Disallow entries hint at paths that may be worth "
                          "reviewing for exposure: " + ", ".join(interesting[:10]) + ".",
                "category": "Crawl Surface",
            })

    sitemap_urls = robots_data.get("sitemap_urls") or [f"{base}/sitemap.xml"]
    all_urls = []
    for sm_url in sitemap_urls[:3]:
        sm_text = _fetch_text(sm_url)
        if sm_text:
            all_urls.extend(_parse_sitemap(sm_text))

    return {
        "module": MODULE_NAME, "status": "success",
        "data": {
            "robots": robots_data,
            "sitemap_url_count": len(all_urls),
            "sitemap_urls_sample": all_urls[:30],
        },
        "findings": findings, "error": None,
    }
