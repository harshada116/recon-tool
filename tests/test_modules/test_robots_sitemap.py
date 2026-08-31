import requests_mock

from modules import robots_sitemap


ROBOTS_TXT = """
User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
""".strip()

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
</urlset>"""


def test_robots_and_sitemap_parsed():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://example.com/robots.txt", text=ROBOTS_TXT)
        m.get("https://example.com/sitemap.xml", text=SITEMAP_XML)
        result = robots_sitemap.run(target)

    assert result["status"] == "success"
    assert result["data"]["robots"]["present"] is True
    assert "/admin/" in result["data"]["robots"]["disallowed_paths"]
    assert result["data"]["sitemap_url_count"] == 2
    ids = [f["id"] for f in result["findings"]]
    assert "interesting_disallowed_paths" in ids


def test_robots_missing():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://example.com/robots.txt", status_code=404)
        m.get("https://example.com/sitemap.xml", status_code=404)
        result = robots_sitemap.run(target)

    assert result["status"] == "success"
    assert result["data"]["robots"]["present"] is False
    assert result["findings"] == []
