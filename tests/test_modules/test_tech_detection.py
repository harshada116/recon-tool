import requests_mock

from modules import tech_detection


def test_detects_wordpress_and_jquery():
    target = {"url": "https://example.com", "hostname": "example.com"}
    html = """
    <html><head>
    <meta name="generator" content="WordPress 6.4">
    <script src="/wp-content/themes/x/script.js"></script>
    <script src="/wp-includes/js/jquery/jquery.min.js"></script>
    </head><body>hello</body></html>
    """
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text=html, headers={"Server": "nginx"})
        result = tech_detection.run(target)

    assert result["status"] == "success"
    names = [t["name"] for t in result["data"]["detected"]]
    assert "WordPress" in names
    assert "jQuery" in names
    assert result["data"]["meta_generator"] == "WordPress 6.4"


def test_detects_php_via_cookie():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text="<html></html>",
              headers={"Set-Cookie": "PHPSESSID=abc123; Path=/"})
        result = tech_detection.run(target)

    names = [t["name"] for t in result["data"]["detected"]]
    assert "PHP" in names


def test_fetch_failure_handled():
    target = {"url": "https://example.com", "hostname": "example.com"}
    import requests
    with requests_mock.Mocker() as m:
        m.get("https://example.com", exc=requests.exceptions.ConnectionError("refused"))
        result = tech_detection.run(target)
    assert result["status"] == "error"
