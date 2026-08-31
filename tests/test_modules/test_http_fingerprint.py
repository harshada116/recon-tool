import requests_mock

from modules import http_fingerprint


def test_http_fingerprint_basic():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text="hello", headers={"Server": "nginx/1.18.0"})
        result = http_fingerprint.run(target)

    assert result["status"] == "success"
    assert result["data"]["status_code"] == 200
    ids = [f["id"] for f in result["findings"]]
    assert "verbose_server_banner" in ids  # version number present


def test_http_fingerprint_no_version_disclosure():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text="hello", headers={"Server": "nginx"})
        result = http_fingerprint.run(target)
    ids = [f["id"] for f in result["findings"]]
    assert "verbose_server_banner" not in ids


def test_http_fingerprint_connection_error():
    target = {"url": "https://example.com", "hostname": "example.com"}
    with requests_mock.Mocker() as m:
        import requests
        m.get("https://example.com", exc=requests.exceptions.ConnectionError("refused"))
        result = http_fingerprint.run(target)
    assert result["status"] == "error"
