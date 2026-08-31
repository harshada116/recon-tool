from unittest.mock import patch

import requests_mock

from modules import subdomain_enum


def test_crtsh_results_merged():
    target = {"hostname": "example.com"}
    crtsh_payload = [
        {"name_value": "www.example.com\nstaging.example.com"},
        {"name_value": "*.example.com"},
    ]
    with requests_mock.Mocker() as m:
        m.get("https://crt.sh/?q=%.example.com&output=json", json=crtsh_payload)
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = Exception("nxdomain")  # wordlist finds nothing
            result = subdomain_enum.run(target)

    assert result["status"] == "success"
    assert "www.example.com" in result["data"]["subdomains"]
    assert "staging.example.com" in result["data"]["subdomains"]
    ids = [f["id"] for f in result["findings"]]
    assert "sensitive_subdomain_exposed" in ids  # "staging" is a sensitive keyword


def test_crtsh_failure_degrades_gracefully():
    target = {"hostname": "example.com"}
    with requests_mock.Mocker() as m:
        m.get("https://crt.sh/?q=%.example.com&output=json", status_code=503)
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = Exception("nxdomain")
            result = subdomain_enum.run(target)

    assert result["status"] == "success"
    assert result["data"]["subdomains"] == []
