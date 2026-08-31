from unittest.mock import patch, MagicMock

from modules import hosting_info


def _target(ip="54.220.192.176"):
    return {"hostname": "juice-shop.herokuapp.com", "resolved_ips": [ip]}


def test_hosting_info_success():
    fake_rdap = {
        "asn": "16509",
        "asn_description": "AMAZON-02, US",
        "asn_country_code": "IE",
        "network": {"name": "AMAZON-EU-IE", "cidr": "54.220.0.0/16"},
    }
    with patch("ipwhois.IPWhois") as MockIPWhois, \
         patch("socket.gethostbyaddr", return_value=("ec2-54-220-192-176.eu-west-1.compute.amazonaws.com", [], [])), \
         patch("dns.resolver.Resolver") as MockResolver:
        MockIPWhois.return_value.lookup_rdap.return_value = fake_rdap
        MockResolver.return_value.resolve.return_value = [MagicMock()]

        result = hosting_info.run(_target())

    assert result["status"] == "success"
    assert result["data"]["ipv4_address"] == "54.220.192.176"
    assert result["data"]["netblock_owner"] == "AMAZON-EU-IE"
    assert result["data"]["asn"] == "16509"
    assert result["data"]["hosting_country"] == "IE"
    assert result["data"]["reverse_dns"] == "ec2-54-220-192-176.eu-west-1.compute.amazonaws.com"
    assert result["data"]["dnssec_enabled"] is True
    assert result["data"]["tld_category"] == "Commercial entities (.com)"
    # Reverse DNS doesn't contain the scanned hostname -> shared-infra info finding.
    ids = [f["id"] for f in result["findings"]]
    assert "reverse_dns_shared_infra" in ids


def test_hosting_info_no_resolved_ip():
    result = hosting_info.run({"hostname": "example.com", "resolved_ips": []})
    assert result["status"] == "error"


def test_hosting_info_rdap_failure_degrades_gracefully():
    with patch("ipwhois.IPWhois") as MockIPWhois, \
         patch("socket.gethostbyaddr", side_effect=OSError("no PTR")), \
         patch("dns.resolver.Resolver") as MockResolver:
        MockIPWhois.return_value.lookup_rdap.side_effect = Exception("RDAP unreachable")
        import dns.resolver as real_dns_resolver
        MockResolver.return_value.resolve.side_effect = real_dns_resolver.NoAnswer()

        result = hosting_info.run(_target())

    assert result["status"] == "success"
    assert result["data"]["netblock_owner"] is None
    assert result["data"]["reverse_dns"] is None
    assert result["data"]["dnssec_enabled"] is False
    ids = [f["id"] for f in result["findings"]]
    assert "dnssec_not_enabled" in ids
    assert "reverse_dns_shared_infra" not in ids


def test_dnssec_unknown_on_resolver_error():
    with patch("dns.resolver.Resolver") as MockResolver:
        MockResolver.return_value.resolve.side_effect = Exception("timeout")
        assert hosting_info._dnssec_enabled("example.com") is None


def test_tld_category_known_and_unknown():
    assert hosting_info._tld_category("juice-shop.herokuapp.com") == "Commercial entities (.com)"
    assert hosting_info._tld_category("example.xyz") == "Generic top-level domain (.xyz)"
