from unittest.mock import MagicMock, patch

from modules import dns_enum


def _mock_answer(values):
    return [MagicMock(__str__=lambda self, v=v: v) for v in values]


class FakeNoAnswer(Exception):
    pass


def test_dns_enum_basic_records():
    target = {"hostname": "example.com"}

    def fake_resolve(name, rtype):
        import dns.resolver as real_resolver
        if rtype == "A":
            return _mock_answer(["93.184.216.34"])
        if rtype == "NS":
            return _mock_answer(["ns1.example.com", "ns2.example.com"])
        if rtype == "TXT":
            return _mock_answer(['"v=spf1 include:_spf.example.com ~all"'])
        raise real_resolver.NoAnswer()

    with patch("dns.resolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve.side_effect = fake_resolve
        result = dns_enum.run(target)

    assert result["status"] == "success"
    assert result["data"]["records"]["A"] == ["93.184.216.34"]
    assert len(result["data"]["records"]["NS"]) == 2
    # SPF present -> no missing_spf finding
    ids = [f["id"] for f in result["findings"]]
    assert "missing_spf" not in ids


def test_dns_enum_nxdomain():
    target = {"hostname": "does-not-exist.invalid"}

    def fake_resolve(name, rtype):
        import dns.resolver as real_resolver
        raise real_resolver.NXDOMAIN()

    with patch("dns.resolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve.side_effect = fake_resolve
        result = dns_enum.run(target)

    assert result["status"] == "error"
    assert "does not exist" in result["error"]


def test_dns_enum_single_nameserver_flagged():
    target = {"hostname": "example.com"}

    def fake_resolve(name, rtype):
        import dns.resolver as real_resolver
        if rtype == "NS":
            return _mock_answer(["ns1.example.com"])
        raise real_resolver.NoAnswer()

    with patch("dns.resolver.Resolver") as MockResolver:
        instance = MockResolver.return_value
        instance.resolve.side_effect = fake_resolve
        result = dns_enum.run(target)

    ids = [f["id"] for f in result["findings"]]
    assert "single_nameserver" in ids
    assert "missing_spf" in ids
