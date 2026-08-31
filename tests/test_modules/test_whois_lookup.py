from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from modules import whois_lookup


def test_whois_success():
    target = {"hostname": "example.com"}
    fake_record = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Example Registrar Inc.",
        "creation_date": datetime(2000, 1, 1, tzinfo=timezone.utc),
        "expiration_date": datetime.now(timezone.utc) + timedelta(days=200),
        "updated_date": datetime(2023, 1, 1, tzinfo=timezone.utc),
        "name_servers": ["NS1.EXAMPLE.COM", "ns2.example.com"],
        "org": "Example Org",
        "status": "active",
    }

    class FakeWhois(dict):
        def get(self, k, default=None):
            return dict.get(self, k, default)

    with patch("whois.whois", return_value=FakeWhois(fake_record)):
        result = whois_lookup.run(target)

    assert result["status"] == "success"
    assert result["data"]["registrar"] == "Example Registrar Inc."
    assert result["findings"] == []


def test_whois_no_record_found():
    target = {"hostname": "example.com"}
    with patch("whois.whois", return_value={}):
        result = whois_lookup.run(target)
    assert result["status"] == "error"


def test_whois_success_without_parsed_domain_name():
    """Many ccTLD/newer-gTLD registries return a record the parser can't
    pull a domain_name out of, even though registrar/dates/name servers
    all parsed fine. This must still be reported as success, not
    "no record found" -- this was the bug causing lookups to fail for
    many websites."""
    target = {"hostname": "example.io"}
    fake_record = {
        "domain_name": None,
        "registrar": "Some Registrar Ltd.",
        "creation_date": datetime(2015, 5, 1, tzinfo=timezone.utc),
        "expiration_date": datetime.now(timezone.utc) + timedelta(days=200),
        "updated_date": None,
        "name_servers": ["ns1.example.io", None],
        "org": None,
        "status": ["active", "clientTransferProhibited"],
    }

    class FakeWhois(dict):
        def get(self, k, default=None):
            return dict.get(self, k, default)

    with patch("whois.whois", return_value=FakeWhois(fake_record)):
        result = whois_lookup.run(target)

    assert result["status"] == "success"
    assert result["data"]["registrar"] == "Some Registrar Ltd."
    assert result["data"]["domain_name"] == "example.io"
    assert result["data"]["name_servers"] == ["ns1.example.io"]
    assert result["data"]["status"] == "active"


def test_whois_truly_empty_record_is_error():
    target = {"hostname": "example.com"}
    fake_record = {
        "domain_name": None, "registrar": None, "creation_date": None,
        "expiration_date": None, "updated_date": None, "name_servers": None,
        "org": None, "status": None,
    }

    class FakeWhois(dict):
        def get(self, k, default=None):
            return dict.get(self, k, default)

    with patch("whois.whois", return_value=FakeWhois(fake_record)):
        result = whois_lookup.run(target)
    assert result["status"] == "error"


def test_whois_lookup_exception_handled():
    target = {"hostname": "example.com"}
    with patch("whois.whois", side_effect=Exception("WHOIS server timeout")):
        result = whois_lookup.run(target)
    assert result["status"] == "error"
    assert "WHOIS lookup failed" in result["error"]


def test_whois_expiring_soon_flagged():
    target = {"hostname": "example.com"}
    fake_record = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Registrar",
        "creation_date": datetime(2000, 1, 1, tzinfo=timezone.utc),
        "expiration_date": datetime.now(timezone.utc) + timedelta(days=10),
        "updated_date": None,
        "name_servers": [],
        "org": None,
        "status": "active",
    }

    class FakeWhois(dict):
        def get(self, k, default=None):
            return dict.get(self, k, default)

    with patch("whois.whois", return_value=FakeWhois(fake_record)):
        result = whois_lookup.run(target)

    ids = [f["id"] for f in result["findings"]]
    assert "domain_expiring_soon" in ids
