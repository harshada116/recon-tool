import pytest

from core import validator


def test_extract_hostname_from_bare_domain():
    assert validator.extract_hostname("example.com") == "example.com"


def test_extract_hostname_from_full_url():
    assert validator.extract_hostname("https://example.com/path?x=1") == "example.com"


def test_extract_hostname_from_domain_with_path():
    assert validator.extract_hostname("example.com/some/path") == "example.com"


def test_extract_hostname_rejects_empty():
    with pytest.raises(validator.ValidationError):
        validator.extract_hostname("   ")


def test_extract_hostname_rejects_invalid_domain():
    with pytest.raises(validator.ValidationError):
        validator.extract_hostname("not a domain!!")


def test_rejects_private_target(monkeypatch):
    monkeypatch.setattr(
        validator.socket, "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("10.0.0.5", 0))],
    )
    with pytest.raises(validator.ValidationError):
        validator.validate_target("internal.corp")


def test_accepts_public_target(monkeypatch):
    monkeypatch.setattr(
        validator.socket, "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    result = validator.validate_target("example.com")
    assert result["hostname"] == "example.com"
    assert result["resolved_ips"] == ["93.184.216.34"]
    assert result["url"] == "https://example.com"


def test_rejects_bad_scheme_in_full_url(monkeypatch):
    monkeypatch.setattr(
        validator.socket, "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    with pytest.raises(validator.ValidationError):
        validator.validate_target("ftp://example.com")


def test_rejects_unresolvable_host(monkeypatch):
    import socket as socket_module

    def raise_gaierror(host, port):
        raise socket_module.gaierror("nope")

    monkeypatch.setattr(validator.socket, "getaddrinfo", raise_gaierror)
    with pytest.raises(validator.ValidationError):
        validator.validate_target("this-does-not-resolve.invalid")


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1"])
def test_is_private_ip_true(ip):
    assert validator._is_private_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34"])
def test_is_private_ip_false(ip):
    assert validator._is_private_ip(ip) is False
