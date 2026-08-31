import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from modules import ssl_inspector


def _future_notafter(days):
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def test_ssl_inspector_healthy_cert():
    target = {"hostname": "example.com"}
    fake_cert = {
        "notAfter": _future_notafter(200),
        "notBefore": _future_notafter(-200),
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        "issuer": ((("organizationName", "Example CA"),),),
        "subject": ((("commonName", "example.com"),),),
    }

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = fake_cert
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = ssl_inspector.run(target)

    assert result["status"] == "success"
    assert result["data"]["verified"] is True
    assert result["data"]["san_count"] == 2
    assert result["findings"] == []


def test_ssl_inspector_expired_cert_flagged():
    target = {"hostname": "example.com"}
    fake_cert = {
        "notAfter": _future_notafter(-10),
        "notBefore": _future_notafter(-400),
        "subjectAltName": [("DNS", "example.com")],
        "issuer": ((("organizationName", "Example CA"),),),
        "subject": ((("commonName", "example.com"),),),
    }
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = fake_cert
    mock_ssock.cipher.return_value = ("AES", "TLSv1.2", 128)
    mock_ssock.version.return_value = "TLSv1.2"
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = ssl_inspector.run(target)

    ids = [f["id"] for f in result["findings"]]
    assert "cert_expired" in ids


def test_ssl_inspector_verification_failure():
    target = {"hostname": "example.com"}
    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed certificate")
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = ssl_inspector.run(target)

    assert result["data"]["verified"] is False
    ids = [f["id"] for f in result["findings"]]
    assert "cert_verification_failed" in ids


def test_ssl_inspector_connection_refused():
    target = {"hostname": "example.com"}
    with patch("ssl.create_default_context", return_value=MagicMock()), \
         patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
        result = ssl_inspector.run(target)

    assert result["status"] == "error"
