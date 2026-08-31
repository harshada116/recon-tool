from unittest.mock import patch, MagicMock

from modules import port_scan


def test_port_scan_detects_open_port():
    target = {"resolved_ips": ["93.184.216.34"], "hostname": "example.com"}

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.__enter__.return_value = s
        s.__exit__.return_value = False
        # Pretend port 22 (SSH) is open, everything else closed.
        s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 22 else 1
        return s

    with patch("socket.socket", side_effect=fake_socket):
        result = port_scan.run(target)

    assert result["status"] == "success"
    open_ports = [p["port"] for p in result["data"]["open_ports"]]
    assert 22 in open_ports
    assert 80 not in open_ports


def test_port_scan_no_open_ports():
    target = {"resolved_ips": ["93.184.216.34"], "hostname": "example.com"}

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.__enter__.return_value = s
        s.__exit__.return_value = False
        s.connect_ex.return_value = 1
        return s

    with patch("socket.socket", side_effect=fake_socket):
        result = port_scan.run(target)

    assert result["data"]["open_ports"] == []
    assert result["findings"] == []


def test_port_scan_flags_risky_ports():
    target = {"resolved_ips": ["93.184.216.34"], "hostname": "example.com"}

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.__enter__.return_value = s
        s.__exit__.return_value = False
        s.connect_ex.side_effect = lambda addr: 0 if addr[1] in (21, 3306) else 1
        return s

    with patch("socket.socket", side_effect=fake_socket):
        result = port_scan.run(target)

    ids = [f["id"] for f in result["findings"]]
    assert "risky_port_open" in ids


def test_port_scan_only_scans_fixed_list():
    """The module must never accept a caller-supplied port list — this
    protects the authorization gate from being bypassed via input."""
    target = {"resolved_ips": ["93.184.216.34"], "hostname": "example.com", "ports": [9999]}

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.__enter__.return_value = s
        s.__exit__.return_value = False
        s.connect_ex.return_value = 1
        return s

    with patch("socket.socket", side_effect=fake_socket):
        result = port_scan.run(target)

    from config import PORT_SCAN_PORTS
    assert result["data"]["scanned_ports"] == PORT_SCAN_PORTS
