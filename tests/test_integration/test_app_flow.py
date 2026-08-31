import time

import pytest

import app as app_module
from core import job_manager


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Start Recon" in resp.data


def test_scan_rejects_invalid_target(client):
    resp = client.post("/scan", data={"target": "not a domain!!"})
    assert resp.status_code == 400


def test_scan_rejects_private_target(client):
    resp = client.post("/scan", data={"target": "127.0.0.1"})
    assert resp.status_code == 400


def test_port_scan_requires_authorization_confirmation(client, monkeypatch):
    monkeypatch.setattr(app_module, "validate_target", lambda t: {
        "hostname": "example.com", "url": "https://example.com", "resolved_ips": ["93.184.216.34"]
    })
    resp = client.post("/scan", data={"target": "example.com", "port_scan": "1", "authorize_confirm": ""})
    assert resp.status_code == 400
    assert b"authorization" in resp.data.lower() or b"authorized" in resp.data.lower()


def test_full_scan_flow_with_mocked_modules(client, monkeypatch):
    """Exercises validate -> async job -> module run -> report, with every
    module's underlying network call mocked so nothing hits the real
    network."""
    monkeypatch.setattr(app_module, "validate_target", lambda t: {
        "hostname": "example.com", "url": "https://example.com", "resolved_ips": ["93.184.216.34"]
    })

    # Stub every module's run() to avoid real network calls entirely,
    # verifying the orchestration/report layer independent of module internals.
    from core.orchestrator import ANALYZER_MODULES

    def make_stub(name):
        stub_data = {
            "whois": {"registrar": "Stub Registrar", "name_servers": []},
            "dns_enum": {"records": {"A": ["93.184.216.34"]}},
            "ssl_inspector": {"verified": True, "issuer": "Stub CA", "san_count": 1},
            "http_fingerprint": {"final_url": "https://example.com", "status_code": 200,
                                  "redirect_chain": [], "cookie_names": []},
            "subdomain_enum": {"subdomains": []},
            "robots_sitemap": {"robots": {"present": False, "disallowed_paths": []},
                                "sitemap_url_count": 0},
            "tech_detection": {"detected": [], "meta_generator": None},
        }.get(name, {})

        def stub(target):
            return {"module": name, "status": "success", "data": stub_data, "findings": [], "error": None}
        return stub

    for mod in ANALYZER_MODULES:
        monkeypatch.setattr(mod, "run", make_stub(mod.MODULE_NAME))

    resp = client.post("/scan", data={"target": "example.com"}, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["Location"]
    # Location looks like /scan/<job_id>/progress?hostname=example.com
    path = location.split("?")[0]
    job_id = path.strip("/").split("/")[1]

    # Poll status until complete (background thread; should be fast since stubbed)
    deadline = time.time() + 5
    status = None
    while time.time() < deadline:
        status_resp = client.get(f"/scan/{job_id}/status")
        status = status_resp.get_json()
        if status["status"] == "complete":
            break
        time.sleep(0.05)

    assert status["status"] == "complete"

    report_resp = client.get(f"/scan/{job_id}/report")
    assert report_resp.status_code == 200
    assert b"example.com" in report_resp.data


def test_report_404_for_unknown_job(client):
    resp = client.get("/scan/does-not-exist/report")
    assert resp.status_code == 404


def test_job_manager_isolates_module_failure():
    """A module raising should not prevent the job from completing."""
    target = {"hostname": "example.com", "url": "https://example.com", "resolved_ips": ["1.1.1.1"]}
    job_id = job_manager.create_job()

    from core.orchestrator import ANALYZER_MODULES

    # Back up every module's original run() so we can restore all of them,
    # not just the one we intentionally break — leaving any of these
    # patched leaks into every other test in the session.
    originals = {mod.MODULE_NAME: mod.run for mod in ANALYZER_MODULES}

    def broken_run(target):
        raise RuntimeError("simulated module crash")

    ANALYZER_MODULES[0].run = broken_run
    for mod in ANALYZER_MODULES[1:]:
        mod.run = lambda t, name=mod.MODULE_NAME: {
            "module": name, "status": "success", "data": {}, "findings": [], "error": None
        }

    try:
        job_manager.run_job_async(job_id, target, {})
        job = job_manager.get_job(job_id)
        assert job["status"] == "complete"
        # The broken module should show up as an error result, not crash the job.
        broken_result = job["report"]["modules_by_name"][ANALYZER_MODULES[0].MODULE_NAME]
        assert broken_result["status"] == "error"
    finally:
        for mod in ANALYZER_MODULES:
            mod.run = originals[mod.MODULE_NAME]
