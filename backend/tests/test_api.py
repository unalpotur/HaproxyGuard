from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

CFG = """\
frontend web
    bind *:80
    default_backend app

backend app
    server s1 10.0.0.1:8080 check
"""


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_parse_endpoint():
    r = client.post("/api/parse", json={"content": CFG})
    assert r.status_code == 200
    data = r.json()
    assert data["frontends"][0]["name"] == "web"
    assert data["backends"][0]["servers"][0]["name"] == "s1"


def test_analyze_endpoint():
    r = client.post("/api/analyze", json={"content": CFG})
    assert r.status_code == 200
    assert "summary" in r.json()


def test_topology_endpoint():
    r = client.post("/api/topology", json={"content": CFG})
    g = r.json()
    ids = {n["id"] for n in g["nodes"]}
    assert {"fe:web", "be:app", "srv:app/s1"} <= ids
    assert {"source": "fe:web", "target": "be:app", "label": "default"} in g["edges"]


def test_analyze_marks_fixable():
    r = client.post("/api/analyze", json={"content": "defaults\n    mode http\n"})
    findings = r.json()["findings"]
    hg008 = next(f for f in findings if f["rule_id"] == "HG008")
    assert hg008["fixable"] is True


def test_fix_preview_and_apply_and_rollback():
    cfg = "defaults\n    mode http\n"
    prev = client.post("/api/fix/preview",
                       json={"content": cfg, "run_validation": False}).json()
    assert prev["changed"] is True
    assert prev["version_id"] is None  # preview never persists
    assert "timeout connect" in prev["proposed_content"]

    applied = client.post("/api/fix/apply",
                          json={"content": cfg, "run_validation": False}).json()
    vid = applied["version_id"]
    assert vid

    rb = client.post("/api/fix/rollback", json={"version_id": vid})
    assert rb.status_code == 200
    assert rb.json()["content"] == cfg


def test_fix_rollback_unknown_version():
    r = client.post("/api/fix/rollback", json={"version_id": "nope"})
    assert r.status_code == 404


def test_ssl_analyze_cert_endpoint():
    from tests.test_sslmgr import make_cert
    pem = make_cert("api.example", days_valid=200)
    r = client.post("/api/ssl/analyze-cert", json={"pem": pem})
    assert r.status_code == 200
    assert r.json()[0]["subject_cn"] == "api.example"


def test_ssl_analyze_cert_invalid():
    r = client.post("/api/ssl/analyze-cert", json={"pem": "garbage"})
    assert r.status_code == 400


def test_ssl_scan_endpoint():
    cfg = "frontend web\n    bind *:443 ssl crt /nope/site.pem ciphers RC4\n"
    r = client.post("/api/ssl/scan", json={"content": cfg, "read_files": False})
    assert r.status_code == 200
    body = r.json()
    assert body["ciphers"][0]["grade"] == "F"
    assert any(ref["kind"] == "bind-crt" for ref in body["references"])
