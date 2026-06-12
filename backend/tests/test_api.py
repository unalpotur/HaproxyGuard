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


def test_security_catalog_endpoint():
    r = client.get("/api/security/catalog")
    body = r.json()
    assert any(c["id"] == "request_rate" for c in body["controls"])
    assert any(p["id"] == "strict" for p in body["presets"])


def test_security_generate_preset():
    r = client.post("/api/security/generate", json={"preset": "basic"})
    assert r.status_code == 200
    body = r.json()
    assert body["preset"] == "basic"
    assert any("stick-table" in l for l in body["frontend_lines"])


def test_security_generate_unknown_preset():
    r = client.post("/api/security/generate", json={"preset": "ghost"})
    assert r.status_code == 404


def test_security_generate_requires_input():
    r = client.post("/api/security/generate", json={})
    assert r.status_code == 400


def test_security_posture_endpoint():
    cfg = "frontend web\n    bind *:80\n    default_backend a\nbackend a\n    server s 1.1.1.1:80\n"
    r = client.post("/api/security/posture", json={"content": cfg})
    body = r.json()
    assert body["total"] >= 5
    assert 0 <= body["score"] <= 100


def test_assistant_status_endpoint():
    r = client.get("/api/assistant/status")
    assert r.status_code == 200
    assert "llm_available" in r.json()


def test_assistant_analyze_endpoint():
    cfg = "frontend web\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0\n    default_backend ghost\n"
    r = client.post("/api/assistant/analyze", json={"content": cfg, "use_llm": False})
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] in ("low", "medium", "high", "critical")
    assert body["used_llm"] is False
    assert isinstance(body["root_causes"], list)


def test_cluster_enroll_deploy_heartbeat_flow():
    enroll = client.post("/api/cluster/nodes",
                         json={"name": "edge-1", "address": "10.0.0.1", "labels": {"role": "edge"}})
    assert enroll.status_code == 200
    body = enroll.json()
    node_id = body["node"]["id"]
    token = body["token"]
    assert body["node"]["status"] == "pending"

    # deploy a config to the node (no validation — env-independent)
    cfg = "defaults\n    mode http\n"
    dep = client.post("/api/cluster/deploy",
                      json={"content": cfg, "node_ids": [node_id], "validate_config": False})
    assert dep.json()["deployments"][0]["status"] == "pending"

    # agent heartbeat with valid token receives the desired config
    hb = client.post(f"/api/agent/{node_id}/heartbeat",
                     json={"haproxy_version": "2.8"},
                     headers={"Authorization": f"Bearer {token}"})
    assert hb.status_code == 200
    assert hb.json()["desired_config"] == cfg

    # node now shows online in the dashboard
    nodes = client.get("/api/cluster/nodes").json()
    me = next(n for n in nodes if n["id"] == node_id)
    assert me["status"] == "online" and me["haproxy_version"] == "2.8"


def test_agent_heartbeat_rejects_bad_token():
    node_id = client.post("/api/cluster/nodes",
                          json={"name": "n", "address": "10.0.0.9"}).json()["node"]["id"]
    r = client.post(f"/api/agent/{node_id}/heartbeat", json={},
                    headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_cluster_overview_endpoint():
    r = client.get("/api/cluster/overview")
    assert r.status_code == 200
    assert "total" in r.json()


def test_alerts_evaluate_endpoint():
    cfg = "frontend f\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0 ciphers RC4\n    default_backend ghost\n"
    r = client.post("/api/alerts/evaluate",
                    json={"content": cfg, "include_cluster": False})
    assert r.status_code == 200
    alerts = r.json()
    assert any(a["source"] == "config" for a in alerts)
    assert any(a["severity"] == "critical" for a in alerts)


def test_alerts_channel_crud_and_dispatch():
    add = client.post("/api/alerts/channels",
                      json={"name": "ops", "type": "webhook",
                            "url": "http://127.0.0.1:9/none", "min_severity": "high"})
    cid = add.json()["id"]
    assert any(c["id"] == cid for c in client.get("/api/alerts/channels").json())

    # dispatch to an unreachable channel: alerts found, send reported as failed (not raised)
    cfg = "frontend f\n    bind *:80\n    default_backend ghost\n"
    disp = client.post("/api/alerts/dispatch", json={"content": cfg, "include_cluster": False})
    body = disp.json()
    assert body["alerts"]
    assert body["results"] and body["results"][0]["ok"] is False

    assert client.delete(f"/api/alerts/channels/{cid}").status_code == 200
    assert client.delete(f"/api/alerts/channels/{cid}").status_code == 404
