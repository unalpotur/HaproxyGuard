import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app

@pytest_asyncio.fixture
async def client(db, session_factory, monkeypatch):
    import app.main as main_mod
    monkeypatch.setattr(main_mod.registry, "_sf", session_factory)
    monkeypatch.setattr(main_mod.channels, "_sf", session_factory)
    monkeypatch.setattr(main_mod.version_store, "_sf", session_factory)
    monkeypatch.setattr(main_mod.principals, "_sf", session_factory)
    monkeypatch.setattr(main_mod.audit, "_sf", session_factory)
    monkeypatch.setattr(main_mod.fix_engine, "_sf", session_factory)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

CFG = """\
frontend web
    bind *:80
    default_backend app

backend app
    server s1 10.0.0.1:8080 check
"""

async def test_health(client):
    r = await client.get("/api/health")
    assert r.json() == {"status": "ok"}

async def test_local_config_reads_configured_path(client, tmp_path, monkeypatch):
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text("defaults\n    mode http\n")
    monkeypatch.setenv("HG_LOCAL_CONFIG", str(cfg))
    r = await client.get("/api/local-config")
    assert r.status_code == 200
    assert r.json()["content"] == "defaults\n    mode http\n"
    assert r.json()["path"] == str(cfg)

async def test_local_config_missing_path_404(client, monkeypatch):
    monkeypatch.setenv("HG_LOCAL_CONFIG", "/nonexistent/haproxy.cfg")
    r = await client.get("/api/local-config")
    assert r.status_code == 404

async def test_parse_endpoint(client):
    r = await client.post("/api/parse", json={"content": CFG})
    assert r.status_code == 200
    data = r.json()
    assert data["frontends"][0]["name"] == "web"
    assert data["backends"][0]["servers"][0]["name"] == "s1"

async def test_analyze_endpoint(client):
    r = await client.post("/api/analyze", json={"content": CFG})
    assert r.status_code == 200
    assert "summary" in r.json()

async def test_topology_endpoint(client):
    r = await client.post("/api/topology", json={"content": CFG})
    g = r.json()
    ids = {n["id"] for n in g["nodes"]}
    assert {"fe:web", "be:app", "srv:app/s1"} <= ids
    assert {"source": "fe:web", "target": "be:app", "label": "default"} in g["edges"]

async def test_analyze_marks_fixable(client):
    r = await client.post("/api/analyze", json={"content": "defaults\n    mode http\n"})
    findings = r.json()["findings"]
    hg008 = next(f for f in findings if f["rule_id"] == "HG008")
    assert hg008["fixable"] is True

async def test_fix_preview_and_apply_and_rollback(client):
    cfg = "defaults\n    mode http\n"
    r_prev = await client.post("/api/fix/preview",
                       json={"content": cfg, "run_validation": False})
    prev = r_prev.json()
    assert prev["changed"] is True
    assert prev["version_id"] is None  # preview never persists
    assert "timeout connect" in prev["proposed_content"]

    r_applied = await client.post("/api/fix/apply",
                          json={"content": cfg, "run_validation": False})
    applied = r_applied.json()
    vid = applied["version_id"]
    assert vid

    rb = await client.post("/api/fix/rollback", json={"version_id": vid})
    assert rb.status_code == 200
    assert rb.json()["content"] == cfg

async def test_fix_rollback_unknown_version(client):
    r = await client.post("/api/fix/rollback", json={"version_id": "nope"})
    assert r.status_code == 404

async def test_ssl_analyze_cert_endpoint(client):
    from tests.test_sslmgr import make_cert
    pem = make_cert("api.example", days_valid=200)
    r = await client.post("/api/ssl/analyze-cert", json={"pem": pem})
    assert r.status_code == 200
    assert r.json()[0]["subject_cn"] == "api.example"

async def test_ssl_analyze_cert_invalid(client):
    r = await client.post("/api/ssl/analyze-cert", json={"pem": "garbage"})
    assert r.status_code == 400

async def test_ssl_scan_endpoint(client):
    cfg = "frontend web\n    bind *:443 ssl crt /nope/site.pem ciphers RC4\n"
    r = await client.post("/api/ssl/scan", json={"content": cfg, "read_files": False})
    assert r.status_code == 200
    body = r.json()
    assert body["ciphers"][0]["grade"] == "F"
    assert any(ref["kind"] == "bind-crt" for ref in body["references"])

async def test_security_catalog_endpoint(client):
    r = await client.get("/api/security/catalog")
    body = r.json()
    assert any(cat["id"] == "request_rate" for cat in body["controls"])
    assert any(p["id"] == "strict" for p in body["presets"])

async def test_security_generate_preset(client):
    r = await client.post("/api/security/generate", json={"preset": "basic"})
    assert r.status_code == 200
    body = r.json()
    assert body["preset"] == "basic"
    assert any("stick-table" in l for l in body["frontend_lines"])

async def test_security_generate_unknown_preset(client):
    r = await client.post("/api/security/generate", json={"preset": "ghost"})
    assert r.status_code == 404

async def test_security_generate_requires_input(client):
    r = await client.post("/api/security/generate", json={})
    assert r.status_code == 400

async def test_security_posture_endpoint(client):
    cfg = "frontend web\n    bind *:80\n    default_backend a\nbackend a\n    server s 1.1.1.1:80\n"
    r = await client.post("/api/security/posture", json={"content": cfg})
    body = r.json()
    assert body["total"] >= 5
    assert 0 <= body["score"] <= 100

async def test_assistant_status_endpoint(client):
    r = await client.get("/api/assistant/status")
    assert r.status_code == 200
    assert "llm_available" in r.json()

async def test_assistant_analyze_endpoint(client):
    cfg = "frontend web\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0\n    default_backend ghost\n"
    r = await client.post("/api/assistant/analyze", json={"content": cfg, "use_llm": False, "include_metrics": False})
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_level"] in ("low", "medium", "high", "critical")
    assert body["used_llm"] is False
    assert isinstance(body["root_causes"], list)

async def test_cluster_enroll_deploy_heartbeat_flow(client):
    enroll = await client.post("/api/cluster/nodes",
                         json={"name": "edge-1", "address": "10.0.0.1", "labels": {"role": "edge"}})
    assert enroll.status_code == 200
    body = enroll.json()
    node_id = body["node"]["id"]
    token = body["token"]
    assert body["node"]["status"] == "pending"

    cfg = "defaults\n    mode http\n"
    dep = await client.post("/api/cluster/deploy",
                      json={"content": cfg, "node_ids": [node_id], "validate_config": False})
    assert dep.json()["deployments"][0]["status"] == "pending"

    hb = await client.post(f"/api/agent/{node_id}/heartbeat",
                     json={"haproxy_version": "2.8"},
                     headers={"Authorization": f"Bearer {token}"})
    assert hb.status_code == 200
    assert hb.json()["desired_config"] == cfg

    nodes = await client.get("/api/cluster/nodes")
    me = next(n for n in nodes.json() if n["id"] == node_id)
    assert me["status"] == "online" and me["haproxy_version"] == "2.8"

async def test_agent_heartbeat_rejects_bad_token(client):
    r_node = await client.post("/api/cluster/nodes",
                          json={"name": "n", "address": "10.0.0.9"})
    node_id = r_node.json()["node"]["id"]
    r = await client.post(f"/api/agent/{node_id}/heartbeat", json={},
                    headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401

async def test_cluster_overview_endpoint(client):
    r = await client.get("/api/cluster/overview")
    assert r.status_code == 200
    assert "total" in r.json()

async def test_alerts_evaluate_endpoint(client):
    cfg = "frontend f\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0 ciphers RC4\n    default_backend ghost\n"
    r = await client.post("/api/alerts/evaluate",
                    json={"content": cfg, "logs": "", "include_cluster": False})
    assert r.status_code == 200
    alerts = r.json()
    assert any(a["source"] == "config" for a in alerts)
    assert any(a["severity"] == "critical" for a in alerts)

async def test_alerts_channel_crud_and_dispatch(client):
    add = await client.post("/api/alerts/channels",
                      json={"name": "ops", "type": "webhook",
                            "url": "http://127.0.0.1:9/none", "min_severity": "high"})
    cid = add.json()["id"]
    r_list = await client.get("/api/alerts/channels")
    assert any(c["id"] == cid for c in r_list.json())

    cfg = "frontend f\n    bind *:80\n    default_backend ghost\n"
    disp = await client.post("/api/alerts/dispatch", json={"content": cfg, "logs": "", "include_cluster": False})
    body = disp.json()
    assert body["alerts"]
    assert body["results"] and body["results"][0]["ok"] is False

    r_del1 = await client.delete(f"/api/alerts/channels/{cid}")
    assert r_del1.status_code == 200
    r_del2 = await client.delete(f"/api/alerts/channels/{cid}")
    assert r_del2.status_code == 404

async def test_whoami_open_mode_is_anonymous_admin(client):
    r = await client.get("/api/auth/whoami")
    assert r.status_code == 200
    assert r.json()["role"] == "admin"

async def test_versions_save_diff_restore_flow(client):
    save1 = await client.post("/api/versions", json={"content": "defaults\n    mode http\n",
                                               "label": "v-initial"})
    assert save1.status_code == 200
    vid1 = save1.json()["id"]
    save2 = await client.post("/api/versions",
                        json={"content": "defaults\n    mode http\n    timeout connect 5s\n"})
    vid2 = save2.json()["id"]

    r_diff = await client.get(f"/api/versions/diff?a={vid1}&b={vid2}")
    diff = r_diff.json()
    assert "+    timeout connect 5s" in diff["diff"]

    got = await client.get(f"/api/versions/{vid1}")
    assert got.json()["version"]["label"] == "v-initial"

    r_restore = await client.post(f"/api/versions/{vid1}/restore")
    restore = r_restore.json()
    assert restore["content"] == "defaults\n    mode http\n"
    assert restore["version"]["message"] == f"restore of {vid1}"

async def test_versions_diff_route_not_shadowed_by_id(client):
    r = await client.get("/api/versions/diff?a=v1&b=v1")
    assert r.status_code in (200, 404)

async def test_mutating_action_is_audited(client):
    await client.post("/api/cluster/nodes", json={"name": "audited-node", "address": "10.9.9.9"})
    r_audit = await client.get("/api/audit")
    audit = r_audit.json()
    assert any(e["action"] == "cluster.enroll" and e["target"] == "audited-node"
               for e in audit)
    assert audit[0]["actor"] == "anonymous"
