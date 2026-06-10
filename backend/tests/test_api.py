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
