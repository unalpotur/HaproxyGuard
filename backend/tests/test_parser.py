from pathlib import Path

from app.parser.parser import parse_config

EXAMPLE = (Path(__file__).resolve().parents[2] / "examples" / "haproxy.cfg").read_text()


def test_sections_detected():
    cfg = parse_config(EXAMPLE)
    assert cfg.global_section is not None
    assert len(cfg.defaults) == 1
    assert [f.name for f in cfg.frontends] == ["web"]
    assert {b.name for b in cfg.backends} == {
        "web_servers", "api_servers", "static_servers", "orphan_backend"
    }
    assert [l.name for l in cfg.listens] == ["stats"]
    assert cfg.parse_errors == []


def test_frontend_binds_and_rules():
    cfg = parse_config(EXAMPLE)
    fe = cfg.frontends[0]
    assert len(fe.binds) == 2
    https = fe.binds[1]
    assert https.port == 443 and https.ssl
    assert https.certificate == "/etc/haproxy/certs/site.pem"
    assert https.options.get("ssl-min-ver") == "TLSv1.2"
    assert fe.default_backend == "web_servers"
    assert {r.backend for r in fe.switching_rules} == {"api_servers", "static_servers"}
    rule = fe.switching_rules[0]
    assert rule.operator == "if" and rule.condition == "is_api"
    assert [a.name for a in fe.acls] == ["is_api", "is_static"]


def test_servers_parsed():
    cfg = parse_config(EXAMPLE)
    web = next(b for b in cfg.backends if b.name == "web_servers")
    assert web.balance == "roundrobin"
    assert web.has_health_check
    assert len(web.servers) == 3
    s1 = web.servers[0]
    assert (s1.name, s1.address, s1.port, s1.check, s1.weight) == ("web1", "10.0.0.11", 8080, True, 100)
    assert web.servers[2].backup

    api = next(b for b in cfg.backends if b.name == "api_servers")
    assert api.servers[0].maxconn == 200


def test_timeouts_and_mode():
    cfg = parse_config(EXAMPLE)
    d = cfg.defaults[0]
    timeouts = {x.keyword.split(" ", 1)[1]: x.args[0] for x in d.directives if x.keyword.startswith("timeout ")}
    assert timeouts == {"connect": "5s", "client": "30s", "server": "30s"}
    assert cfg.frontends[0].mode is None  # inherited from defaults


def test_ipv6_and_unix_binds():
    cfg = parse_config("frontend f\n    bind [::1]:443 ssl\n    bind unix@/var/run/hap.sock\n")
    binds = cfg.frontends[0].binds
    assert binds[0].address == "[::1]" and binds[0].port == 443
    assert binds[1].address == "unix@/var/run/hap.sock" and binds[1].port is None


def test_directive_outside_section_reported():
    cfg = parse_config("maxconn 100\nglobal\n    daemon\n")
    assert len(cfg.parse_errors) == 1
