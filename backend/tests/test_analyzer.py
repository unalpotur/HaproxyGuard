from pathlib import Path

from app.parser.parser import parse_config
from app.analyzer.rules import analyze

EXAMPLE = (Path(__file__).resolve().parents[2] / "examples" / "haproxy.cfg").read_text()


def _ids(findings):
    return {f.rule_id for f in findings}


def test_example_findings():
    findings = analyze(parse_config(EXAMPLE))
    ids = _ids(findings)
    assert "HG001" in ids  # orphan_backend unused
    assert "HG003" in ids  # static_servers no health check
    assert "HG007" in ids  # stats without auth on public bind
    assert "HG004" not in ids  # all references valid
    assert "HG008" not in ids  # timeouts present


def test_unknown_backend_reference():
    cfg = parse_config("frontend f\n    bind *:80\n    default_backend ghost\n")
    assert "HG004" in _ids(analyze(cfg))


def test_duplicate_bind():
    cfg = parse_config(
        "frontend a\n    bind *:80\nfrontend b\n    bind *:80\n"
    )
    assert "HG002" in _ids(analyze(cfg))


def test_weak_tls():
    cfg = parse_config("frontend f\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0\n")
    assert "HG005" in _ids(analyze(cfg))


def test_missing_timeouts_flagged():
    cfg = parse_config("defaults\n    mode http\n")
    assert "HG008" in _ids(analyze(cfg))


# --- expanded Phase 4 catalog --------------------------------------------

def test_no_rule_crashes_on_example():
    # HG000 is the sentinel emitted when a rule raises.
    assert "HG000" not in _ids(analyze(parse_config(EXAMPLE)))


def test_all_findings_have_category():
    for f in analyze(parse_config(EXAMPLE)):
        assert f.category, f.rule_id


def test_duplicate_proxy_name():
    cfg = parse_config("backend b\n    server s1 1.1.1.1:80\nbackend b\n    server s2 1.1.1.2:80\n")
    assert "HG009" in _ids(analyze(cfg))


def test_duplicate_server_name():
    cfg = parse_config("backend b\n    server s 1.1.1.1:80\n    server s 1.1.1.2:80\n")
    assert "HG010" in _ids(analyze(cfg))


def test_undefined_acl_in_condition():
    cfg = parse_config("frontend f\n    bind *:80\n    use_backend b if missing_acl\nbackend b\n    server s 1.1.1.1:80\n")
    assert "HG011" in _ids(analyze(cfg))


def test_unused_acl():
    cfg = parse_config("frontend f\n    bind *:80\n    acl unused path_beg /x\n    default_backend b\nbackend b\n    server s 1.1.1.1:80\n")
    assert "HG012" in _ids(analyze(cfg))


def test_frontend_without_bind_and_route():
    cfg = parse_config("frontend f\n    acl a path_beg /x\n")
    ids = _ids(analyze(cfg))
    assert "HG013" in ids  # no bind
    assert "HG014" in ids  # no route


def test_unconditional_use_backend_shadows():
    cfg = parse_config(
        "frontend f\n    bind *:80\n    use_backend a\n    use_backend b if foo\n"
        "backend a\n    server s 1.1.1.1:80\nbackend b\n    server s 1.1.1.2:80\n"
    )
    assert "HG015" in _ids(analyze(cfg))


def test_all_backup_servers():
    cfg = parse_config("backend b\n    server s1 1.1.1.1:80 check backup\n    server s2 1.1.1.2:80 check backup\n")
    assert "HG021" in _ids(analyze(cfg))


def test_stats_admin_and_weak_creds():
    cfg = parse_config(
        "listen stats\n    bind *:8404\n    stats enable\n    stats admin if TRUE\n    stats auth admin:admin\n"
    )
    ids = _ids(analyze(cfg))
    assert "HG027" in ids  # admin on public bind
    assert "HG028" in ids  # weak credentials


def test_backend_tls_not_verified():
    cfg = parse_config("backend b\n    server s 1.1.1.1:443 ssl\n")
    assert "HG029" in _ids(analyze(cfg))


def test_weak_ciphers():
    cfg = parse_config("frontend f\n    bind *:443 ssl crt /x.pem ciphers RC4-SHA\n")
    assert "HG035" in _ids(analyze(cfg))


def test_forced_legacy_protocol():
    cfg = parse_config("frontend f\n    bind *:443 ssl crt /x.pem force-tlsv10\n")
    assert "HG037" in _ids(analyze(cfg))


def test_deprecated_nbproc():
    cfg = parse_config("global\n    nbproc 4\n")
    assert "HG041" in _ids(analyze(cfg))


def test_deprecated_directive():
    cfg = parse_config("backend b\n    reqrep ^Host:\\ foo Host:\\ bar\n    server s 1.1.1.1:80\n")
    assert "HG049" in _ids(analyze(cfg))


def test_no_logging():
    cfg = parse_config("global\n    maxconn 100\n")
    assert "HG046" in _ids(analyze(cfg))


def test_http_rules_in_tcp_mode():
    cfg = parse_config("frontend f\n    mode tcp\n    bind *:80\n    http-request deny\n    default_backend b\n")
    assert "HG052" in _ids(analyze(cfg))
