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
