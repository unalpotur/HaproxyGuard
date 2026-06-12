import pytest

from app.parser.parser import parse_config
from app.security import (
    catalog, generate, generate_preset, assess, PRESETS,
)
from app.security.models import ControlRequest
from app.autofix.validator import haproxy_binary, validate


def _wrap(frontend_lines: list[str], global_lines: list[str] | None = None) -> str:
    g = "\n".join("    " + l for l in (global_lines or []))
    fe = "\n".join("    " + l for l in frontend_lines)
    return (
        "global\n    maxconn 2000\n" + (g + "\n" if g else "") +
        "defaults\n    mode http\n    timeout connect 5s\n"
        "    timeout client 30s\n    timeout server 30s\n"
        "frontend web\n    bind *:8080\n" + fe + "\n    default_backend app\n"
        "backend app\n    server s1 127.0.0.1:9999\n"
    )


def test_catalog_and_presets_nonempty():
    assert len(catalog()) >= 5
    assert "strict" in PRESETS and "basic" in PRESETS


def test_generate_preset_shares_single_table():
    cfg = generate_preset("strict")
    table_lines = [l for l in cfg.frontend_lines if l.startswith("stick-table")]
    track_lines = [l for l in cfg.frontend_lines if "track-sc0" in l]
    assert len(table_lines) == 1  # one shared stick-table
    assert len(track_lines) == 1
    # all four counters present in the single table
    for counter in ("http_req_rate", "conn_rate", "conn_cur", "http_err_rate"):
        assert counter in table_lines[0]


def test_generate_explicit_controls():
    cfg = generate([ControlRequest(id="request_rate", params={"rate": 5})])
    assert any("sc_http_req_rate(0) gt 5" in l for l in cfg.frontend_lines)
    assert "request rate" in cfg.snippet.lower()


def test_generate_unknown_control_raises():
    with pytest.raises(KeyError):
        generate([ControlRequest(id="nope")])


def test_geo_block_notes_and_map():
    cfg = generate([ControlRequest(id="geo_block", params={"countries": ["RU"]})])
    assert any("map_ip(" in l for l in cfg.frontend_lines)
    assert any("map file" in n for n in cfg.notes)


def test_admin_protection_allowlist():
    cfg = generate([ControlRequest(id="admin_protection",
                                   params={"networks": "10.0.0.0/8"})])
    assert any("acl admin_allowed src 10.0.0.0/8" in l for l in cfg.frontend_lines)
    assert any("deny if !admin_allowed" in l for l in cfg.frontend_lines)


def test_posture_detects_present_and_absent():
    cfg = parse_config(
        "frontend web\n    bind *:80\n"
        "    stick-table type ip size 100k expire 30s store http_req_rate(10s)\n"
        "    tcp-request connection track-sc0 src\n"
        "    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }\n"
    )
    posture = assess(cfg)
    by_id = {c.id: c for c in posture.controls}
    assert by_id["request_rate"].present is True
    assert "web" in by_id["request_rate"].sections
    assert by_id["geo_block"].present is False
    assert 0 < posture.score < 100


def test_posture_admin_protection_detected():
    cfg = parse_config(
        "listen stats\n    bind *:8404\n    stats enable\n"
        "    acl admin_allowed src 10.0.0.0/8\n    http-request deny if !admin_allowed\n"
    )
    posture = assess(cfg)
    by_id = {c.id: c for c in posture.controls}
    assert by_id["admin_protection"].present is True


@pytest.mark.skipif(haproxy_binary() is None, reason="haproxy binary not installed")
@pytest.mark.parametrize("preset_id", ["basic", "strict", "api", "ddos-mitigation"])
def test_generated_presets_validate_with_haproxy(preset_id):
    cfg = generate_preset(preset_id)
    full = _wrap(cfg.frontend_lines, cfg.global_lines)
    result = validate(full)
    assert result.ran
    assert result.ok, result.message
