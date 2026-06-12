from app.autofix import FixEngine
from app.analyzer.rules import analyze
from app.parser.parser import parse_config


def _ids(content):
    return {f.rule_id for f in analyze(parse_config(content))}


def test_add_missing_timeouts_fix_clears_finding():
    cfg = "defaults\n    mode http\n"
    assert "HG008" in _ids(cfg)
    eng = FixEngine()
    prop = eng.dry_run(cfg, ["HG008"], run_validation=False)
    assert prop.changed
    assert "HG008" not in _ids(prop.proposed_content)
    assert any(a.rule_id == "HG008" for a in prop.applied)
    assert "timeout connect" in prop.proposed_content


def test_dry_run_does_not_mutate_input():
    cfg = "defaults\n    mode http\n"
    eng = FixEngine()
    prop = eng.dry_run(cfg, ["HG008"], run_validation=False)
    assert prop.original_content == cfg
    # the original string is unchanged; only proposed_content differs
    assert prop.proposed_content != cfg


def test_pin_tls_min_version():
    cfg = "frontend f\n    bind *:443 ssl crt /x.pem\n"
    eng = FixEngine()
    prop = eng.dry_run(cfg, ["HG006"], run_validation=False)
    assert "ssl-min-ver TLSv1.2" in prop.proposed_content
    assert "HG006" not in _ids(prop.proposed_content)


def test_remove_forced_legacy_protocol():
    cfg = "frontend f\n    bind *:443 ssl crt /x.pem force-tlsv10\n"
    eng = FixEngine()
    prop = eng.dry_run(cfg, ["HG037"], run_validation=False)
    assert "force-tlsv10" not in prop.proposed_content
    assert "HG037" not in _ids(prop.proposed_content)


def test_idempotent_fix_is_noop_second_time():
    cfg = "defaults\n    mode http\n"
    eng = FixEngine()
    once = eng.dry_run(cfg, ["HG008"], run_validation=False).proposed_content
    # re-running produces no further change (the finding no longer fires)
    twice = eng.dry_run(once, ["HG008"], run_validation=False)
    assert not twice.changed
    assert twice.proposed_content == once


def test_apply_then_rollback_restores_original():
    cfg = "defaults\n    mode http\n"
    eng = FixEngine()
    prop = eng.apply(cfg, ["HG008"], run_validation=False)
    assert prop.version_id is not None
    restored = eng.rollback(prop.version_id)
    assert restored.content == cfg


def test_rollback_unknown_version():
    eng = FixEngine()
    try:
        eng.rollback("does-not-exist")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_diff_is_produced():
    cfg = "defaults\n    mode http\n"
    prop = FixEngine().dry_run(cfg, ["HG008"], run_validation=False)
    assert prop.diff.startswith("---")
    assert "+++ haproxy.cfg (fixed)" in prop.diff


def test_unfixable_rule_skipped():
    # HG001 (unused backend) has no auto-fixer; engine leaves it untouched
    cfg = "backend orphan\n    server s 1.1.1.1:80 check\n"
    assert "HG001" in _ids(cfg)
    prop = FixEngine().dry_run(cfg, ["HG001"], run_validation=False)
    assert not prop.changed
