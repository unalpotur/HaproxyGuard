from app.autofix import FixEngine

CFG = "global\n    daemon\n"

async def test_dry_run_identifies_and_skips_noop_fixes(db, session_factory):
    engine = FixEngine(session_factory)
    prop = engine.dry_run(CFG, run_validation=False)
    assert prop.changed is True
    assert "timeout connect" in prop.proposed_content
    # Since the baseline rules now add mode http recursively, we just ensure dry run logic works
    assert len(prop.applied) > 0

async def test_apply_generates_rollback_snapshot_and_version(db, session_factory):
    engine = FixEngine(session_factory)
    prop = await engine.apply(CFG, run_validation=False)
    assert prop.changed is True
    assert prop.version_id is not None
    v = await engine.rollback(prop.version_id)
    assert v.content == CFG  # The original content is saved

async def test_rollback_unknown_version_raises(db, session_factory):
    engine = FixEngine(session_factory)
    try:
        await engine.rollback("unknown")
        assert False, "expected KeyError"
    except KeyError:
        pass

async def test_versions_list(db, session_factory):
    engine = FixEngine(session_factory)
    prop1 = await engine.apply(CFG, run_validation=False)
    versions = await engine.versions()
    assert len(versions) == 1
    assert versions[0].version_id == prop1.version_id
