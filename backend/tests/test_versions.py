from app.versions import VersionStore

A = "defaults\n    mode http\n"
B = "defaults\n    mode http\n    timeout connect 5s\n"


async def test_save_creates_linear_history(db, session_factory):
    store = VersionStore(session_factory)
    v1 = await store.save(A, label="initial", author="alice")
    v2 = await store.save(B, message="add timeout", author="bob")
    assert v1.id == "v1" and v2.id == "v2"
    assert v2.parent_id == "v1"
    assert v1.author == "alice" and v2.author == "bob"
    assert v1.content_hash != v2.content_hash
    # newest first
    assert [v.id for v in await store.list()] == ["v2", "v1"]


async def test_saving_identical_content_is_noop(db, session_factory):
    store = VersionStore(session_factory)
    v1 = await store.save(A)
    v2 = await store.save(A)  # no change since tip
    assert v1.id == v2.id
    assert len(await store.list()) == 1


async def test_get_content_and_metadata(db, session_factory):
    store = VersionStore(session_factory)
    await store.save(A)
    assert await store.content("v1") == A
    assert (await store.get("v1")).size == len(A)
    assert await store.content("missing") is None


async def test_diff_between_versions(db, session_factory):
    store = VersionStore(session_factory)
    await store.save(A)
    await store.save(B)
    diff = await store.diff("v1", "v2")
    assert diff.startswith("--- v1")
    assert "+    timeout connect 5s" in diff


async def test_diff_unknown_version_raises(db, session_factory):
    store = VersionStore(session_factory)
    await store.save(A)
    try:
        await store.diff("v1", "v99")
        assert False, "expected KeyError"
    except KeyError:
        pass


async def test_restore_creates_new_version_with_old_content(db, session_factory):
    store = VersionStore(session_factory)
    await store.save(A)
    await store.save(B)
    restored = await store.restore("v1", author="carol")
    assert restored.id == "v3"
    assert restored.message == "restore of v1"
    assert await store.content("v3") == A  # content matches the restored version
    assert restored.author == "carol"


async def test_restore_unknown_returns_none(db, session_factory):
    assert await VersionStore(session_factory).restore("v1") is None
