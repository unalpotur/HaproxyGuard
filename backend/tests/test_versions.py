from app.versions import VersionStore

A = "defaults\n    mode http\n"
B = "defaults\n    mode http\n    timeout connect 5s\n"


def test_save_creates_linear_history():
    store = VersionStore()
    v1 = store.save(A, label="initial", author="alice")
    v2 = store.save(B, message="add timeout", author="bob")
    assert v1.id == "v1" and v2.id == "v2"
    assert v2.parent_id == "v1"
    assert v1.author == "alice" and v2.author == "bob"
    assert v1.content_hash != v2.content_hash
    # newest first
    assert [v.id for v in store.list()] == ["v2", "v1"]


def test_saving_identical_content_is_noop():
    store = VersionStore()
    v1 = store.save(A)
    v2 = store.save(A)  # no change since tip
    assert v1.id == v2.id
    assert len(store.list()) == 1


def test_get_content_and_metadata():
    store = VersionStore()
    store.save(A)
    assert store.content("v1") == A
    assert store.get("v1").size == len(A)
    assert store.content("missing") is None


def test_diff_between_versions():
    store = VersionStore()
    store.save(A)
    store.save(B)
    diff = store.diff("v1", "v2")
    assert diff.startswith("--- v1")
    assert "+    timeout connect 5s" in diff


def test_diff_unknown_version_raises():
    store = VersionStore()
    store.save(A)
    try:
        store.diff("v1", "v99")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_restore_creates_new_version_with_old_content():
    store = VersionStore()
    store.save(A)
    store.save(B)
    restored = store.restore("v1", author="carol")
    assert restored.id == "v3"
    assert restored.message == "restore of v1"
    assert store.content("v3") == A  # content matches the restored version
    assert restored.author == "carol"


def test_restore_unknown_returns_none():
    assert VersionStore().restore("v1") is None
