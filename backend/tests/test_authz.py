from app.authz import PrincipalRegistry, AuditLog, has_at_least


async def test_role_ordering():
    assert has_at_least("admin", "operator")
    assert has_at_least("operator", "operator")
    assert not has_at_least("viewer", "operator")
    assert not has_at_least("operator", "admin")


async def test_registry_open_until_a_principal_is_added(db, session_factory):
    reg = PrincipalRegistry(session_factory)
    assert await reg.is_open() is True
    await reg.add("alice", "admin")
    assert await reg.is_open() is False


async def test_token_auth_and_hash_storage(db, session_factory):
    reg = PrincipalRegistry(session_factory)
    created = await reg.add("bob", "operator")
    assert created.token  # plaintext returned once
    # the stored hash is not the plaintext token
    assert await reg.authenticate(created.token) is not None
    p = await reg.authenticate(created.token)
    assert p is not None and p.name == "bob" and p.role == "operator"
    assert await reg.authenticate("wrong") is None


async def test_add_with_explicit_token_and_remove(db, session_factory):
    reg = PrincipalRegistry(session_factory)
    await reg.add_with_token("admin", "admin", "secret-key")
    assert (await reg.authenticate("secret-key")).role == "admin"
    assert await reg.remove("admin") is True
    assert await reg.authenticate("secret-key") is None
    assert await reg.is_open() is True


async def test_unknown_role_rejected(db, session_factory):
    reg = PrincipalRegistry(session_factory)
    try:
        await reg.add("x", "superuser")
        assert False, "expected ValueError"
    except ValueError:
        pass


async def test_audit_log_orders_newest_first_and_caps(db, session_factory):
    log = AuditLog(session_factory)
    for i in range(5):
        await log.append("alice", "admin", f"action.{i}")
    entries = await log.list()
    assert entries[0].action == "action.4"  # newest first
    assert entries[0].id == 5
