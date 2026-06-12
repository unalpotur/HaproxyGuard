from app.authz import PrincipalRegistry, AuditLog, has_at_least


def test_role_ordering():
    assert has_at_least("admin", "operator")
    assert has_at_least("operator", "operator")
    assert not has_at_least("viewer", "operator")
    assert not has_at_least("operator", "admin")


def test_registry_open_until_a_principal_is_added():
    reg = PrincipalRegistry()
    assert reg.is_open() is True
    reg.add("alice", "admin")
    assert reg.is_open() is False


def test_token_auth_and_hash_storage():
    reg = PrincipalRegistry()
    created = reg.add("bob", "operator")
    assert created.token  # plaintext returned once
    # the stored hash is not the plaintext token
    assert created.token not in reg._token_hashes
    p = reg.authenticate(created.token)
    assert p is not None and p.name == "bob" and p.role == "operator"
    assert reg.authenticate("wrong") is None


def test_add_with_explicit_token_and_remove():
    reg = PrincipalRegistry()
    reg.add_with_token("admin", "admin", "secret-key")
    assert reg.authenticate("secret-key").role == "admin"
    assert reg.remove("admin") is True
    assert reg.authenticate("secret-key") is None
    assert reg.is_open() is True


def test_unknown_role_rejected():
    reg = PrincipalRegistry()
    try:
        reg.add("x", "superuser")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_audit_log_orders_newest_first_and_caps():
    log = AuditLog(maxlen=3)
    for i in range(5):
        log.append("alice", "admin", f"action.{i}")
    entries = log.list()
    assert len(entries) == 3  # capped
    assert entries[0].action == "action.4"  # newest first
    assert entries[0].id == 5
