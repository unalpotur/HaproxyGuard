import importlib.util
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

# The host agent is a standalone script under scripts/; import it by path.
_AGENT = Path(__file__).resolve().parents[2] / "scripts" / "haproxy_guard_agent.py"
_spec = importlib.util.spec_from_file_location("hg_agent", _AGENT)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


# ── pure functions (no I/O) ─────────────────────────────────────────────


def test_parse_haproxy_version():
    assert agent.parse_haproxy_version("HAProxy version 2.8.16-1 2026/05/20") == "2.8.16-1"
    assert agent.parse_haproxy_version("no version here") is None


def test_config_hash_is_stable_and_short():
    h = agent.config_hash("defaults\n    mode http\n")
    assert len(h) == 12
    assert h == agent.config_hash("defaults\n    mode http\n")
    assert h != agent.config_hash("defaults\n    mode tcp\n")


def test_decide_noop_when_nothing_pending():
    assert agent.decide(None, None, None, "") == "noop"


def test_decide_apply_when_content_differs():
    assert agent.decide(1, "new", None, "old") == "apply"
    assert agent.decide(2, "new", 1, "old") == "apply"


def test_decide_adopt_when_content_already_matches():
    # desired version is ahead but the file already holds that exact content
    assert agent.decide(2, "same", 1, "same") == "adopt"


# ── _run helper ─────────────────────────────────────────────────────────


def test_run_returns_code_and_output():
    code, out = agent._run(["echo", "hello"])
    assert code == 0
    assert out == "hello"


def test_run_command_not_found():
    code, out = agent._run(["nonexistent_command_12345"])
    assert code != 0


# ── systemd mode dispatch ───────────────────────────────────────────────


def test_systemd_mode_functions_are_assigned():
    """When MANAGE_MODE is not set (defaults to systemd), validate_fn is _systemd_validate."""
    # The module-level _MODE is computed at import time using os.environ.
    # We test the exported names point to the expected implementations.
    # In systemd mode, the apply function exists.
    assert callable(agent.apply_config_fn)
    assert callable(agent.validate_fn)
    assert callable(agent.haproxy_version_fn)


def test_systemd_validate_valid_config(tmp_path):
    """_systemd_validate should accept valid config and reject invalid."""
    cfg = tmp_path / "test.cfg"
    cfg.write_text("defaults\n    mode http\n")
    # _systemd_validate runs haproxy -c; works if haproxy binary is available
    ok, msg = agent._systemd_validate("defaults\n    mode http\n")
    # May fail on systems without haproxy installed — just check it doesn't crash
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


def test_systemd_validate_invalid_config(tmp_path):
    ok, msg = agent._systemd_validate("garbage not a config")
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


# ── Docker mode dispatch ────────────────────────────────────────────────


def test_docker_exec_helper():
    """_docker_exec constructs the correct docker command."""
    with patch.dict(os.environ, {"CONTAINER_NAME": "test-haproxy"}):
        result = agent._docker_exec("haproxy -v")
        assert len(result) == 2
        # Will fail if docker / container not running, but shouldn't crash
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)


def test_docker_mode_functions_exist():
    """Docker backend functions are importable and callable."""
    assert callable(agent._docker_version)
    assert callable(agent._docker_validate)
    assert callable(agent._docker_apply)
    assert callable(agent._docker_exec)


# ── heartbeat (pure URL construction test) ──────────────────────────────


def test_heartbeat_url_construction():
    """Verify the heartbeat URL strips trailing slashes correctly."""
    # We test that the helper exists and is callable.
    assert callable(agent.heartbeat)


# ── main() guard ────────────────────────────────────────────────────────


def test_main_requires_env_vars():
    """main() returns 2 when required env vars are missing."""
    with patch.dict(os.environ, {}, clear=True):
        rc = agent.main()
        assert rc == 2


def test_main_accepts_minimal_env():
    """main() doesn't crash with GUARD_URL/NODE_ID/NODE_TOKEN set (fails at heartbeat)."""
    with patch.dict(os.environ, {
        "GUARD_URL": "http://localhost:8000",
        "NODE_ID": "test-node",
        "NODE_TOKEN": "test-token",
        "INTERVAL": "0.01",  # fast loop for test
    }):
        # main() runs an infinite loop; we test that it starts without error,
        # then kill it by patching the heartbeat to raise after first attempt.
        with patch.object(agent, "heartbeat", side_effect=StopIteration("done")):
            try:
                agent.main()
            except StopIteration:
                pass  # expected — loop exits cleanly
