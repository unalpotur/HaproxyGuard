#!/usr/bin/env python3
"""HAProxy Guard host agent — systemd and Docker modes.

Runs on a machine where HAProxy is reachable, either as a systemd service or a
Docker container. It periodically heartbeats the Guard control plane, and when a
new desired config is published it validates, writes, reloads and reports back.

Self-contained (standard library only) so it can be copied to any host. Configure
via environment variables:

    GUARD_URL          Control plane base URL          (e.g. http://guard.local:8000)
    NODE_ID            Node id from enrollment         (node_xxx)
    NODE_TOKEN         Bearer token from enrollment

Manage mode — how HAProxy is controlled on this host:

    MANAGE_MODE        'systemd' (default) or 'docker'

systemd mode (default):
    HAPROXY_CFG        Config path       (default: /etc/haproxy/haproxy.cfg)
    HAPROXY_BIN        Binary            (default: haproxy, resolved on PATH)
    RELOAD_CMD         Reload command    (default: systemctl reload haproxy)
    RESTART_CMD         Restart command   (default: systemctl restart haproxy)
    STOP_CMD            Stop command      (default: systemctl stop haproxy)
    START_CMD           Start command     (default: systemctl start haproxy)

Docker mode:
    HAPROXY_CFG        Config path on host            (default: /etc/haproxy/haproxy.cfg)
    CONTAINER_NAME     Docker container name           (default: haproxy)
    CONTAINER_CFG_PATH Config path inside container    (default: /usr/local/etc/haproxy/haproxy.cfg)

Common:
    INTERVAL           Seconds between heartbeats      (default: 10)
    AGENT_VERSION      Reported agent version          (default: 2.1.0)
    CERT_DIR           Directory for cert files        (default: /etc/haproxy/certs)

Auto-enrollment — set ENROLL_KEY instead of NODE_ID / NODE_TOKEN:
    ENROLL_KEY         Pre-shared key (HG_ADMIN_KEY on control plane)
    NODE_NAME          Display name    (default: hostname)
    NODE_ADDRESS       Address         (default: hostname)
    NODE_LABELS        k=v,k=v labels  (default: empty)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

AGENT_VERSION = os.environ.get("AGENT_VERSION", "2.1.0")
_VERSION_RE = re.compile(r"HAProxy version (\S+)")
_STATE_FILE = os.path.join(os.path.expanduser("~"), ".haproxy-guard-agent", "state.json")


# ── helpers (mode-agnostic) ──────────────────────────────────────────────

def config_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


def parse_haproxy_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def decide(desired_version, desired_config, current_version, current_content) -> str:
    if desired_version is None:
        return "noop"
    if desired_config is not None and desired_config == current_content:
        return "adopt"
    return "apply"


def _run(cmd: list[str], timeout: float = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _http_post(url: str, data: dict, headers: dict = None) -> dict:
    """Simple HTTP POST returning parsed JSON."""
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _parse_labels(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            labels[k.strip()] = v.strip()
    return labels


# ── state persistence ────────────────────────────────────────────────────

def _load_state() -> dict | None:
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f)


# ── auto-enrollment ──────────────────────────────────────────────────────

def auto_enroll(url: str) -> tuple[str, str]:
    """Register this host with the control plane, return (node_id, token)."""
    enroll_key = os.environ.get("ENROLL_KEY", "")
    name = os.environ.get("NODE_NAME") or socket.gethostname()
    address = os.environ.get("NODE_ADDRESS") or socket.gethostname()
    labels = _parse_labels(os.environ.get("NODE_LABELS", ""))

    print(f"[agent] auto-enrolling as name={name} address={address} labels={labels}")

    headers = {"X-API-Key": enroll_key} if enroll_key else {}
    resp = _http_post(f"{url.rstrip('/')}/api/cluster/nodes",
                      {"name": name, "address": address, "labels": labels},
                      headers=headers)

    node_id = resp["node"]["id"]
    token = resp["token"]
    _save_state({"node_id": node_id, "token": token})
    print(f"[agent] enrolled: node_id={node_id}")
    return node_id, token


# ── systemd mode backend ─────────────────────────────────────────────────

def _systemd_binary() -> str:
    return os.environ.get("HAPROXY_BIN") or shutil.which("haproxy") or "haproxy"


def _systemd_version() -> str | None:
    code, out = _run([_systemd_binary(), "-v"])
    return parse_haproxy_version(out) if code == 0 else None


def _systemd_validate(content: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        code, out = _run([_systemd_binary(), "-c", "-f", path])
        return code == 0, out
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _systemd_apply(content: str, cfg_path: str, reload_cmd: list[str]) -> tuple[bool, str]:
    try:
        if os.path.exists(cfg_path):
            shutil.copy2(cfg_path, cfg_path + ".guard.bak")
        with open(cfg_path, "w") as f:
            f.write(content)
        code, out = _run(reload_cmd, timeout=30)
        if code != 0:
            return False, f"reload failed: {out}"
        return True, "applied and reloaded"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _systemd_run_action(cmd: list[str]) -> tuple[bool, str]:
    code, out = _run(cmd, timeout=30)
    return code == 0, out


# ── Docker mode backend ──────────────────────────────────────────────────

def _docker_exec(cmd: str, timeout: float = 20) -> tuple[int, str]:
    container = os.environ.get("CONTAINER_NAME", "haproxy")
    return _run(["docker", "exec", container] + shlex.split(cmd), timeout=timeout)


def _docker_version() -> str | None:
    code, out = _docker_exec("haproxy -v")
    return parse_haproxy_version(out) if code == 0 else None


def _docker_validate(content: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(content)
        host_temp = f.name

    container_name = os.environ.get("CONTAINER_NAME", "haproxy")
    container_temp = "/tmp/guard_validate.cfg"

    try:
        code, out = _run(["docker", "cp", host_temp,
                          f"{container_name}:{container_temp}"])
        if code != 0:
            return False, f"docker cp into container failed: {out}"

        code, out = _docker_exec(f"haproxy -c -f {container_temp}")
        return code == 0, out
    finally:
        try:
            os.unlink(host_temp)
        except OSError:
            pass
        _run(["docker", "exec", container_name, "rm", "-f", container_temp])


def _docker_apply(content: str, cfg_path: str, _reload_cmd_unused=None) -> tuple[bool, str]:
    container_name = os.environ.get("CONTAINER_NAME", "haproxy")
    container_cfg = os.environ.get("CONTAINER_CFG_PATH",
                                   "/usr/local/etc/haproxy/haproxy.cfg")

    try:
        if os.path.exists(cfg_path):
            shutil.copy2(cfg_path, cfg_path + ".guard.bak")

        with open(cfg_path, "w") as f:
            f.write(content)

        code, out = _run(["docker", "cp", cfg_path,
                          f"{container_name}:{container_cfg}"])
        if code != 0:
            return False, f"docker cp into container failed: {out}"

        code, out = _run(["docker", "kill", "-s", "HUP", container_name],
                         timeout=30)
        if code != 0:
            return False, f"reload failed: {out}"
        return True, "applied and reloaded (docker)"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _docker_run_action(cmd: list[str]) -> tuple[bool, str]:
    code, out = _run(cmd, timeout=30)
    return code == 0, out


# ── mode dispatch ────────────────────────────────────────────────────────

_MODE = os.environ.get("MANAGE_MODE", "systemd").lower()

if _MODE == "docker":
    haproxy_version_fn = _docker_version
    validate_fn = _docker_validate
    apply_config_fn = _docker_apply
    run_action_fn = _docker_run_action
    _CONTAINER = os.environ.get("CONTAINER_NAME", "haproxy")
elif _MODE == "systemd":
    haproxy_version_fn = _systemd_version
    validate_fn = _systemd_validate
    apply_config_fn = _systemd_apply
    run_action_fn = _systemd_run_action
    _CONTAINER = None
else:
    print(f"[agent] unknown MANAGE_MODE={_MODE!r}; use 'systemd' or 'docker'",
          file=sys.stderr)
    sys.exit(1)


# ── Actions ──────────────────────────────────────────────────────────────

def _action_restart() -> tuple[bool, str]:
    if _MODE == "docker":
        return run_action_fn(["docker", "restart", _CONTAINER])
    else:
        cmd = shlex.split(os.environ.get("RESTART_CMD", "systemctl restart haproxy"))
        return run_action_fn(cmd)


def _action_stop() -> tuple[bool, str]:
    if _MODE == "docker":
        return run_action_fn(["docker", "stop", _CONTAINER])
    else:
        cmd = shlex.split(os.environ.get("STOP_CMD", "systemctl stop haproxy"))
        return run_action_fn(cmd)


def _action_start() -> tuple[bool, str]:
    if _MODE == "docker":
        return run_action_fn(["docker", "start", _CONTAINER])
    else:
        cmd = shlex.split(os.environ.get("START_CMD", "systemctl start haproxy"))
        return run_action_fn(cmd)


def _action_config_get(params: dict | None = None) -> tuple[bool, str]:
    cfg_path = os.environ.get("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg")
    try:
        with open(cfg_path, "rb") as f:
            return True, base64.b64encode(f.read()).decode()
    except OSError as e:
        return False, str(e)


def _action_cert_list() -> tuple[bool, str]:
    cert_dir = os.environ.get("CERT_DIR", "/etc/haproxy/certs")
    try:
        if not os.path.isdir(cert_dir):
            return True, json.dumps([])
        files = sorted(os.listdir(cert_dir))
        result = []
        for name in files:
            fpath = os.path.join(cert_dir, name)
            if os.path.isfile(fpath):
                result.append({"name": name, "size": os.path.getsize(fpath)})
        return True, json.dumps(result)
    except OSError as e:
        return False, str(e)


def _action_cert_upload(params: dict) -> tuple[bool, str]:
    name = params.get("name", "")
    content_b64 = params.get("content", "")
    if not name or not content_b64:
        return False, "missing 'name' or 'content' in cert-upload params"
    if "/" in name or name.startswith("."):
        return False, f"invalid cert name: {name!r}"
    try:
        data = base64.b64decode(content_b64)
    except Exception as e:
        return False, f"base64 decode failed: {e}"

    cert_dir = os.environ.get("CERT_DIR", "/etc/haproxy/certs")
    fpath = os.path.join(cert_dir, name)
    try:
        os.makedirs(cert_dir, exist_ok=True)
        with open(fpath, "wb") as f:
            f.write(data)
        return True, f"cert wrote {len(data)} bytes to {fpath}"
    except OSError as e:
        return False, str(e)


def _action_cert_delete(params: dict) -> tuple[bool, str]:
    name = params.get("name", "")
    if not name:
        return False, "missing 'name' in cert-delete params"
    if "/" in name or name.startswith("."):
        return False, f"invalid cert name: {name!r}"
    cert_dir = os.environ.get("CERT_DIR", "/etc/haproxy/certs")
    fpath = os.path.join(cert_dir, name)
    try:
        os.unlink(fpath)
        return True, f"deleted {fpath}"
    except OSError as e:
        return False, str(e)


_ACTIONS = {
    "restart": _action_restart,
    "stop": _action_stop,
    "start": _action_start,
    "config-get": _action_config_get,
    "cert-list": _action_cert_list,
    "cert-upload": _action_cert_upload,
    "cert-delete": _action_cert_delete,
}


def handle_action(action: dict | None) -> dict | None:
    if not action:
        return None
    action_type = action.get("type", "")
    params = action.get("params", {})
    handler = _ACTIONS.get(action_type)
    if handler is None:
        return {"type": action_type, "ok": False, "error": f"unknown action: {action_type}"}
    if action_type in ("cert-upload", "cert-delete"):
        ok, msg = handler(params)
    else:
        ok, msg = handler()
    return {"type": action_type, "ok": ok, "error" if not ok else "output": msg}


# ── heartbeat HTTP helper ────────────────────────────────────────────────

def heartbeat(url: str, node_id: str, token: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/agent/{node_id}/heartbeat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


# ── main loop ────────────────────────────────────────────────────────────


def main() -> int:
    url = os.environ.get("GUARD_URL")
    if not url:
        print("GUARD_URL is required", file=sys.stderr)
        return 2

    node_id = os.environ.get("NODE_ID")
    token = os.environ.get("NODE_TOKEN")

    # ── auto-enrollment ───────────────────────────────────────────────
    if not node_id or not token:
        # try saved state first
        saved = _load_state()
        if saved:
            node_id = saved.get("node_id", "")
            token = saved.get("token", "")
            if node_id and token:
                print(f"[agent] loaded state: node={node_id}")
        # enroll if still no credentials
        if not node_id or not token:
            if not os.environ.get("ENROLL_KEY"):
                print("Set ENROLL_KEY (same as HG_ADMIN_KEY) to auto-enroll, "
                      "or NODE_ID+NODE_TOKEN from manual enrollment",
                      file=sys.stderr)
                return 2
            try:
                node_id, token = auto_enroll(url)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                print(f"[agent] auto-enroll failed: {exc}", file=sys.stderr)
                return 2

    cfg_path = os.environ.get("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg")
    interval = float(os.environ.get("INTERVAL", "10"))

    if _MODE == "systemd":
        reload_cmd = shlex.split(os.environ.get("RELOAD_CMD", "systemctl reload haproxy"))
    else:
        reload_cmd = []

    hav = haproxy_version_fn()

    current_version: int | None = None
    current_content = ""
    if os.path.exists(cfg_path):
        try:
            current_content = open(cfg_path).read()
        except OSError:
            pass

    print(f"[agent] v{AGENT_VERSION} mode={_MODE} node={node_id} "
          f"cfg={cfg_path} haproxy={hav} → {url}")

    last_action_result: dict | None = None

    while True:
        # Check HAProxy service status
        service_status = "running"
        if _MODE == "docker":
            code, out = _run(["docker", "inspect", "-f", "{{.State.Running}}", _CONTAINER], timeout=5)
            if code != 0 or "true" not in out.lower():
                service_status = "stopped"
        elif _MODE == "systemd":
            code, _ = _run(["systemctl", "is-active", "haproxy"], timeout=5)
            if code != 0:
                service_status = "stopped"

        payload = {
            "agent_version": AGENT_VERSION,
            "haproxy_version": hav,
            "config_version": current_version,
            "config_hash": config_hash(current_content),
            "service_status": service_status,
        }
        if last_action_result:
            payload["last_action"] = last_action_result
            last_action_result = None

        try:
            reply = heartbeat(url, node_id, token, payload)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"[agent] heartbeat error: {exc}", file=sys.stderr)
            time.sleep(interval)
            continue

        pending = reply.get("action")
        if pending:
            print(f"[agent] action received: {pending.get('type')}")
            last_action_result = handle_action(pending)
            if last_action_result:
                ok = last_action_result.get("ok", False)
                status = "OK" if ok else "FAIL"
                detail = last_action_result.get("error") or last_action_result.get("output", "")
                print(f"[agent] action {pending['type']}: {status} - {detail[:120]}")

        decision = decide(reply.get("desired_version"),
                          reply.get("desired_config"),
                          current_version, current_content)

        if decision == "adopt":
            current_version = reply["desired_version"]
            print(f"[agent] config already current; adopted version {current_version}")

        elif decision == "apply":
            desired = reply["desired_config"]
            ok, msg = validate_fn(desired)
            if not ok:
                print(f"[agent] desired config failed validation, "
                      f"keeping current: {msg}", file=sys.stderr)
            else:
                ok, msg = apply_config_fn(desired, cfg_path, reload_cmd)
                if ok:
                    current_content = desired
                    current_version = reply["desired_version"]
                    print(f"[agent] {msg}; now at version {current_version}")
                else:
                    print(f"[agent] {msg}", file=sys.stderr)

        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
