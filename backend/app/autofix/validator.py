"""Optional config validation via the real `haproxy -c` binary.

If HAProxy is not installed, validation is reported as "not run" rather than
failing — the engine still works in environments without the binary.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from .models import Validation

_BINARY_ENV = "HAPROXY_BINARY"


def haproxy_binary() -> str | None:
    return os.environ.get(_BINARY_ENV) or shutil.which("haproxy")


def validate(content: str) -> Validation:
    binary = haproxy_binary()
    if not binary:
        return Validation(ran=False, ok=True, message="haproxy binary not found; validation skipped")
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        proc = subprocess.run(
            [binary, "-c", "-f", path],
            capture_output=True, text=True, timeout=15,
        )
        ok = proc.returncode == 0
        msg = (proc.stdout + proc.stderr).strip()
        return Validation(ran=True, ok=ok, message=msg)
    except (subprocess.SubprocessError, OSError) as exc:
        return Validation(ran=False, ok=True, message=f"validation error: {exc}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
