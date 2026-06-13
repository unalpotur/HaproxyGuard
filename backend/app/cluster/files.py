"""Detect external files an HAProxy config depends on.

A config text is not self-contained: it can reference TLS certificates, map
files, error pages, CA bundles and Lua scripts that must also exist on the
target host. We extract those paths so the control plane can warn about (and
ship) them before a deploy.
"""
from __future__ import annotations

import re

# Roots an agent is allowed to read from / write to. Anything outside these is
# rejected, so a config can never make the agent touch /etc/passwd & friends.
ALLOWED_ROOTS = (
    "/etc/haproxy/",
    "/var/lib/haproxy/",
    "/opt/haproxy-guard/",
    "/etc/ssl/",
)

# Each pattern captures a filesystem path argument of a directive.
_PATTERNS = (
    re.compile(r"\bcrt-list\s+(/\S+)"),
    re.compile(r"\bcrt\s+(/\S+)"),
    re.compile(r"\bca-file\s+(/\S+)"),
    re.compile(r"\bca-verify-file\s+(/\S+)"),
    re.compile(r"\bcrl-file\s+(/\S+)"),
    re.compile(r"\berrorfile\s+\d+\s+(/\S+)"),
    re.compile(r"\blua-load\s+(/\S+)"),
    # map_beg(/path,..), map(/path), map_dir(/path), map_reg(...), etc.
    re.compile(r"\bmap\w*\(\s*(/[^,)\s]+)"),
)


def extract_file_refs(config: str) -> list[str]:
    """Return the sorted, de-duplicated external file paths a config needs."""
    refs: set[str] = set()
    for raw in config.splitlines():
        line = raw.split("#", 1)[0]  # ignore comments
        if not line.strip():
            continue
        for pat in _PATTERNS:
            for m in pat.finditer(line):
                refs.add(m.group(1).rstrip(",;"))
    return sorted(refs)


def is_allowed_path(path: str) -> bool:
    """True if path is absolute, free of traversal, and under an allowed root."""
    if not path.startswith("/") or ".." in path.split("/"):
        return False
    return any(path.startswith(root) for root in ALLOWED_ROOTS)
