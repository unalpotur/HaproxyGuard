"""Mask secrets before sending a config to an external model.

Certificate paths, auth credentials and userlist passwords are replaced with a
redaction marker so that nothing sensitive leaves the host. The structure of the
configuration is preserved so the model can still reason about it.
"""
from __future__ import annotations

import re

REDACTION = "***REDACTED***"

# `stats auth user:password` -> keep user, mask password
_STATS_AUTH = re.compile(r"(\bstats\s+auth\s+\S+?:)\S+")
# userlist: `user name password <hash>` / `insecure-password <pw>`
_USER_PW = re.compile(r"((?:insecure-)?password\s+)\S+", re.IGNORECASE)
# bind/server crt, ca-file, crl-file paths
_FILE_OPT = re.compile(r"\b(crt|crt-list|ca-file|ca-base|crt-base|crl-file)\s+(\S+)")
# generic secret-ish tokens
_SECRETISH = re.compile(r"\b(secret|token|key)\s+\S+", re.IGNORECASE)


def sanitize(config_text: str) -> str:
    out_lines = []
    for line in config_text.splitlines():
        line = _STATS_AUTH.sub(rf"\1{REDACTION}", line)
        line = _USER_PW.sub(rf"\1{REDACTION}", line)
        line = _FILE_OPT.sub(lambda m: f"{m.group(1)} {_mask_path(m.group(2))}", line)
        line = _SECRETISH.sub(rf"\1 {REDACTION}", line)
        out_lines.append(line)
    return "\n".join(out_lines)


def _mask_path(path: str) -> str:
    """Keep the basename's extension hint but drop the directory & name."""
    if "." in path.rsplit("/", 1)[-1]:
        ext = path.rsplit(".", 1)[-1]
        return f"{REDACTION}.{ext}"
    return REDACTION
