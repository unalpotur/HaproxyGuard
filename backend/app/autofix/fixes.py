"""Concrete auto-fixers. Each is conservative and additive where possible."""
from __future__ import annotations

from ..analyzer.registry import Finding
from . import _lines as L
from .registry import fix

SAFE_TIMEOUTS = {"connect": "5s", "client": "30s", "server": "30s"}


def _insert_into_section(content: str, kind: str, name: str | None,
                         new_directives: list[str]) -> str | None:
    """Insert directives at the end of a section body. Returns None if the
    section is missing (caller decides whether to create it)."""
    lines = L.split(content)
    loc = L.find_section(lines, kind, name)
    if loc is None:
        return None
    start, end = loc
    indent = L.body_indent(lines, start, end)
    anchor = L.last_body_line(lines, start, end)
    block = [indent + d for d in new_directives]
    lines[anchor + 1: anchor + 1] = block
    return L.join(lines)


@fix("HG008")
def add_missing_timeouts(content: str, finding: Finding) -> tuple[str, str]:
    lines = L.split(content)
    loc = L.find_section(lines, "defaults", None)
    present: set[str] = set()
    if loc:
        start, end = loc
        for k in range(start + 1, end):
            toks = lines[k].strip().split()
            if len(toks) >= 2 and toks[0] == "timeout":
                present.add(toks[1])
    missing = [f"timeout {k} {v}" for k, v in SAFE_TIMEOUTS.items() if k not in present]
    if not missing:
        return content, "timeouts already present"
    if loc is None:
        # create a minimal defaults section at the top
        block = ["defaults"] + [L.DEFAULT_INDENT + d for d in missing] + [""]
        return L.join(block + lines), f"added defaults with {len(missing)} timeout(s)"
    out = _insert_into_section(content, "defaults", None, missing)
    return out or content, f"added {', '.join(missing)}"


@fix("HG006")
def pin_tls_min_version(content: str, finding: Finding) -> tuple[str, str]:
    """Append 'ssl-min-ver TLSv1.2' to ssl bind lines that don't pin it."""
    lines = L.split(content)
    loc = L.find_section(lines, "frontend", finding.section) \
        or L.find_section(lines, "listen", finding.section)
    if loc is None:
        return content, "section not found"
    start, end = loc
    changed = 0
    for k in range(start + 1, end):
        toks = lines[k].strip().split()
        if toks[:1] == ["bind"] and "ssl" in toks and "ssl-min-ver" not in toks:
            lines[k] = lines[k].rstrip() + " ssl-min-ver TLSv1.2"
            changed += 1
    if not changed:
        return content, "no eligible bind"
    return L.join(lines), f"pinned ssl-min-ver on {changed} bind(s)"


@fix("HG037")
def remove_forced_legacy_protocol(content: str, finding: Finding) -> tuple[str, str]:
    legacy = {"force-sslv3", "force-tlsv10", "force-tlsv11"}
    lines = L.split(content)
    loc = L.find_section(lines, "frontend", finding.section) \
        or L.find_section(lines, "listen", finding.section)
    if loc is None:
        return content, "section not found"
    start, end = loc
    removed = 0
    for k in range(start + 1, end):
        toks = lines[k].split()
        if toks[:1] == ["bind"] and any(t in legacy for t in toks):
            kept = [t for t in toks if t not in legacy]
            indent = lines[k][: len(lines[k]) - len(lines[k].lstrip())]
            lines[k] = indent + " ".join(kept)
            removed += 1
    if not removed:
        return content, "no legacy token found"
    return L.join(lines), f"removed legacy protocol token from {removed} bind(s)"


@fix("HG022")
def add_redispatch(content: str, finding: Finding) -> tuple[str, str]:
    out = _insert_into_section(content, "backend", finding.section, ["option redispatch"]) \
        or _insert_into_section(content, "listen", finding.section, ["option redispatch"])
    if out is None:
        return content, "section not found"
    return out, "added 'option redispatch'"


@fix("HG026")
def set_default_mode(content: str, finding: Finding) -> tuple[str, str]:
    out = _insert_into_section(content, "defaults", None, ["mode http"])
    if out is None:
        return content, "no defaults section"
    return out, "added 'mode http' to defaults"


@fix("HG046")
def enable_logging(content: str, finding: Finding) -> tuple[str, str]:
    lines = L.split(content)
    summary = []
    if L.find_section(lines, "global", None):
        out = _insert_into_section(content, "global", None, ["log /dev/log local0"])
        if out:
            content = out
            summary.append("global log target")
    if L.find_section(L.split(content), "defaults", None):
        out = _insert_into_section(content, "defaults", None, ["log global"])
        if out:
            content = out
            summary.append("defaults log global")
    if not summary:
        return content, "no global/defaults section to add logging"
    return content, "added " + " + ".join(summary)
