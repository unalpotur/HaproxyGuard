"""Line/section utilities for text-level config edits.

Fixes operate directly on the raw configuration text so that comments and
unknown directives are preserved verbatim (round-trip safety). These helpers
locate section blocks and infer indentation without re-serialising the parsed
model.
"""
from __future__ import annotations

from ..parser.parser import SECTION_KEYWORDS

DEFAULT_INDENT = "    "


def split(content: str) -> list[str]:
    return content.splitlines()


def join(lines: list[str]) -> str:
    text = "\n".join(lines)
    return text + "\n" if text and not text.endswith("\n") else text


def is_section_header(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    return stripped.split()[0] in SECTION_KEYWORDS


def find_section(lines: list[str], kind: str, name: str | None) -> tuple[int, int] | None:
    """Return (header_index, body_end_index) for the matching section.

    body_end_index is exclusive and points just past the last body line
    (i.e. at the next section header or EOF). Returns None if not found.
    """
    start = None
    for i, line in enumerate(lines):
        if not is_section_header(line):
            continue
        toks = line.strip().split()
        if toks[0] != kind:
            continue
        sec_name = toks[1] if len(toks) > 1 else None
        if name is None or sec_name == name:
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if is_section_header(lines[j]):
            end = j
            break
    return start, end


def body_indent(lines: list[str], start: int, end: int) -> str:
    for k in range(start + 1, end):
        stripped = lines[k].strip()
        if stripped and not stripped.startswith("#"):
            return lines[k][: len(lines[k]) - len(lines[k].lstrip())] or DEFAULT_INDENT
    return DEFAULT_INDENT


def last_body_line(lines: list[str], start: int, end: int) -> int:
    """Index of the last non-blank body line (or the header if body is empty)."""
    for k in range(end - 1, start, -1):
        if lines[k].strip():
            return k
    return start
