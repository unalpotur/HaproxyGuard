"""Registry mapping analyzer rule_ids to safe auto-fix functions.

A fixer takes the current config text and a single Finding, and returns the
new text plus a short summary. Returning text identical to the input means
"no change" (the engine treats that as skipped). Fixers must be idempotent and
must never delete user content beyond the specific issue they target.
"""
from __future__ import annotations

from typing import Callable

from ..analyzer.registry import Finding

# (new_content, summary). new_content == input => no-op.
FixFunc = Callable[[str, Finding], tuple[str, str]]

FIXES: dict[str, FixFunc] = {}


def fix(rule_id: str) -> Callable[[FixFunc], FixFunc]:
    def deco(func: FixFunc) -> FixFunc:
        FIXES[rule_id] = func
        return func
    return deco


def has_fix(rule_id: str) -> bool:
    return rule_id in FIXES


def get_fix(rule_id: str) -> FixFunc | None:
    return FIXES.get(rule_id)
