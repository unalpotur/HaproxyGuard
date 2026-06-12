"""Core analyzer registry: the Finding model, the @rule decorator and analyze().

Rules live in the `rules/` package as small functions that take a parsed
`HaproxyConfig` and return a list of `Finding`. Each rule registers itself with
the global `RULES` list via the `@rule` decorator. This keeps the catalog
extensible — a community rule is just a decorated function in a category module.
"""
from __future__ import annotations

from typing import Callable, Iterable
from pydantic import BaseModel

from ..parser.models import (
    Backend, Frontend, HaproxyConfig, Listen, Section,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Finding(BaseModel):
    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str
    category: str = ""
    section: str | None = None
    line_number: int | None = None
    suggestion: str | None = None


RuleFunc = Callable[[HaproxyConfig], list[Finding]]
RULES: list[RuleFunc] = []
_SEEN_IDS: set[str] = set()


def rule(func: RuleFunc) -> RuleFunc:
    """Register a rule function. Idempotent across re-imports."""
    if func not in RULES:
        RULES.append(func)
    return func


def analyze(config: HaproxyConfig) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        try:
            findings.extend(r(config))
        except Exception as exc:  # a buggy rule must never break the whole run
            findings.append(Finding(
                rule_id="HG000", severity="info", category="internal",
                title="Rule crashed",
                detail=f"Rule '{getattr(r, '__name__', r)}' raised: {exc!r}",
            ))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), f.rule_id))
    return findings


# --- shared helpers used across rule modules -------------------------------

def frontend_like(config: HaproxyConfig) -> list[Frontend | Listen]:
    """Sections that can have binds / routing (frontends + listens)."""
    return [*config.frontends, *config.listens]


def backend_like(config: HaproxyConfig) -> list[Backend | Listen]:
    """Sections that can have servers (backends + listens)."""
    return [*config.backends, *config.listens]


def all_proxies(config: HaproxyConfig) -> list[Frontend | Backend | Listen]:
    return [*config.frontends, *config.backends, *config.listens]


def section_kind(proxy) -> str:
    if isinstance(proxy, Listen):
        return "listen"
    if isinstance(proxy, Frontend):
        return "frontend"
    return "backend"


def has_option(proxy, name: str) -> bool:
    """True if `option <name>` is set on the proxy (options store the text
    after 'option ', e.g. 'httplog', 'forwardfor except 127.0.0.1')."""
    return any(o == name or o.startswith(name + " ") for o in proxy.options)


def has_directive(proxy, keyword: str) -> bool:
    return any(d.keyword == keyword for d in proxy.directives)


def get_directive(proxy, keyword: str):
    for d in proxy.directives:
        if d.keyword == keyword:
            return d
    return None


def iter_directives(section: Section | None):
    return iter(section.directives) if section else iter(())


def global_has(config: HaproxyConfig, keyword: str) -> bool:
    g = config.global_section
    return bool(g) and any(d.keyword == keyword for d in g.directives)


def effective_mode(config: HaproxyConfig, proxy) -> str | None:
    """Resolve the proxy mode, falling back to the defaults section."""
    if proxy.mode:
        return proxy.mode
    for d in config.defaults:
        m = d.get("mode")
        if m and m.args:
            return m.args[0]
    return None


def defaults_directives(config: HaproxyConfig) -> Iterable:
    for d in config.defaults:
        yield from d.directives
