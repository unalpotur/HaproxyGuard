"""Configuration analysis rules (Phase 4 — initial rule set)."""
from __future__ import annotations

from typing import Callable
from pydantic import BaseModel

from ..parser.models import HaproxyConfig


class Finding(BaseModel):
    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str
    section: str | None = None
    line_number: int | None = None
    suggestion: str | None = None


RuleFunc = Callable[[HaproxyConfig], list[Finding]]
RULES: list[RuleFunc] = []


def rule(func: RuleFunc) -> RuleFunc:
    RULES.append(func)
    return func


def analyze(config: HaproxyConfig) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        findings.extend(r(config))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return findings


@rule
def unused_backends(config: HaproxyConfig) -> list[Finding]:
    referenced: set[str] = set()
    for fe in list(config.frontends) + list(config.listens):
        if fe.default_backend:
            referenced.add(fe.default_backend)
        for r in fe.switching_rules:
            referenced.add(r.backend)
    return [
        Finding(
            rule_id="HG001", severity="low",
            title="Unused backend",
            detail=f"Backend '{b.name}' is never referenced by any frontend.",
            section=b.name, line_number=b.line_number,
            suggestion=f"Remove backend '{b.name}' or wire it to a frontend.",
        )
        for b in config.backends if b.name not in referenced
    ]


@rule
def duplicate_bind_ports(config: HaproxyConfig) -> list[Finding]:
    seen: dict[tuple[str, int], str] = {}
    findings = []
    for fe in list(config.frontends) + list(config.listens):
        for b in fe.binds:
            if b.port is None:
                continue
            key = (b.address, b.port)
            if key in seen and seen[key] != fe.name:
                findings.append(Finding(
                    rule_id="HG002", severity="high",
                    title="Duplicate bind address",
                    detail=f"'{fe.name}' binds {b.address}:{b.port}, already bound by '{seen[key]}'.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion="Use distinct ports or consolidate the frontends.",
                ))
            else:
                seen[key] = fe.name
    return findings


@rule
def missing_health_checks(config: HaproxyConfig) -> list[Finding]:
    return [
        Finding(
            rule_id="HG003", severity="medium",
            title="Missing health checks",
            detail=f"Backend '{b.name}' has servers but no health checking.",
            section=b.name, line_number=b.line_number,
            suggestion="Add 'check' to server lines and/or 'option httpchk'.",
        )
        for b in list(config.backends) + list(config.listens)
        if b.servers and not b.has_health_check
    ]


@rule
def unknown_backend_references(config: HaproxyConfig) -> list[Finding]:
    known = config.backend_names()
    findings = []
    for fe in list(config.frontends) + list(config.listens):
        targets = [r.backend for r in fe.switching_rules]
        if fe.default_backend:
            targets.append(fe.default_backend)
        for t in targets:
            # dynamic backend names (log-format style) can't be validated statically
            if t and "%" not in t and t not in known:
                findings.append(Finding(
                    rule_id="HG004", severity="critical",
                    title="Reference to unknown backend",
                    detail=f"Frontend '{fe.name}' references backend '{t}' which does not exist.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion=f"Define backend '{t}' or fix the reference.",
                ))
    return findings


@rule
def weak_ssl(config: HaproxyConfig) -> list[Finding]:
    findings = []
    weak_versions = {"SSLv3", "TLSv1.0", "TLSv1.1"}
    for fe in list(config.frontends) + list(config.listens):
        for b in fe.binds:
            if not b.ssl:
                continue
            min_ver = b.options.get("ssl-min-ver")
            if isinstance(min_ver, str) and min_ver in weak_versions:
                findings.append(Finding(
                    rule_id="HG005", severity="high",
                    title="Weak TLS minimum version",
                    detail=f"'{fe.name}' allows {min_ver} on {b.address}:{b.port}.",
                    section=fe.name,
                    suggestion="Set 'ssl-min-ver TLSv1.2' or higher.",
                ))
            elif min_ver is None:
                findings.append(Finding(
                    rule_id="HG006", severity="low",
                    title="No explicit TLS minimum version",
                    detail=f"SSL bind in '{fe.name}' does not pin ssl-min-ver.",
                    section=fe.name,
                    suggestion="Add 'ssl-min-ver TLSv1.2' to the bind line.",
                ))
    return findings


@rule
def stats_exposure(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for sec_list, getter in ((config.listens, True), (config.frontends, True)):
        for fe in sec_list:
            directives = fe.directives
            has_stats = any(d.keyword == "stats enable" for d in directives)
            has_auth = any(d.keyword == "stats auth" for d in directives)
            public = any(b.address in ("*", "0.0.0.0", "::") for b in fe.binds)
            if has_stats and public and not has_auth:
                findings.append(Finding(
                    rule_id="HG007", severity="critical",
                    title="Stats endpoint exposed without authentication",
                    detail=f"'{fe.name}' enables stats on a public bind with no 'stats auth'.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion="Add 'stats auth user:password' or bind to localhost.",
                ))
    return findings


@rule
def missing_timeouts(config: HaproxyConfig) -> list[Finding]:
    defaults_timeouts: set[str] = set()
    for d in config.defaults:
        for directive in d.directives:
            if directive.keyword.startswith("timeout "):
                defaults_timeouts.add(directive.keyword.split(" ", 1)[1])
    required = {"client", "server", "connect"}
    missing = required - defaults_timeouts
    if not missing:
        return []
    return [Finding(
        rule_id="HG008", severity="medium",
        title="Missing default timeouts",
        detail=f"Defaults section missing timeouts: {', '.join(sorted(missing))}.",
        suggestion="Set 'timeout client/server/connect' in defaults to avoid hung connections.",
    )]
