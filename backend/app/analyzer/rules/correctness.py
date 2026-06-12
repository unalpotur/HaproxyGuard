"""Correctness rules: references, duplicates and structural mistakes."""
from __future__ import annotations

import re

from ..registry import (
    Finding, rule, frontend_like, backend_like, all_proxies, section_kind,
)
from ...parser.models import HaproxyConfig

CATEGORY = "correctness"

_ACL_TOKEN = re.compile(r"[A-Za-z_][\w.\-]*")
_LOGIC_WORDS = {"if", "unless", "or", "||", "&&", "!"}


@rule
def unused_backends(config: HaproxyConfig) -> list[Finding]:
    referenced: set[str] = set()
    for fe in frontend_like(config):
        if fe.default_backend:
            referenced.add(fe.default_backend)
        for r in fe.switching_rules:
            referenced.add(r.backend)
    return [
        Finding(
            rule_id="HG001", severity="low", category=CATEGORY,
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
    for fe in frontend_like(config):
        for b in fe.binds:
            if b.port is None:
                continue
            key = (b.address, b.port)
            if key in seen and seen[key] != fe.name:
                findings.append(Finding(
                    rule_id="HG002", severity="high", category=CATEGORY,
                    title="Duplicate bind address",
                    detail=f"'{fe.name}' binds {b.address}:{b.port}, already bound by '{seen[key]}'.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion="Use distinct ports or consolidate the frontends.",
                ))
            else:
                seen[key] = fe.name
    return findings


@rule
def unknown_backend_references(config: HaproxyConfig) -> list[Finding]:
    known = config.backend_names()
    findings = []
    for fe in frontend_like(config):
        targets = [r.backend for r in fe.switching_rules]
        if fe.default_backend:
            targets.append(fe.default_backend)
        for t in targets:
            # dynamic backend names (log-format style) can't be validated statically
            if t and "%" not in t and t not in known:
                findings.append(Finding(
                    rule_id="HG004", severity="critical", category=CATEGORY,
                    title="Reference to unknown backend",
                    detail=f"Frontend '{fe.name}' references backend '{t}' which does not exist.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion=f"Define backend '{t}' or fix the reference.",
                ))
    return findings


@rule
def duplicate_proxy_names(config: HaproxyConfig) -> list[Finding]:
    seen: dict[tuple[str, str], int] = {}
    findings = []
    for p in all_proxies(config):
        key = (section_kind(p), p.name)
        if key in seen:
            findings.append(Finding(
                rule_id="HG009", severity="high", category=CATEGORY,
                title="Duplicate proxy name",
                detail=f"{key[0]} '{p.name}' is defined more than once "
                       f"(also at line {seen[key]}).",
                section=p.name, line_number=p.line_number,
                suggestion="Proxy names must be unique within their type; rename or merge.",
            ))
        else:
            seen[key] = p.line_number
    return findings


@rule
def duplicate_server_names(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        seen: set[str] = set()
        for s in be.servers:
            if s.name in seen:
                findings.append(Finding(
                    rule_id="HG010", severity="medium", category=CATEGORY,
                    title="Duplicate server name",
                    detail=f"Backend '{be.name}' has two servers named '{s.name}'.",
                    section=be.name, line_number=be.line_number,
                    suggestion="Server names must be unique within a backend.",
                ))
            seen.add(s.name)
    return findings


def _acl_names_in_condition(condition: str | None) -> set[str]:
    if not condition:
        return set()
    names = set()
    for tok in _ACL_TOKEN.findall(condition):
        if tok in _LOGIC_WORDS:
            continue
        names.add(tok)
    return names


@rule
def undefined_acl_in_condition(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        defined = {a.name for a in fe.acls}
        for r in fe.switching_rules:
            for name in _acl_names_in_condition(r.condition):
                # skip things that look like inline anonymous ACLs (contain a path/operator)
                if "(" in name or "/" in name or "." in name:
                    continue
                if name not in defined:
                    findings.append(Finding(
                        rule_id="HG011", severity="medium", category=CATEGORY,
                        title="Condition uses undefined ACL",
                        detail=f"'{fe.name}' routes on ACL '{name}' which is not defined in this frontend.",
                        section=fe.name, line_number=fe.line_number,
                        suggestion=f"Define 'acl {name} ...' or correct the condition.",
                    ))
    return findings


@rule
def unused_acl(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        used: set[str] = set()
        for r in fe.switching_rules:
            used |= _acl_names_in_condition(r.condition)
        # also consider http-request/redirect conditions referencing the acl
        for d in fe.directives:
            if d.keyword.startswith(("http-request", "http-response", "tcp-request")):
                used |= _acl_names_in_condition(" ".join(d.args))
        for a in fe.acls:
            if a.name not in used:
                findings.append(Finding(
                    rule_id="HG012", severity="low", category=CATEGORY,
                    title="Unused ACL",
                    detail=f"ACL '{a.name}' in '{fe.name}' is declared but never referenced.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion=f"Remove ACL '{a.name}' or use it in a routing/condition rule.",
                ))
    return findings


@rule
def frontend_without_bind(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        if not fe.binds:
            findings.append(Finding(
                rule_id="HG013", severity="high", category=CATEGORY,
                title="Frontend without a bind",
                detail=f"{section_kind(fe)} '{fe.name}' has no bind line and will not accept traffic.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add a 'bind' line or remove the section.",
            ))
    return findings


@rule
def frontend_without_route(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in config.frontends:  # listens serve their own servers, exclude them
        if not fe.default_backend and not fe.switching_rules:
            findings.append(Finding(
                rule_id="HG014", severity="high", category=CATEGORY,
                title="Frontend routes nowhere",
                detail=f"Frontend '{fe.name}' has neither default_backend nor use_backend rules.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add a 'default_backend' or 'use_backend' rule.",
            ))
    return findings


@rule
def unconditional_use_backend_shadows(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        rules = fe.switching_rules
        for i, r in enumerate(rules[:-1]):
            if r.operator is None:  # unconditional use_backend
                shadowed = [x.backend for x in rules[i + 1:]]
                findings.append(Finding(
                    rule_id="HG015", severity="medium", category=CATEGORY,
                    title="Unreachable routing rules",
                    detail=f"'{fe.name}' has an unconditional 'use_backend {r.backend}' "
                           f"before other rules ({', '.join(shadowed)}), which can never match.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion="Move the unconditional use_backend last or add a condition.",
                ))
                break
    return findings


@rule
def server_without_address(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        for s in be.servers:
            if not s.address:
                findings.append(Finding(
                    rule_id="HG016", severity="high", category=CATEGORY,
                    title="Server without an address",
                    detail=f"Server '{s.name}' in backend '{be.name}' has no address.",
                    section=be.name, line_number=be.line_number,
                    suggestion="Provide '<server> <address>:<port>'.",
                ))
    return findings


@rule
def invalid_port(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        for b in fe.binds:
            if b.port is not None and not (1 <= b.port <= 65535):
                findings.append(Finding(
                    rule_id="HG017", severity="medium", category=CATEGORY,
                    title="Invalid bind port",
                    detail=f"'{fe.name}' binds {b.address}:{b.port} — port out of range 1-65535.",
                    section=fe.name, line_number=fe.line_number,
                ))
    for be in backend_like(config):
        for s in be.servers:
            if s.port is not None and not (1 <= s.port <= 65535):
                findings.append(Finding(
                    rule_id="HG018", severity="medium", category=CATEGORY,
                    title="Invalid server port",
                    detail=f"Server '{s.name}' in '{be.name}' uses port {s.port} (out of range).",
                    section=be.name, line_number=be.line_number,
                ))
    return findings


@rule
def parse_errors_surfaced(config: HaproxyConfig) -> list[Finding]:
    return [
        Finding(
            rule_id="HG019", severity="medium", category=CATEGORY,
            title="Parser warning",
            detail=err,
            suggestion="Review the configuration line; it may be misplaced or malformed.",
        )
        for err in config.parse_errors
    ]
