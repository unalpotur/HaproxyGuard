"""Reliability rules: health checks, timeouts, redundancy, failover."""
from __future__ import annotations

from ..registry import (
    Finding, rule, backend_like, has_option, has_directive, defaults_directives,
)
from ...parser.models import HaproxyConfig
from ._util import parse_duration_ms

CATEGORY = "reliability"


@rule
def missing_health_checks(config: HaproxyConfig) -> list[Finding]:
    return [
        Finding(
            rule_id="HG003", severity="medium", category=CATEGORY,
            title="Missing health checks",
            detail=f"Backend '{b.name}' has servers but no health checking.",
            section=b.name, line_number=b.line_number,
            suggestion="Add 'check' to server lines and/or 'option httpchk'.",
        )
        for b in backend_like(config)
        if b.servers and not b.has_health_check
    ]


@rule
def missing_timeouts(config: HaproxyConfig) -> list[Finding]:
    defaults_timeouts: set[str] = set()
    for d in defaults_directives(config):
        if d.keyword.startswith("timeout "):
            defaults_timeouts.add(d.keyword.split(" ", 1)[1])
    required = {"client", "server", "connect"}
    missing = required - defaults_timeouts
    if not missing:
        return []
    return [Finding(
        rule_id="HG008", severity="medium", category=CATEGORY,
        title="Missing default timeouts",
        detail=f"Defaults section missing timeouts: {', '.join(sorted(missing))}.",
        suggestion="Set 'timeout client/server/connect' in defaults to avoid hung connections.",
    )]


def _active_servers(be) -> list:
    return [s for s in be.servers if not s.backup]


@rule
def single_point_of_failure(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        active = _active_servers(be)
        if len(active) == 1 and not any(s.backup for s in be.servers):
            findings.append(Finding(
                rule_id="HG020", severity="low", category=CATEGORY,
                title="Single server backend",
                detail=f"Backend '{be.name}' has only one active server — no redundancy.",
                section=be.name, line_number=be.line_number,
                suggestion="Add a second server or a 'backup' server for failover.",
            ))
    return findings


@rule
def all_servers_backup(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        if be.servers and not _active_servers(be):
            findings.append(Finding(
                rule_id="HG021", severity="high", category=CATEGORY,
                title="No active servers",
                detail=f"Every server in backend '{be.name}' is marked 'backup' — no traffic by default.",
                section=be.name, line_number=be.line_number,
                suggestion="Remove 'backup' from at least one server.",
            ))
    return findings


@rule
def missing_redispatch(config: HaproxyConfig) -> list[Finding]:
    # option redispatch may be set once in the defaults section for all proxies
    defaults_redispatch = any(
        any(opt.keyword == "option redispatch" for opt in d.directives)
        for d in config.defaults
    )
    findings = []
    for be in backend_like(config):
        if be.has_health_check and not has_option(be, "redispatch") and not defaults_redispatch:
            findings.append(Finding(
                rule_id="HG022", severity="low", category=CATEGORY,
                title="No connection redispatch",
                detail=f"Backend '{be.name}' health-checks servers but lacks 'option redispatch'.",
                section=be.name, line_number=be.line_number,
                suggestion="Add 'option redispatch' so failed connections retry on another server.",
            ))
    return findings


@rule
def no_retries_with_redispatch(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        if has_option(be, "redispatch") and not has_directive(be, "retries"):
            findings.append(Finding(
                rule_id="HG023", severity="low", category=CATEGORY,
                title="Redispatch without retries",
                detail=f"Backend '{be.name}' sets 'option redispatch' but no 'retries' value.",
                section=be.name, line_number=be.line_number,
                suggestion="Set 'retries N' (default is 3) to control redispatch attempts.",
            ))
    return findings


@rule
def excessive_client_timeout(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        for kind, value in be.timeouts.items():
            ms = parse_duration_ms(value)
            if kind == "client" and ms is not None and ms > 10 * 60_000:
                findings.append(Finding(
                    rule_id="HG024", severity="low", category=CATEGORY,
                    title="Very large client timeout",
                    detail=f"'{be.name}' sets 'timeout client {value}' (> 10m); idle clients tie up resources.",
                    section=be.name, line_number=be.line_number,
                    suggestion="Use a shorter client timeout unless long-lived connections are required.",
                ))
    return findings


@rule
def tiny_connect_timeout(config: HaproxyConfig) -> list[Finding]:
    findings = []
    sources = list(backend_like(config))
    for be in sources:
        v = be.timeouts.get("connect")
        ms = parse_duration_ms(v) if v else None
        if ms is not None and ms < 1000:
            findings.append(Finding(
                rule_id="HG025", severity="low", category=CATEGORY,
                title="Very small connect timeout",
                detail=f"'{be.name}' sets 'timeout connect {v}' (< 1s); slow backends may be marked down spuriously.",
                section=be.name, line_number=be.line_number,
                suggestion="A connect timeout of 1-5s is typical.",
            ))
    return findings


@rule
def no_default_mode(config: HaproxyConfig) -> list[Finding]:
    has_defaults_mode = any(d.get("mode") for d in config.defaults)
    if has_defaults_mode or not config.defaults:
        return []
    return [Finding(
        rule_id="HG026", severity="low", category=CATEGORY,
        title="No mode set in defaults",
        detail="The defaults section does not set 'mode'; HAProxy defaults to tcp which is rarely intended.",
        suggestion="Set 'mode http' (or 'mode tcp') explicitly in defaults.",
    )]
