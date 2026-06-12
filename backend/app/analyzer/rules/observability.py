"""Observability rules: logging and tracing coverage."""
from __future__ import annotations

from ..registry import (
    Finding, rule, frontend_like, has_option, global_has, effective_mode,
)
from ...parser.models import HaproxyConfig

CATEGORY = "observability"


def _logging_configured(config: HaproxyConfig) -> bool:
    if global_has(config, "log"):
        return True
    for d in config.defaults:
        if any(dd.keyword == "log" for dd in d.directives):
            return True
    return False


@rule
def no_logging(config: HaproxyConfig) -> list[Finding]:
    if _logging_configured(config):
        return []
    return [Finding(
        rule_id="HG046", severity="medium", category=CATEGORY,
        title="No logging configured",
        detail="Neither global nor defaults define a 'log' target; HAProxy will emit no traffic logs.",
        section="global",
        suggestion="Add 'log /dev/log local0' (or a remote syslog) in global and 'log global' in defaults.",
    )]


@rule
def defaults_without_log_global(config: HaproxyConfig) -> list[Finding]:
    if not global_has(config, "log"):
        return []  # handled by HG046
    findings = []
    for d in config.defaults:
        has_log = any(dd.keyword == "log" for dd in d.directives)
        if not has_log:
            findings.append(Finding(
                rule_id="HG047", severity="low", category=CATEGORY,
                title="Defaults does not inherit logging",
                detail="A global 'log' target exists but the defaults section has no 'log global'.",
                line_number=d.line_number,
                suggestion="Add 'log global' to defaults so proxies emit logs.",
            ))
    return findings


@rule
def http_frontend_without_httplog(config: HaproxyConfig) -> list[Finding]:
    defaults_httplog = any(
        any(dd.keyword == "option httplog" for dd in d.directives)
        for d in config.defaults
    )
    if defaults_httplog:
        return []
    findings = []
    for fe in frontend_like(config):
        if effective_mode(config, fe) == "http" and fe.binds and not has_option(fe, "httplog"):
            findings.append(Finding(
                rule_id="HG048", severity="low", category=CATEGORY,
                title="HTTP frontend without httplog",
                detail=f"'{fe.name}' is http but lacks 'option httplog'; logs will be terse TCP-style lines.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add 'option httplog' for rich HTTP request logging.",
            ))
    return findings
