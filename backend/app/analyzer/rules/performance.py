"""Performance & resource rules: connection limits, threading, keep-alive."""
from __future__ import annotations

from ..registry import (
    Finding, rule, backend_like, has_option,
)
from ...parser.models import HaproxyConfig

CATEGORY = "performance"


def _global_int(config: HaproxyConfig, keyword: str) -> int | None:
    g = config.global_section
    if not g:
        return None
    for d in g.directives:
        if d.keyword == keyword and d.args and d.args[0].isdigit():
            return int(d.args[0])
    return None


@rule
def global_maxconn_missing(config: HaproxyConfig) -> list[Finding]:
    if config.global_section is None:
        return []
    if _global_int(config, "maxconn") is None:
        return [Finding(
            rule_id="HG040", severity="low", category=CATEGORY,
            title="No global maxconn",
            detail="The global section sets no 'maxconn'; HAProxy will use a conservative default.",
            section="global",
            suggestion="Set 'maxconn' in global to size the connection table for your hardware.",
        )]
    return []


@rule
def deprecated_nbproc(config: HaproxyConfig) -> list[Finding]:
    n = _global_int(config, "nbproc")
    if n and n > 1:
        return [Finding(
            rule_id="HG041", severity="medium", category=CATEGORY,
            title="Deprecated multi-process (nbproc)",
            detail=f"global 'nbproc {n}' is deprecated since HAProxy 2.5 and complicates stats/stick-tables.",
            section="global",
            suggestion="Use a single process with 'nbthread' for multi-core scaling.",
        )]
    return []


@rule
def no_threading_configured(config: HaproxyConfig) -> list[Finding]:
    if config.global_section is None:
        return []
    if _global_int(config, "nbthread") is None and _global_int(config, "nbproc") is None:
        return [Finding(
            rule_id="HG042", severity="info", category=CATEGORY,
            title="Threading not configured",
            detail="global sets neither 'nbthread' nor 'nbproc'; HAProxy auto-detects but pinning is recommended.",
            section="global",
            suggestion="Set 'nbthread' to the number of available cores for predictable scaling.",
        )]
    return []


@rule
def server_without_maxconn(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        has_default_maxconn = any(
            d.keyword == "default-server" and "maxconn" in d.args for d in be.directives
        )
        if has_default_maxconn:
            continue
        unbounded = [s.name for s in be.servers if s.maxconn is None]
        if unbounded and len(unbounded) == len(be.servers) and be.servers:
            findings.append(Finding(
                rule_id="HG043", severity="low", category=CATEGORY,
                title="Servers without a connection limit",
                detail=f"No server in backend '{be.name}' sets 'maxconn'; a traffic spike can overwhelm them.",
                section=be.name, line_number=be.line_number,
                suggestion="Set per-server 'maxconn' (or a 'default-server maxconn N').",
            ))
    return findings


@rule
def deprecated_httpclose(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config) + config.frontends:
        if has_option(be, "httpclose") or has_option(be, "forceclose"):
            findings.append(Finding(
                rule_id="HG044", severity="medium", category=CATEGORY,
                title="Deprecated connection option",
                detail=f"'{be.name}' uses 'option httpclose/forceclose', which disables keep-alive and hurts performance.",
                section=be.name, line_number=be.line_number,
                suggestion="Use the default keep-alive or 'option http-server-close' instead.",
            ))
    return findings


@rule
def no_http_reuse(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in config.backends:
        if not be.servers:
            continue
        reuse = next((d for d in be.directives if d.keyword == "http-reuse"), None)
        if reuse and reuse.args and reuse.args[0] == "never":
            findings.append(Finding(
                rule_id="HG045", severity="info", category=CATEGORY,
                title="Connection reuse disabled",
                detail=f"Backend '{be.name}' sets 'http-reuse never', opening a new server connection per request.",
                section=be.name, line_number=be.line_number,
                suggestion="Use 'http-reuse safe' (the modern default) unless you have a specific reason.",
            ))
    return findings
