"""Best-practice & maintainability rules, incl. deprecated-keyword detection."""
from __future__ import annotations

from ..registry import (
    Finding, rule, all_proxies, backend_like, frontend_like, effective_mode,
)
from ...parser.models import HaproxyConfig

CATEGORY = "best-practices"

# directive keyword -> (modern replacement, severity)
_DEPRECATED = {
    "reqrep": ("http-request replace-path/replace-uri", "medium"),
    "reqirep": ("http-request replace-path/replace-uri", "medium"),
    "reqadd": ("http-request add-header", "medium"),
    "reqidel": ("http-request del-header", "medium"),
    "reqdel": ("http-request del-header", "medium"),
    "rspadd": ("http-response add-header", "medium"),
    "rspdel": ("http-response del-header", "medium"),
    "rsprep": ("http-response replace-header", "medium"),
    "reqdeny": ("http-request deny", "medium"),
    "rspdeny": ("http-response deny", "medium"),
    "block": ("http-request deny", "medium"),
    "redirect": (None, None),  # not deprecated, placeholder to avoid accidental match
}
_DEPRECATED.pop("redirect")


@rule
def deprecated_directives(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for p in all_proxies(config):
        for d in p.directives:
            kw = d.keyword.split(" ", 1)[0]
            if kw in _DEPRECATED:
                replacement, sev = _DEPRECATED[kw]
                findings.append(Finding(
                    rule_id="HG049", severity=sev, category=CATEGORY,
                    title=f"Deprecated directive '{kw}'",
                    detail=f"'{p.name}' uses deprecated '{kw}', removed/legacy in modern HAProxy.",
                    section=p.name, line_number=d.line_number,
                    suggestion=f"Replace with '{replacement}'.",
                ))
    return findings


@rule
def bare_httpchk(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        for o in be.options:
            if o == "httpchk":  # no method/path/version configured
                findings.append(Finding(
                    rule_id="HG050", severity="info", category=CATEGORY,
                    title="Bare 'option httpchk'",
                    detail=f"Backend '{be.name}' uses 'option httpchk' without a method/URI; it only opens a TCP connection by default.",
                    section=be.name, line_number=be.line_number,
                    suggestion="Specify a check, e.g. 'option httpchk GET /healthz'.",
                ))
    return findings


@rule
def empty_section(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for p in all_proxies(config):
        if not p.directives:
            findings.append(Finding(
                rule_id="HG051", severity="info", category=CATEGORY,
                title="Empty proxy section",
                detail=f"'{p.name}' contains no directives.",
                section=p.name, line_number=p.line_number,
                suggestion="Remove the empty section or fill in its configuration.",
            ))
    return findings


@rule
def http_rules_in_tcp_mode(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for p in all_proxies(config):
        if effective_mode(config, p) != "tcp":
            continue
        for d in p.directives:
            if d.keyword.startswith(("http-request", "http-response")) or d.keyword == "redirect":
                findings.append(Finding(
                    rule_id="HG052", severity="medium", category=CATEGORY,
                    title="HTTP rule in a TCP proxy",
                    detail=f"'{p.name}' is mode tcp but uses '{d.keyword}', which requires HTTP mode.",
                    section=p.name, line_number=d.line_number,
                    suggestion="Set 'mode http' or remove the HTTP-layer rule.",
                ))
                break
    return findings


@rule
def redirect_without_https_in_http(config: HaproxyConfig) -> list[Finding]:
    """An http frontend with a TLS bind but no redirect from its plaintext bind."""
    findings = []
    for fe in frontend_like(config):
        plain = [b for b in fe.binds if not b.ssl and b.port == 80]
        tls = [b for b in fe.binds if b.ssl]
        has_redirect = any(
            d.keyword == "redirect" and "https" in " ".join(d.args).lower()
            for d in fe.directives
        )
        if plain and tls and not has_redirect:
            findings.append(Finding(
                rule_id="HG053", severity="low", category=CATEGORY,
                title="No HTTP→HTTPS redirect",
                detail=f"'{fe.name}' serves both :80 and TLS but has no 'redirect scheme https'.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add 'http-request redirect scheme https unless { ssl_fc }'.",
            ))
    return findings
