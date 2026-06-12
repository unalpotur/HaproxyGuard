"""Security rules: exposed admin surfaces, weak auth, unverified TLS to backends."""
from __future__ import annotations

from ..registry import (
    Finding, rule, frontend_like, backend_like, has_option,
)
from ...parser.models import HaproxyConfig

CATEGORY = "security"

_PUBLIC_ADDRS = {"*", "0.0.0.0", "::", "[::]"}
_WEAK_CREDS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "haproxy"),
    ("root", "root"), ("stats", "stats"), ("admin", "1234"),
    ("user", "password"), ("guest", "guest"),
}


def _is_public(fe) -> bool:
    return any(b.address in _PUBLIC_ADDRS for b in fe.binds)


@rule
def stats_exposure(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        has_stats = any(d.keyword == "stats enable" for d in fe.directives)
        has_auth = any(d.keyword == "stats auth" for d in fe.directives)
        if has_stats and _is_public(fe) and not has_auth:
            findings.append(Finding(
                rule_id="HG007", severity="critical", category=CATEGORY,
                title="Stats endpoint exposed without authentication",
                detail=f"'{fe.name}' enables stats on a public bind with no 'stats auth'.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add 'stats auth user:password' or bind to localhost.",
            ))
    return findings


@rule
def stats_admin_enabled(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        has_admin = any(d.keyword == "stats admin" for d in fe.directives)
        if has_admin and _is_public(fe):
            findings.append(Finding(
                rule_id="HG027", severity="high", category=CATEGORY,
                title="Stats admin enabled on a public bind",
                detail=f"'{fe.name}' enables 'stats admin' (server control) on a publicly reachable bind.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Restrict the admin UI to an internal/localhost bind and authenticate it.",
            ))
    return findings


@rule
def weak_stats_credentials(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        for d in fe.directives:
            if d.keyword == "stats auth" and d.args:
                user, _, pw = d.args[0].partition(":")
                if (user, pw) in _WEAK_CREDS or user == pw:
                    findings.append(Finding(
                        rule_id="HG028", severity="high", category=CATEGORY,
                        title="Weak stats credentials",
                        detail=f"'{fe.name}' uses a weak/default stats login '{user}:****'.",
                        section=fe.name, line_number=fe.line_number,
                        suggestion="Use a strong, unique password for the stats interface.",
                    ))
    return findings


@rule
def server_tls_not_verified(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for be in backend_like(config):
        for s in be.servers:
            if not s.ssl:
                continue
            verify = s.options.get("verify")
            if verify == "none" or verify is None:
                findings.append(Finding(
                    rule_id="HG029", severity="medium", category=CATEGORY,
                    title="Unverified TLS to backend server",
                    detail=f"Server '{s.name}' in '{be.name}' uses SSL but does not verify the certificate "
                           f"(verify {verify or 'unset'}).",
                    section=be.name, line_number=be.line_number,
                    suggestion="Set 'verify required' with a 'ca-file' to prevent MITM to the backend.",
                ))
    return findings


@rule
def admin_socket_unrestricted(config: HaproxyConfig) -> list[Finding]:
    g = config.global_section
    if not g:
        return []
    findings = []
    for d in g.directives:
        if d.keyword != "stats socket":
            continue
        args = d.args
        path = args[0] if args else ""
        opts = " ".join(args).lower()
        is_tcp = path.startswith("ipv4@") or path.startswith("ipv6@") or ":" in path.split()[0] if path else False
        level_admin = "level admin" in opts
        if level_admin and is_tcp:
            findings.append(Finding(
                rule_id="HG030", severity="critical", category=CATEGORY,
                title="Admin-level stats socket over TCP",
                detail="A 'stats socket' with 'level admin' is exposed over a TCP address.",
                section="global", line_number=d.line_number,
                suggestion="Bind the admin socket to a unix socket with restricted file permissions.",
            ))
        elif level_admin:
            mode = ""
            if "mode" in args:
                mi = args.index("mode")
                if mi + 1 < len(args):
                    mode = args[mi + 1]
            if mode in ("666", "777", "0666", "0777") or not mode:
                findings.append(Finding(
                    rule_id="HG031", severity="high", category=CATEGORY,
                    title="Admin stats socket with weak permissions",
                    detail=f"Admin 'stats socket' has mode '{mode or 'unset'}' — too permissive for an admin control channel.",
                    section="global", line_number=d.line_number,
                    suggestion="Use 'mode 600' and a dedicated 'user'/'group' for the admin socket.",
                ))
    return findings


@rule
def http_without_forwardfor(config: HaproxyConfig) -> list[Finding]:
    """In http mode, without 'option forwardfor' the backend loses the client IP."""
    defaults_ff = any(
        any(opt.keyword == "option forwardfor" for opt in d.directives)
        for d in config.defaults
    )
    if defaults_ff:
        return []
    findings = []
    for be in config.backends:
        mode = be.mode or next((d.get("mode").args[0] for d in config.defaults
                                if d.get("mode") and d.get("mode").args), None)
        if mode == "http" and be.servers and not has_option(be, "forwardfor"):
            findings.append(Finding(
                rule_id="HG032", severity="low", category=CATEGORY,
                title="Client IP not forwarded",
                detail=f"Backend '{be.name}' is http but has no 'option forwardfor'; servers see HAProxy's IP.",
                section=be.name, line_number=be.line_number,
                suggestion="Add 'option forwardfor' so X-Forwarded-For carries the real client IP.",
            ))
    return findings


@rule
def plaintext_public_http(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe in frontend_like(config):
        for b in fe.binds:
            if b.address in _PUBLIC_ADDRS and b.port == 80 and not b.ssl:
                # not necessarily wrong (could be a redirect-to-https frontend); flag as info
                has_redirect = any(
                    d.keyword == "redirect" and "https" in " ".join(d.args)
                    for d in fe.directives
                )
                if not has_redirect:
                    findings.append(Finding(
                        rule_id="HG033", severity="info", category=CATEGORY,
                        title="Public plaintext HTTP bind",
                        detail=f"'{fe.name}' serves plaintext HTTP on {b.address}:80 with no redirect to HTTPS.",
                        section=fe.name, line_number=fe.line_number,
                        suggestion="Add a 'redirect scheme https' rule or terminate TLS here.",
                    ))
    return findings
