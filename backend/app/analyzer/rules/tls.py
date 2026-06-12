"""TLS/SSL rules: protocol versions, ciphers, certificates, ALPN."""
from __future__ import annotations

from ..registry import Finding, rule, frontend_like, global_has
from ...parser.models import HaproxyConfig
from ._util import WEAK_TLS_VERSIONS, has_weak_cipher

CATEGORY = "tls"


def _ssl_binds(config: HaproxyConfig):
    for fe in frontend_like(config):
        for b in fe.binds:
            if b.ssl:
                yield fe, b


@rule
def weak_tls_min_version(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe, b in _ssl_binds(config):
        min_ver = b.options.get("ssl-min-ver")
        if isinstance(min_ver, str) and min_ver in WEAK_TLS_VERSIONS:
            findings.append(Finding(
                rule_id="HG005", severity="high", category=CATEGORY,
                title="Weak TLS minimum version",
                detail=f"'{fe.name}' allows {min_ver} on {b.address}:{b.port}.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Set 'ssl-min-ver TLSv1.2' or higher.",
            ))
    return findings


@rule
def no_explicit_tls_min_version(config: HaproxyConfig) -> list[Finding]:
    # If a global default min ver is set, individual binds don't need to repeat it.
    if global_has(config, "ssl-default-bind-options") or _global_min_ver(config):
        return []
    findings = []
    for fe, b in _ssl_binds(config):
        if b.options.get("ssl-min-ver") is None:
            findings.append(Finding(
                rule_id="HG006", severity="low", category=CATEGORY,
                title="No explicit TLS minimum version",
                detail=f"SSL bind in '{fe.name}' does not pin ssl-min-ver and no global default is set.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add 'ssl-min-ver TLSv1.2' to the bind or set 'ssl-default-bind-options' globally.",
            ))
    return findings


def _global_min_ver(config: HaproxyConfig) -> str | None:
    g = config.global_section
    if not g:
        return None
    for d in g.directives:
        if d.keyword == "ssl-default-bind-options":
            for a in d.args:
                if a.startswith("ssl-min-ver"):
                    return a
    return None


@rule
def ssl_bind_without_certificate(config: HaproxyConfig) -> list[Finding]:
    findings = []
    crt_store = global_has(config, "ssl-default-bind-crt")
    for fe, b in _ssl_binds(config):
        if not b.certificate and "crt-list" not in b.options and not crt_store:
            findings.append(Finding(
                rule_id="HG034", severity="high", category=CATEGORY,
                title="SSL bind without a certificate",
                detail=f"'{fe.name}' enables ssl on {b.address}:{b.port} but specifies no 'crt' or 'crt-list'.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Add 'crt /path/to/cert.pem' (or a crt-list) to the bind line.",
            ))
    return findings


@rule
def weak_ciphers(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe, b in _ssl_binds(config):
        for key in ("ciphers", "ciphersuites"):
            val = b.options.get(key)
            if isinstance(val, str):
                weak = has_weak_cipher(val)
                if weak:
                    findings.append(Finding(
                        rule_id="HG035", severity="high", category=CATEGORY,
                        title="Weak cipher configured",
                        detail=f"'{fe.name}' {key} on {b.address}:{b.port} includes weak primitives: {', '.join(weak)}.",
                        section=fe.name, line_number=fe.line_number,
                        suggestion="Remove RC4/3DES/DES/MD5/NULL/EXPORT ciphers; use a modern suite.",
                    ))
    return findings


@rule
def ssl_max_ver_too_low(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe, b in _ssl_binds(config):
        max_ver = b.options.get("ssl-max-ver")
        if isinstance(max_ver, str) and max_ver in WEAK_TLS_VERSIONS:
            findings.append(Finding(
                rule_id="HG036", severity="high", category=CATEGORY,
                title="TLS maximum version capped too low",
                detail=f"'{fe.name}' caps ssl-max-ver at {max_ver}, disabling modern TLS.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Remove ssl-max-ver or set it to TLSv1.3.",
            ))
    return findings


@rule
def forced_legacy_protocol(config: HaproxyConfig) -> list[Finding]:
    bad = {"force-sslv3", "force-tlsv10", "force-tlsv11"}
    findings = []
    for fe, b in _ssl_binds(config):
        for opt in b.options:
            if opt in bad:
                findings.append(Finding(
                    rule_id="HG037", severity="critical", category=CATEGORY,
                    title="Legacy TLS protocol forced",
                    detail=f"'{fe.name}' bind uses '{opt}', forcing an insecure protocol.",
                    section=fe.name, line_number=fe.line_number,
                    suggestion=f"Remove '{opt}' and rely on 'ssl-min-ver TLSv1.2'.",
                ))
    return findings


@rule
def no_http2_alpn(config: HaproxyConfig) -> list[Finding]:
    findings = []
    for fe, b in _ssl_binds(config):
        alpn = b.options.get("alpn")
        if isinstance(alpn, str) and "h2" not in alpn:
            findings.append(Finding(
                rule_id="HG038", severity="info", category=CATEGORY,
                title="HTTP/2 not advertised",
                detail=f"'{fe.name}' SSL bind advertises ALPN '{alpn}' without h2.",
                section=fe.name, line_number=fe.line_number,
                suggestion="Use 'alpn h2,http/1.1' to enable HTTP/2.",
            ))
    return findings


@rule
def global_ssl_defaults_missing(config: HaproxyConfig) -> list[Finding]:
    if not list(_ssl_binds(config)):  # only relevant when SSL is actually used
        return []
    if global_has(config, "ssl-default-bind-ciphers") or global_has(config, "ssl-default-bind-options"):
        return []
    return [Finding(
        rule_id="HG039", severity="low", category=CATEGORY,
        title="No global SSL hardening defaults",
        detail="SSL is in use but global 'ssl-default-bind-ciphers'/'ssl-default-bind-options' are not set.",
        section="global",
        suggestion="Set strong global SSL defaults so every bind inherits a hardened baseline.",
    )]
