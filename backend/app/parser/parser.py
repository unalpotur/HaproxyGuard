"""HAProxy configuration parser (HAProxy 2.x / 3.x syntax).

Parses a raw haproxy.cfg into the structured models in `models.py`.
The parser is tolerant: unknown directives are preserved verbatim so the
original configuration can always be reconstructed or inspected.
"""
from __future__ import annotations

import shlex

from .models import (
    Acl, Backend, Bind, Directive, Frontend, HaproxyConfig,
    Listen, Section, Server, SwitchingRule,
)

SECTION_KEYWORDS = {
    "global", "defaults", "frontend", "backend", "listen",
    "userlist", "resolvers", "peers", "mailers", "cache",
    "program", "ring", "http-errors", "fcgi-app", "crt-store",
}

# server/bind keywords that take a value argument
_SERVER_VALUE_OPTS = {
    "weight", "maxconn", "inter", "rise", "fall", "cookie", "port",
    "addr", "minconn", "slowstart", "error-limit", "on-error", "verify",
    "ca-file", "crt", "sni", "check-sni", "resolvers", "init-addr",
    "observe", "pool-max-conn", "pool-purge-delay", "proto", "ws",
}
_BIND_VALUE_OPTS = {
    "crt", "ca-file", "verify", "alpn", "npn", "ciphers", "ciphersuites",
    "ssl-min-ver", "ssl-max-ver", "user", "group", "mode", "name",
    "process", "thread", "interface", "nice", "id", "maxconn", "backlog",
    "crt-list", "proto", "severity-output",
}


def _split_address(token: str) -> tuple[str, int | None]:
    """Split 'host:port' keeping IPv6 brackets and unix sockets intact."""
    if token.startswith("unix@") or token.startswith("/"):
        return token, None
    if token.startswith("["):  # [::1]:443
        host, _, rest = token.partition("]")
        host += "]"
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else None
    if ":" in token:
        host, _, port = token.rpartition(":")
        if port.isdigit():
            return host or "*", int(port)
    return token, None


def _parse_options(tokens: list[str], value_opts: set[str]) -> dict[str, str | bool]:
    opts: dict[str, str | bool] = {}
    i = 0
    while i < len(tokens):
        key = tokens[i]
        if key in value_opts and i + 1 < len(tokens):
            opts[key] = tokens[i + 1]
            i += 2
        else:
            opts[key] = True
            i += 1
    return opts


def _parse_bind(args: list[str], raw: str) -> Bind:
    address, port = _split_address(args[0]) if args else ("", None)
    opts = _parse_options(args[1:], _BIND_VALUE_OPTS)
    return Bind(
        address=address, port=port,
        ssl="ssl" in opts,
        certificate=opts.get("crt") if isinstance(opts.get("crt"), str) else None,
        options=opts, raw=raw,
    )


def _parse_server(args: list[str], raw: str) -> Server:
    name = args[0] if args else ""
    address, port = _split_address(args[1]) if len(args) > 1 else ("", None)
    opts = _parse_options(args[2:], _SERVER_VALUE_OPTS)

    def _int(key: str) -> int | None:
        v = opts.get(key)
        return int(v) if isinstance(v, str) and v.isdigit() else None

    return Server(
        name=name, address=address, port=port,
        check="check" in opts, backup="backup" in opts, ssl="ssl" in opts,
        weight=_int("weight"), maxconn=_int("maxconn"),
        options=opts, raw=raw,
    )


def _parse_acl(args: list[str], raw: str) -> Acl:
    return Acl(
        name=args[0] if args else "",
        criterion=args[1] if len(args) > 1 else "",
        values=args[2:], raw=raw,
    )


def _parse_use_backend(args: list[str], raw: str) -> SwitchingRule:
    backend = args[0] if args else ""
    operator = condition = None
    if len(args) > 1 and args[1] in ("if", "unless"):
        operator = args[1]
        condition = " ".join(args[2:])
    return SwitchingRule(backend=backend, operator=operator, condition=condition, raw=raw)


def _tokenize(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False)
    except ValueError:
        return line.split()


def parse_config(text: str) -> HaproxyConfig:
    config = HaproxyConfig()
    sections: list[Section] = []
    current: Section | None = None

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # strip trailing comments (naive but adequate: HAProxy itself does this)
        tokens = _tokenize(line)
        if not tokens:
            continue
        keyword = tokens[0]

        if keyword in SECTION_KEYWORDS:
            current = Section(
                kind=keyword,
                name=tokens[1] if len(tokens) > 1 else None,
                line_number=line_no,
            )
            sections.append(current)
            continue

        if current is None:
            config.parse_errors.append(
                f"line {line_no}: directive '{keyword}' outside of any section"
            )
            continue

        kw = keyword
        args = tokens[1:]
        # multi-word keywords: "timeout client", "option httpchk", "http-check ..."
        if keyword in ("timeout", "option", "stats", "http-check", "tcp-check",
                       "http-request", "http-response", "stick-table", "stick",
                       "tcp-request", "tcp-response", "default-server",
                       "errorfile", "compression", "monitor", "rate-limit") and args:
            kw = f"{keyword} {args[0]}"
            args = args[1:]

        current.directives.append(
            Directive(keyword=kw, args=args, line_number=line_no, raw=line)
        )

    for sec in sections:
        if sec.kind == "global":
            config.global_section = sec
        elif sec.kind == "defaults":
            config.defaults.append(sec)
        elif sec.kind == "frontend":
            config.frontends.append(_build_frontend(sec))
        elif sec.kind == "backend":
            config.backends.append(_build_backend(sec, Backend))
        elif sec.kind == "listen":
            listen = _build_backend(sec, Listen)
            _apply_frontend_directives(sec, listen)
            config.listens.append(listen)
        else:
            config.other_sections.append(sec)

    return config


def _common_fields(sec: Section) -> dict:
    timeouts = {}
    options = []
    mode = None
    for d in sec.directives:
        if d.keyword.startswith("timeout "):
            timeouts[d.keyword.split(" ", 1)[1]] = " ".join(d.args)
        elif d.keyword.startswith("option "):
            options.append(d.keyword.split(" ", 1)[1] + (" " + " ".join(d.args) if d.args else ""))
        elif d.keyword == "mode" and d.args:
            mode = d.args[0]
    return {"timeouts": timeouts, "options": options, "mode": mode}


def _build_frontend(sec: Section) -> Frontend:
    fe = Frontend(name=sec.name or "", line_number=sec.line_number,
                  directives=sec.directives, **_common_fields(sec))
    _apply_frontend_directives(sec, fe)
    return fe


def _apply_frontend_directives(sec: Section, target) -> None:
    for d in sec.directives:
        if d.keyword == "bind":
            target.binds.append(_parse_bind(d.args, d.raw))
        elif d.keyword == "acl":
            target.acls.append(_parse_acl(d.args, d.raw))
        elif d.keyword == "use_backend":
            target.switching_rules.append(_parse_use_backend(d.args, d.raw))
        elif d.keyword == "default_backend" and d.args:
            target.default_backend = d.args[0]


def _build_backend(sec: Section, cls):
    be = cls(name=sec.name or "", line_number=sec.line_number,
             directives=sec.directives, **_common_fields(sec))
    for d in sec.directives:
        if d.keyword == "server":
            be.servers.append(_parse_server(d.args, d.raw))
        elif d.keyword == "acl":
            be.acls.append(_parse_acl(d.args, d.raw))
        elif d.keyword == "balance" and d.args:
            be.balance = d.args[0]
    be.has_health_check = (
        any(s.check for s in be.servers)
        or any(d.keyword.startswith("http-check") for d in sec.directives)
        or any(o.startswith(("httpchk", "tcp-check", "ssl-hello-chk", "smtpchk",
                             "ldap-check", "mysql-check", "pgsql-check", "redis-check"))
               for o in be.options)
    )
    return be
