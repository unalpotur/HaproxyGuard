"""Extract certificate/CA file references from a parsed HAProxy config."""
from __future__ import annotations

from ..analyzer.registry import frontend_like, backend_like
from ..parser.models import HaproxyConfig
from .models import CertReference


def _bind_label(fe) -> str:
    return fe.name


def collect_references(config: HaproxyConfig) -> list[CertReference]:
    refs: list[CertReference] = []

    # global ssl-default-bind-crt
    g = config.global_section
    if g:
        for d in g.directives:
            if d.keyword == "ssl-default-bind-crt" and d.args:
                refs.append(CertReference(path=d.args[0], kind="global-crt",
                                          section="global", line_number=d.line_number))

    for fe in frontend_like(config):
        for b in fe.binds:
            if not b.ssl:
                continue
            crt = b.options.get("crt")
            if isinstance(crt, str):
                refs.append(CertReference(path=crt, kind="bind-crt",
                                          section=fe.name, line_number=fe.line_number))
            crt_list = b.options.get("crt-list")
            if isinstance(crt_list, str):
                refs.append(CertReference(path=crt_list, kind="crt-list",
                                          section=fe.name, line_number=fe.line_number))
            ca = b.options.get("ca-file")
            if isinstance(ca, str):
                refs.append(CertReference(path=ca, kind="bind-ca",
                                          section=fe.name, line_number=fe.line_number))

    for be in backend_like(config):
        for s in be.servers:
            crt = s.options.get("crt")
            if isinstance(crt, str):
                refs.append(CertReference(path=crt, kind="server-crt",
                                          section=be.name, line_number=be.line_number))
            ca = s.options.get("ca-file")
            if isinstance(ca, str):
                refs.append(CertReference(path=ca, kind="server-ca",
                                          section=be.name, line_number=be.line_number))

    return refs
