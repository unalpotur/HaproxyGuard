"""Render selected security controls into ready-to-merge HAProxy snippets."""
from __future__ import annotations

from .controls import CONTROLS, resolve_params
from .models import ControlRequest, GeneratedConfig, ResolvedControl
from .presets import preset as get_preset

DEFAULT_TABLE_SIZE = "100k"
DEFAULT_TABLE_EXPIRE = "30s"


def _resolve(requests: list[ControlRequest]) -> list[tuple[ResolvedControl, object]]:
    resolved = []
    for req in requests:
        if req.id not in CONTROLS:
            raise KeyError(req.id)
        cdef = CONTROLS[req.id]
        params = resolve_params(req.id, req.params)
        rc = ResolvedControl(id=cdef.id, name=cdef.name, category=cdef.category, params=params)
        resolved.append((rc, cdef.build(params)))
    return resolved


def generate(requests: list[ControlRequest], *, preset: str | None = None,
             table_size: str = DEFAULT_TABLE_SIZE,
             table_expire: str = DEFAULT_TABLE_EXPIRE) -> GeneratedConfig:
    resolved = _resolve(requests)

    counters: list[str] = []
    for _, parts in resolved:
        if parts.counter and parts.counter not in counters:
            counters.append(parts.counter)

    frontend: list[str] = []
    if counters:
        frontend.append(
            f"stick-table type ip size {table_size} expire {table_expire} "
            f"store {','.join(counters)}")
        frontend.append("tcp-request connection track-sc0 src")
    for _, parts in resolved:
        frontend.extend(parts.tcp_rules)
    for _, parts in resolved:
        frontend.extend(parts.http_rules)
    for _, parts in resolved:
        frontend.extend(parts.extra_frontend)

    global_lines: list[str] = []
    notes: list[str] = []
    for _, parts in resolved:
        for g in parts.global_lines:
            if g not in global_lines:
                global_lines.append(g)
        for n in parts.notes:
            if n not in notes:
                notes.append(n)

    cfg = GeneratedConfig(
        preset=preset,
        controls=[rc for rc, _ in resolved],
        global_lines=global_lines,
        frontend_lines=frontend,
        notes=notes,
    )
    cfg.snippet = render_snippet(cfg)
    return cfg


def generate_preset(preset_id: str, **kwargs) -> GeneratedConfig:
    spec = get_preset(preset_id)
    return generate(spec.controls, preset=preset_id, **kwargs)


def render_snippet(cfg: GeneratedConfig) -> str:
    label = f" (preset: {cfg.preset})" if cfg.preset else ""
    out = [f"# --- HAProxy Guard: security snippet{label} ---"]
    names = ", ".join(c.name for c in cfg.controls)
    out.append(f"# controls: {names}")
    if cfg.global_lines:
        out.append("")
        out.append("# Add to your global section:")
        out.append("global")
        out.extend("    " + line for line in cfg.global_lines)
    if cfg.frontend_lines:
        out.append("")
        out.append("# Add inside the frontend that receives client traffic:")
        out.append("frontend <your_frontend>")
        out.extend("    " + line for line in cfg.frontend_lines)
    if cfg.notes:
        out.append("")
        out.append("# Notes:")
        out.extend("#   - " + n for n in cfg.notes)
    return "\n".join(out) + "\n"
