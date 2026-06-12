"""Assess which security controls an existing config already implements."""
from __future__ import annotations

from ..analyzer.registry import frontend_like
from ..parser.models import HaproxyConfig
from .controls import CONTROLS
from .models import ControlStatus, SecurityPosture


def _section_text(proxy) -> str:
    return "\n".join(d.raw for d in proxy.directives)


def assess(config: HaproxyConfig) -> SecurityPosture:
    proxies = frontend_like(config)
    statuses: list[ControlStatus] = []

    for cdef in CONTROLS.values():
        sections: list[str] = []
        for p in proxies:
            text = _section_text(p)
            if cdef.id == "admin_protection":
                has_stats = any(d.keyword.startswith("stats ") for d in p.directives)
                restricts = "admin_allowed" in text or (
                    "src" in text and ("deny" in text or "reject" in text))
                if has_stats and restricts:
                    sections.append(p.name)
                continue
            if any(tok in text for tok in cdef.detect_tokens):
                sections.append(p.name)
        statuses.append(ControlStatus(
            id=cdef.id, name=cdef.name, category=cdef.category,
            present=bool(sections), sections=sections,
            detail=("found in: " + ", ".join(sections)) if sections
            else "not configured on any frontend/listen",
        ))

    present = sum(1 for s in statuses if s.present)
    total = len(statuses)
    score = round(present / total * 100) if total else 0
    recommendations = [
        f"Add {s.name.lower()} ({s.category})" for s in statuses if not s.present
    ]
    return SecurityPosture(
        controls=statuses, present_count=present, total=total,
        score=score, recommendations=recommendations,
    )
