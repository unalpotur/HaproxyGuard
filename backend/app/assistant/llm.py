"""Optional Anthropic Claude integration for a richer troubleshooting narrative.

Uses the official `anthropic` SDK with Claude Opus 4.8 and adaptive thinking.
Degrades gracefully: if the SDK isn't installed or no API key is configured,
`available()` returns False and the assistant falls back to the heuristic engine.
The config is always sanitised before it leaves the host.
"""
from __future__ import annotations

import json
import os

from .sanitizer import sanitize

MODEL = "claude-opus-4-8"

_SYSTEM = (
    "You are an expert HAProxy site-reliability engineer. Given a sanitised "
    "HAProxy configuration and a structured risk report (findings, security "
    "posture, TLS state), write a concise root-cause analysis for an operator. "
    "Be specific and actionable. Do not invent details not supported by the "
    "input. Secrets are redacted as ***REDACTED***; never ask for them. "
    "Respond in at most 200 words of plain text."
)


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def narrate(config_text: str, report, posture, ssl_report) -> str | None:
    if not available():
        return None
    try:
        import anthropic
    except ImportError:
        return None

    payload = {
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "root_causes": [rc.model_dump() for rc in report.root_causes],
        "security_score": posture.score,
        "security_missing": posture.recommendations,
        "tls_alerts": ssl_report.alerts,
        "log_summary": report.log_summary.model_dump() if report.log_summary else None,
    }
    user = (
        "Sanitised HAProxy configuration:\n```\n"
        + sanitize(config_text)[:8000]
        + "\n```\n\nStructured risk report:\n"
        + json.dumps(payload, indent=2)[:6000]
        + "\n\nWrite the root-cause analysis and the single most important next step."
    )
    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            system=_SYSTEM,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if b.type == "text").strip() or None
    except Exception:
        # network / auth / rate-limit issues must never break the report
        return None
