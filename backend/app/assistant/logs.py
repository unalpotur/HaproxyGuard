"""Lightweight HAProxy access-log analysis (feeds the AI assistant)."""
from __future__ import annotations

import re

from .models import LogSummary

# HAProxy HTTP log line (option httplog):
#   <client>:<port> [date] <frontend> <backend>/<server> Tq/Tw/Tc/Tr/Tt <status> <bytes> ... "<req>"
_LINE = re.compile(
    r"\]\s+\S+\s+"                       # [date] frontend
    r"(?P<backend>[^/\s]+)/\S+\s+"       # backend/server
    r"\d+/\d+/\d+/-?\d+/(?P<tt>-?\d+)\s+"  # timers, capture Tt
    r"(?P<status>\d{3})\s+"             # status code
)


def analyze_logs(text: str, slow_threshold_ms: int = 1000) -> LogSummary:
    lines = [l for l in text.splitlines() if l.strip()]
    summary = LogSummary(total_lines=len(lines), slow_threshold_ms=slow_threshold_ms)
    classes: dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    per_backend: dict[str, list[int]] = {}  # backend -> [errors, total]
    total_ms = 0
    timed = 0
    errors = 0

    for line in lines:
        m = _LINE.search(line)
        if not m:
            continue
        summary.parsed += 1
        status = int(m.group("status"))
        cls = f"{status // 100}xx"
        classes[cls if cls in classes else "other"] += 1
        is_error = status >= 400
        if is_error:
            errors += 1
        tt = int(m.group("tt"))
        if tt >= 0:
            total_ms += tt
            timed += 1
            if tt >= slow_threshold_ms:
                summary.slow_count += 1
        be = m.group("backend")
        rec = per_backend.setdefault(be, [0, 0])
        rec[1] += 1
        if is_error:
            rec[0] += 1

    summary.status_classes = {k: v for k, v in classes.items() if v}
    summary.error_rate = round(errors / summary.parsed, 4) if summary.parsed else 0.0
    summary.avg_response_ms = round(total_ms / timed, 1) if timed else None
    summary.backends_by_error = sorted(
        ({"backend": b, "errors": e, "total": t} for b, (e, t) in per_backend.items()),
        key=lambda r: r["errors"], reverse=True,
    )[:5]
    return summary
