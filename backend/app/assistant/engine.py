"""AI-powered troubleshooting assistant.

Combines static analysis (rules), SSL posture, security posture and optional log
and runtime-metric signals into a single risk assessment with root causes and
prioritised recommendations. The heuristic core is deterministic and needs no
network; when an Anthropic API key is configured it is enriched with an
LLM-written narrative over a *sanitised* view of the deployment.
"""
from __future__ import annotations

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from ..sslmgr import scan as ssl_scan
from .. import security as sec
from . import llm as llm_mod
from .logs import analyze_logs
from .models import AssistantReport, LogSummary, Recommendation, RootCause


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def analyze_deployment(config_text: str, logs_text: str | None = None,
                       metrics: dict | None = None,
                       use_llm: bool = True) -> AssistantReport:
    config = parse_config(config_text)
    findings = analyze(config)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    ssl_report = ssl_scan(config, read_files=False)
    posture = sec.assess(config)
    log_summary = analyze_logs(logs_text) if logs_text else None

    root_causes: list[RootCause] = []
    recommendations: list[Recommendation] = []
    score = 0

    # --- config correctness / security findings -------------------------
    for f in findings:
        if f.severity == "critical":
            root_causes.append(RootCause(
                title=f.title, severity="critical", category=f.category or "config",
                evidence=f.detail))
            if f.suggestion:
                recommendations.append(Recommendation(
                    action=f.suggestion, rationale=f.detail, priority="high"))
    score += min(by_sev.get("critical", 0) * 15, 45)
    score += min(by_sev.get("high", 0) * 7, 21)

    # --- TLS / certificates ---------------------------------------------
    weak_ciphers = [c for c in ssl_report.ciphers if c.grade in ("C", "F")]
    if weak_ciphers:
        worst = weak_ciphers[0]
        root_causes.append(RootCause(
            title="Weak TLS configuration", severity="high", category="tls",
            evidence=f"{worst.section} {worst.bind}: {'; '.join(worst.issues)}"))
        recommendations.append(Recommendation(
            action="Harden TLS: pin ssl-min-ver TLSv1.2+ and a strong cipher suite.",
            rationale="Weak TLS exposes traffic to downgrade and interception.",
            priority="high"))
        score += min(len(weak_ciphers) * 8, 16)

    expiry_alerts = [a for a in ssl_report.alerts if a.startswith(("EXPIRED", "CRITICAL"))]
    if expiry_alerts:
        root_causes.append(RootCause(
            title="Certificate expiry risk", severity="high", category="tls",
            evidence="; ".join(expiry_alerts[:3])))
        recommendations.append(Recommendation(
            action="Renew/rotate the affected certificates before they expire.",
            rationale="Expired certificates cause TLS handshake failures and outages.",
            priority="high"))
        score += 10

    # --- security posture -----------------------------------------------
    score += round((100 - posture.score) * 0.15)
    if posture.score < 50 and posture.recommendations:
        recommendations.append(Recommendation(
            action="; ".join(posture.recommendations[:3]),
            rationale=f"Security posture score is {posture.score}/100.",
            priority="medium"))

    # --- log signals -----------------------------------------------------
    if log_summary and log_summary.parsed:
        score += _log_score(log_summary, root_causes, recommendations)

    # --- runtime metrics -------------------------------------------------
    if metrics:
        score += _metric_score(metrics, root_causes, recommendations)

    score = max(0, min(score, 100))
    level = _risk_level(score)
    summary = _summarize(level, by_sev, ssl_report, posture, log_summary)

    report = AssistantReport(
        risk_score=score, risk_level=level, summary=summary,
        root_causes=root_causes[:10], recommendations=_dedupe(recommendations)[:10],
        log_summary=log_summary,
    )

    if use_llm and llm_mod.available():
        narrative = llm_mod.narrate(config_text, report, posture, ssl_report)
        if narrative:
            report.used_llm = True
            report.llm_narrative = narrative
    return report


def _log_score(ls: LogSummary, causes, recs) -> int:
    add = 0
    if ls.error_rate >= 0.5:
        add += 20
    elif ls.error_rate >= 0.2:
        add += 12
    elif ls.error_rate >= 0.05:
        add += 5
    if ls.error_rate >= 0.05:
        worst = ls.backends_by_error[0] if ls.backends_by_error else None
        ev = (f"error rate {ls.error_rate:.0%} over {ls.parsed} requests"
              + (f"; worst backend '{worst['backend']}' "
                 f"({worst['errors']}/{worst['total']})" if worst else ""))
        causes.append(RootCause(
            title="Elevated error rate", severity="high", category="logs", evidence=ev))
        recs.append(Recommendation(
            action="Investigate the failing backend's server health and timeouts.",
            rationale="A high 4xx/5xx rate indicates backend or routing problems.",
            priority="high"))
    if ls.slow_count and ls.slow_count >= max(1, ls.parsed // 20):
        add += 5
        causes.append(RootCause(
            title="Slow requests", severity="medium", category="logs",
            evidence=f"{ls.slow_count} request(s) over {ls.slow_threshold_ms}ms"
                     + (f", avg {ls.avg_response_ms}ms" if ls.avg_response_ms else "")))
    return add


def _metric_score(metrics: dict, causes, recs) -> int:
    """metrics is a collector snapshot; look for DOWN servers."""
    down = []
    servers = metrics.get("servers") or metrics.get("stats") or []
    if isinstance(servers, list):
        for s in servers:
            status = str(s.get("status", "")).upper()
            if status.startswith("DOWN") or status == "MAINT":
                down.append(f"{s.get('pxname', '?')}/{s.get('svname', '?')}")
    if down:
        causes.append(RootCause(
            title="Servers down", severity="critical", category="runtime",
            evidence="DOWN: " + ", ".join(down[:8])))
        recs.append(Recommendation(
            action="Bring the DOWN servers back or remove them from rotation.",
            rationale="Down servers reduce capacity and can cause 5xx errors.",
            priority="high"))
        return min(len(down) * 5, 20)
    return 0


def _summarize(level, by_sev, ssl_report, posture, log_summary) -> str:
    parts = [f"Overall risk: {level}."]
    if by_sev:
        parts.append(", ".join(f"{n} {sev}" for sev, n in sorted(by_sev.items()))
                     + " finding(s).")
    if posture.score < 100:
        parts.append(f"Security posture {posture.score}/100.")
    bad_certs = ssl_report.summary.get("expired", 0) + ssl_report.summary.get("critical", 0)
    if bad_certs:
        parts.append(f"{bad_certs} certificate(s) need attention.")
    if log_summary and log_summary.parsed:
        parts.append(f"Log error rate {log_summary.error_rate:.0%}.")
    return " ".join(parts)


def _dedupe(recs: list[Recommendation]) -> list[Recommendation]:
    seen: set[str] = set()
    out = []
    for r in recs:
        if r.action not in seen:
            seen.add(r.action)
            out.append(r)
    return out
