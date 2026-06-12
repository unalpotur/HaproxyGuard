"""Evaluate a deployment's state into actionable alerts.

Pulls from the analyzer (config findings), the SSL manager (cipher grades and
certificate expiry), optional access-log error rate, and the live cluster
overview. Pure given its inputs, so it is fully testable offline.
"""
from __future__ import annotations

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from ..sslmgr import scan as ssl_scan
from ..assistant.logs import analyze_logs
from .models import Alert, Thresholds


def evaluate(content: str, logs: str | None, thresholds: Thresholds,
             read_certs: bool = False, cluster_overview=None) -> list[Alert]:
    config = parse_config(content)
    alerts: list[Alert] = []

    # --- config correctness/security (critical + high findings) ---------
    for f in analyze(config):
        if f.severity in ("critical", "high"):
            alerts.append(Alert(
                severity=f.severity, source="config", title=f.title,
                detail=f.detail + (f" ({f.section})" if f.section else "")))

    # --- TLS: cipher grade + certificate expiry -------------------------
    ssl_report = ssl_scan(config, read_files=read_certs)
    for c in ssl_report.ciphers:
        if c.grade in ("C", "F"):
            alerts.append(Alert(
                severity="high" if c.grade == "F" else "medium", source="tls",
                title=f"Weak TLS (grade {c.grade})",
                detail=f"{c.section} {c.bind}: {'; '.join(c.issues)}"))
    for entry in ssl_report.certificates:
        for cert in entry.certificates:
            if cert.expiry_status == "expired":
                alerts.append(Alert(
                    severity="critical", source="tls", title="Certificate expired",
                    detail=f"{entry.reference.path} ({cert.subject_cn}) expired "
                           f"{-cert.days_remaining} day(s) ago"))
            elif cert.days_remaining <= thresholds.cert_expiry_days:
                alerts.append(Alert(
                    severity="high", source="tls", title="Certificate expiring soon",
                    detail=f"{entry.reference.path} ({cert.subject_cn}) expires in "
                           f"{cert.days_remaining} day(s)"))

    # --- logs: error rate -----------------------------------------------
    if logs:
        ls = analyze_logs(logs)
        if ls.parsed and ls.error_rate >= thresholds.error_rate:
            worst = ls.backends_by_error[0] if ls.backends_by_error else None
            alerts.append(Alert(
                severity="high" if ls.error_rate >= 0.2 else "medium", source="logs",
                title="Error rate above threshold",
                detail=f"{ls.error_rate:.0%} over {ls.parsed} requests"
                       + (f", worst backend '{worst['backend']}'" if worst else "")))

    # --- cluster: offline nodes + config drift --------------------------
    if cluster_overview is not None:
        ov = cluster_overview
        if thresholds.alert_on_offline and ov.offline > 0:
            alerts.append(Alert(
                severity="high", source="cluster", title="Nodes offline",
                detail=f"{ov.offline} of {ov.total} node(s) are offline"))
        if thresholds.alert_on_drift and ov.distinct_config_hashes > 1:
            alerts.append(Alert(
                severity="medium", source="cluster", title="Configuration drift",
                detail=f"{ov.distinct_config_hashes} distinct config hashes across the fleet"))

    return alerts
