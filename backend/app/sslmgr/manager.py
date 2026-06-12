"""SSL Manager: scan a config for certs/ciphers, parse readable certs, alert."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from ..analyzer.registry import frontend_like
from ..parser.models import HaproxyConfig
from .ciphers import assess_bind
from .models import CertEntry, CertificateInfo, CertReference, SslReport
from .references import collect_references
from .x509util import parse_pem_bundle

# cert-list entries to read from disk before giving up
_MAX_READ_BYTES = 1_000_000


def analyze_pem(pem: str, now: datetime | None = None) -> list[CertificateInfo]:
    """Parse a pasted/uploaded PEM bundle into certificate descriptions."""
    return parse_pem_bundle(pem, now)


def _global_min_ver(config: HaproxyConfig) -> str | None:
    g = config.global_section
    if not g:
        return None
    for d in g.directives:
        if d.keyword == "ssl-default-bind-options":
            for a in d.args:
                if a.startswith("ssl-min-ver"):
                    # form is "ssl-min-ver TLSv1.2" possibly as two tokens; best effort
                    return a.split()[-1] if " " in a else None
    return None


def _load_reference(ref: CertReference, now: datetime) -> CertEntry:
    entry = CertEntry(reference=ref)
    if ref.kind == "crt-list":
        # not a cert itself; we don't expand it here beyond noting readability
        entry.readable = os.path.isfile(ref.path) and os.access(ref.path, os.R_OK)
        if not entry.readable:
            entry.error = "crt-list file not readable from this host"
        return entry
    try:
        if not os.path.isfile(ref.path):
            entry.error = "file not found on this host"
            return entry
        with open(ref.path, "rb") as f:
            data = f.read(_MAX_READ_BYTES)
        entry.certificates = parse_pem_bundle(data, now)
        entry.readable = True
    except (OSError, ValueError) as exc:
        entry.error = str(exc)
    return entry


def scan(config: HaproxyConfig, read_files: bool = True,
         now: datetime | None = None) -> SslReport:
    now = now or datetime.now(timezone.utc)
    references = collect_references(config)

    entries: list[CertEntry] = []
    if read_files:
        for ref in references:
            entries.append(_load_reference(ref, now))

    global_min = _global_min_ver(config)
    ciphers = []
    for fe in frontend_like(config):
        for b in fe.binds:
            if b.ssl:
                ciphers.append(assess_bind(b, fe.name, global_min))

    alerts: list[str] = []
    summary = {"expired": 0, "critical": 0, "warning": 0, "ok": 0,
               "unreadable": 0, "weak_ciphers": 0}

    for entry in entries:
        if entry.error and not entry.certificates:
            summary["unreadable"] += 1
        for c in entry.certificates:
            summary[c.expiry_status] = summary.get(c.expiry_status, 0) + 1
            if c.expiry_status == "expired":
                alerts.append(f"EXPIRED: {entry.reference.path} ({c.subject_cn or 'cert'}) "
                              f"in {entry.reference.section}")
            elif c.expiry_status in ("critical", "warning"):
                alerts.append(f"{c.expiry_status.upper()}: {entry.reference.path} "
                              f"({c.subject_cn or 'cert'}) expires in {c.days_remaining} day(s)")

    for ca in ciphers:
        if ca.grade in ("C", "F"):
            summary["weak_ciphers"] += 1
            alerts.append(f"Cipher grade {ca.grade} on {ca.section} {ca.bind}: "
                          f"{'; '.join(ca.issues)}")

    return SslReport(
        references=references, certificates=entries, ciphers=ciphers,
        alerts=alerts, summary=summary,
    )
