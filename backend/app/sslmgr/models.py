"""Models for the SSL Manager (Phase 6): certificates, ciphers, expiry."""
from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field

# expiry status thresholds (days)
CRITICAL_DAYS = 7
WARNING_DAYS = 30

ExpiryStatus = str  # "expired" | "critical" | "warning" | "ok"


def expiry_status(days_remaining: int) -> ExpiryStatus:
    if days_remaining < 0:
        return "expired"
    if days_remaining <= CRITICAL_DAYS:
        return "critical"
    if days_remaining <= WARNING_DAYS:
        return "warning"
    return "ok"


class CertificateInfo(BaseModel):
    subject_cn: str = ""
    issuer_cn: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: datetime
    not_after: datetime
    days_remaining: int
    expiry_status: ExpiryStatus
    sans: list[str] = Field(default_factory=list)
    key_type: str = ""
    key_bits: int | None = None
    signature_algorithm: str = ""
    is_self_signed: bool = False
    is_ca: bool = False
    issues: list[str] = Field(default_factory=list)


class CertReference(BaseModel):
    path: str
    kind: str  # bind-crt | crt-list | bind-ca | server-crt | server-ca | global-crt
    section: str | None = None
    line_number: int | None = None


class CertEntry(BaseModel):
    reference: CertReference
    readable: bool = False
    error: str | None = None
    certificates: list[CertificateInfo] = Field(default_factory=list)


class CipherAssessment(BaseModel):
    section: str | None = None
    bind: str = ""
    min_version: str | None = None
    max_version: str | None = None
    ciphers: str | None = None
    ciphersuites: str | None = None
    alpn: str | None = None
    grade: str = "A"  # A | B | C | F
    issues: list[str] = Field(default_factory=list)


class SslReport(BaseModel):
    references: list[CertReference] = Field(default_factory=list)
    certificates: list[CertEntry] = Field(default_factory=list)
    ciphers: list[CipherAssessment] = Field(default_factory=list)
    alerts: list[str] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
