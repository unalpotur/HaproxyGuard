"""Cipher / TLS protocol grading for SSL binds."""
from __future__ import annotations

from ..parser.models import Bind
from .models import CipherAssessment

WEAK_CIPHER_TOKENS = (
    "RC4", "MD5", "DES", "3DES", "NULL", "EXPORT", "EXP",
    "PSK", "ADH", "AECDH", "SEED", "IDEA", "RC2",
)
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1", "TLSv10", "TLSv11"}
FORCED_LEGACY = {"force-sslv3", "force-tlsv10", "force-tlsv11"}

_GRADE_ORDER = ["A", "B", "C", "F"]


def _worse(current: str, candidate: str) -> str:
    return candidate if _GRADE_ORDER.index(candidate) > _GRADE_ORDER.index(current) else current


def _opt_str(bind: Bind, key: str) -> str | None:
    v = bind.options.get(key)
    return v if isinstance(v, str) else None


def assess_bind(bind: Bind, section: str | None, global_min_ver: str | None = None) -> CipherAssessment:
    min_ver = _opt_str(bind, "ssl-min-ver") or global_min_ver
    max_ver = _opt_str(bind, "ssl-max-ver")
    ciphers = _opt_str(bind, "ciphers")
    ciphersuites = _opt_str(bind, "ciphersuites")
    alpn = _opt_str(bind, "alpn")

    grade = "A"
    issues: list[str] = []

    forced = [o for o in bind.options if o in FORCED_LEGACY]
    if forced:
        grade = _worse(grade, "F")
        issues.append(f"forces legacy protocol: {', '.join(forced)}")

    if min_ver in WEAK_TLS_VERSIONS:
        grade = _worse(grade, "F")
        issues.append(f"minimum TLS version is weak ({min_ver})")
    elif min_ver is None:
        grade = _worse(grade, "B")
        issues.append("no minimum TLS version pinned (no ssl-min-ver / global default)")

    if max_ver in WEAK_TLS_VERSIONS:
        grade = _worse(grade, "F")
        issues.append(f"maximum TLS version capped too low ({max_ver})")

    for label, value in (("ciphers", ciphers), ("ciphersuites", ciphersuites)):
        if value:
            up = value.upper()
            weak = [t for t in WEAK_CIPHER_TOKENS if t in up]
            if weak:
                grade = _worse(grade, "F")
                issues.append(f"{label} include weak primitives: {', '.join(weak)}")

    if ciphers is None and ciphersuites is None and grade == "A":
        grade = _worse(grade, "B")
        issues.append("no explicit cipher list (relies on defaults)")

    bind_label = f"{bind.address}:{bind.port}" if bind.port is not None else bind.address
    return CipherAssessment(
        section=section, bind=bind_label,
        min_version=min_ver, max_version=max_ver,
        ciphers=ciphers, ciphersuites=ciphersuites, alpn=alpn,
        grade=grade, issues=issues,
    )
