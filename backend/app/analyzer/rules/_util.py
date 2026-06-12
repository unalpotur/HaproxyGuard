"""Small parsing helpers shared by rule modules."""
from __future__ import annotations

_UNITS = [("us", 0.001), ("ms", 1.0), ("s", 1000.0),
          ("m", 60_000.0), ("h", 3_600_000.0), ("d", 86_400_000.0)]

# Substrings that mark a cipher suite / cipher string as cryptographically weak.
WEAK_CIPHER_TOKENS = (
    "RC4", "MD5", "DES", "3DES", "NULL", "EXPORT", "EXP",
    "PSK", "ADH", "AECDH", "SEED", "IDEA", "RC2",
)

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1", "TLSv10", "TLSv11"}


def parse_duration_ms(value: str | None) -> float | None:
    """Parse an HAProxy duration (e.g. '5s', '30000', '2m') into milliseconds.
    Bare numbers are milliseconds per HAProxy convention."""
    if not value:
        return None
    s = value.strip()
    for unit, mult in _UNITS:
        if s.endswith(unit):
            num = s[: -len(unit)]
            if num.isdigit():
                return int(num) * mult
            return None
    return int(s) if s.isdigit() else None


def has_weak_cipher(cipher_string: str) -> list[str]:
    """Return the weak tokens found in a ciphers / ciphersuites string."""
    upper = cipher_string.upper()
    return [t for t in WEAK_CIPHER_TOKENS if t in upper]
