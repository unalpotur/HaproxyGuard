"""X509 certificate parsing built on the `cryptography` library."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed448, ed25519, rsa,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from .models import CertificateInfo, expiry_status

_WEAK_SIG_HASHES = {"md5", "sha1"}
_MIN_RSA_BITS = 2048


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", None
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__, None


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return bool(ext.value.ca)
    except x509.ExtensionNotFound:
        return False


def _signature_name(cert: x509.Certificate) -> str:
    try:
        algo = cert.signature_hash_algorithm
        if algo is not None:
            return algo.name
    except Exception:
        pass
    return cert.signature_algorithm_oid._name


def describe(cert: x509.Certificate, now: datetime | None = None) -> CertificateInfo:
    now = now or datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_remaining = (not_after - now).days
    key_type, key_bits = _key_info(cert)
    sig = _signature_name(cert)
    self_signed = cert.subject == cert.issuer

    issues: list[str] = []
    status = expiry_status(days_remaining)
    if status == "expired":
        issues.append(f"certificate expired {-days_remaining} day(s) ago")
    elif status in ("critical", "warning"):
        issues.append(f"expires in {days_remaining} day(s)")
    if sig.lower() in _WEAK_SIG_HASHES:
        issues.append(f"weak signature hash ({sig})")
    if key_type == "RSA" and key_bits is not None and key_bits < _MIN_RSA_BITS:
        issues.append(f"RSA key too small ({key_bits} bits)")
    if self_signed and not _is_ca(cert):
        issues.append("self-signed certificate")

    return CertificateInfo(
        subject_cn=_cn(cert.subject),
        issuer_cn=_cn(cert.issuer),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=f"{cert.serial_number:x}",
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        expiry_status=status,
        sans=_sans(cert),
        key_type=key_type,
        key_bits=key_bits,
        signature_algorithm=sig,
        is_self_signed=self_signed,
        is_ca=_is_ca(cert),
        issues=issues,
    )


def parse_pem_bundle(pem: str | bytes, now: datetime | None = None) -> list[CertificateInfo]:
    """Parse one or more certificates from a PEM blob.

    Handles full chains and HAProxy's combined cert+key files (the private key
    block is ignored — only CERTIFICATE blocks are parsed).
    """
    data = pem.encode() if isinstance(pem, str) else pem
    certs = x509.load_pem_x509_certificates(data)  # raises ValueError if none
    return [describe(c, now) for c in certs]
