from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.parser.parser import parse_config
from app.sslmgr import analyze_pem, scan
from app.sslmgr.ciphers import assess_bind


def make_cert(cn="example.com", days_valid=100, key_bits=2048, sans=None,
              not_before=None) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=1))
    na = now + timedelta(days=days_valid)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_analyze_valid_cert():
    pem = make_cert("valid.example", days_valid=100, sans=["valid.example", "www.valid.example"])
    info = analyze_pem(pem)[0]
    assert info.subject_cn == "valid.example"
    assert info.expiry_status == "ok"
    assert info.days_remaining >= 90
    assert info.key_type == "RSA" and info.key_bits == 2048
    assert "valid.example" in info.sans and "www.valid.example" in info.sans
    assert info.is_self_signed is True
    assert info.issues == [] or info.issues == ["self-signed certificate"]


def test_expired_cert():
    pem = make_cert(days_valid=-1, not_before=datetime.now(timezone.utc) - timedelta(days=30))
    info = analyze_pem(pem)[0]
    assert info.expiry_status == "expired"
    assert any("expired" in i for i in info.issues)


def test_critical_and_warning_thresholds():
    crit = analyze_pem(make_cert(days_valid=5))[0]
    warn = analyze_pem(make_cert(days_valid=20))[0]
    assert crit.expiry_status == "critical"
    assert warn.expiry_status == "warning"


def test_small_key_flagged():
    info = analyze_pem(make_cert(key_bits=1024))[0]
    assert any("too small" in i for i in info.issues)


def test_chain_bundle_parsed():
    bundle = make_cert("leaf.example") + make_cert("intermediate.example")
    infos = analyze_pem(bundle)
    assert {i.subject_cn for i in infos} == {"leaf.example", "intermediate.example"}


def test_invalid_pem_raises():
    with pytest.raises(ValueError):
        analyze_pem("not a certificate")


# --- cipher grading -------------------------------------------------------

def _bind(line: str):
    cfg = parse_config(f"frontend f\n    {line}\n")
    return cfg.frontends[0].binds[0]


def test_cipher_grade_weak():
    a = assess_bind(_bind("bind *:443 ssl crt /x.pem ciphers RC4-SHA"), "f")
    assert a.grade == "F"
    assert any("weak" in i for i in a.issues)


def test_cipher_grade_no_min_ver():
    a = assess_bind(_bind("bind *:443 ssl crt /x.pem"), "f")
    assert a.grade == "B"
    assert any("no minimum TLS version" in i for i in a.issues)


def test_cipher_grade_forced_legacy():
    a = assess_bind(_bind("bind *:443 ssl crt /x.pem force-tlsv10"), "f")
    assert a.grade == "F"


def test_cipher_global_min_ver_inherited():
    a = assess_bind(_bind("bind *:443 ssl crt /x.pem ciphers ECDHE-RSA-AES128-GCM-SHA256"),
                    "f", global_min_ver="TLSv1.2")
    assert a.min_version == "TLSv1.2"
    assert a.grade == "A"


# --- config scan ----------------------------------------------------------

def test_scan_collects_references_without_reading_disk():
    cfg = parse_config(
        "global\n    ssl-default-bind-options ssl-min-ver TLSv1.2\n"
        "frontend web\n    bind *:443 ssl crt /etc/haproxy/site.pem ciphers RC4\n"
    )
    report = scan(cfg, read_files=False)
    assert any(r.path == "/etc/haproxy/site.pem" and r.kind == "bind-crt"
               for r in report.references)
    assert report.certificates == []  # read_files=False
    assert report.ciphers and report.ciphers[0].grade == "F"
    assert any("Cipher grade F" in a for a in report.alerts)


def test_scan_reads_real_cert(tmp_path):
    pem = make_cert("disk.example", days_valid=3)
    p = tmp_path / "disk.pem"
    p.write_text(pem)
    cfg = parse_config(f"frontend web\n    bind *:443 ssl crt {p}\n")
    report = scan(cfg, read_files=True)
    entry = next(e for e in report.certificates if e.reference.path == str(p))
    assert entry.readable and entry.certificates[0].subject_cn == "disk.example"
    assert report.summary["critical"] == 1
    assert any("CRITICAL" in a for a in report.alerts)
