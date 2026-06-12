from app.assistant import analyze_deployment, analyze_logs, sanitize
from app.assistant.sanitizer import REDACTION

GOOD = """\
global
    log /dev/log local0
    maxconn 2000
defaults
    mode http
    log global
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend web
    bind *:443 ssl crt /etc/haproxy/site.pem ssl-min-ver TLSv1.2 ciphers ECDHE-RSA-AES128-GCM-SHA256
    default_backend app
backend app
    option httpchk GET /health
    server s1 10.0.0.1:8080 check
    server s2 10.0.0.2:8080 check
"""

BAD = """\
frontend web
    bind *:80
    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0 ciphers RC4-SHA
    default_backend ghost
listen stats
    bind *:8404
    stats enable
    stats auth admin:admin
"""

LOGS = "\n".join(
    f'1.2.3.4:5000 [16/Jul/2026:10:00:0{i}.000] web app/s1 0/0/1/2/{tt} {status} 100 - - ---- '
    f'1/1/0/0/0 0/0 "GET /x HTTP/1.1"'
    for i, (tt, status) in enumerate([
        (5, 200), (5, 200), (5, 500), (1500, 502), (5, 503), (5, 404), (5, 200), (5, 500),
    ])
)


def test_healthy_config_low_risk():
    report = analyze_deployment(GOOD, use_llm=False)
    assert report.risk_level in ("low", "medium")
    assert report.used_llm is False


def test_broken_config_high_risk():
    report = analyze_deployment(BAD, use_llm=False)
    assert report.risk_score > 40
    assert report.risk_level in ("high", "critical")
    titles = " ".join(rc.title for rc in report.root_causes).lower()
    assert "unknown backend" in titles or "weak tls" in titles
    assert report.recommendations  # actionable output


def test_logs_drive_error_rate_signal():
    report = analyze_deployment(GOOD, logs_text=LOGS, use_llm=False)
    assert report.log_summary is not None
    assert report.log_summary.parsed == 8
    assert report.log_summary.error_rate > 0.4  # 4 of 8 are >=400
    assert report.log_summary.slow_count == 1   # the 1500ms request
    assert any(rc.category == "logs" for rc in report.root_causes)


def test_analyze_logs_status_classes():
    ls = analyze_logs(LOGS)
    assert ls.status_classes.get("5xx") == 4
    assert ls.status_classes.get("2xx") == 3
    assert ls.backends_by_error and ls.backends_by_error[0]["backend"] == "app"


def test_metrics_down_servers_flagged():
    metrics = {"servers": [
        {"pxname": "app", "svname": "s1", "status": "DOWN"},
        {"pxname": "app", "svname": "s2", "status": "UP"},
    ]}
    report = analyze_deployment(GOOD, metrics=metrics, use_llm=False)
    assert any(rc.title == "Servers down" for rc in report.root_causes)


def test_sanitizer_masks_secrets():
    s = sanitize(BAD)
    assert "admin:admin" not in s
    assert "/x.pem" not in s
    assert REDACTION in s
    # structure preserved
    assert "stats auth admin:" in s
    assert "frontend web" in s


def test_sanitizer_masks_userlist_password():
    cfg = "userlist L\n    user bob insecure-password s3cr3t\n"
    s = sanitize(cfg)
    assert "s3cr3t" not in s
    assert "user bob insecure-password" in s


def test_use_llm_false_never_calls_model():
    # With use_llm=False the report must be purely heuristic regardless of env
    report = analyze_deployment(BAD, use_llm=False)
    assert report.used_llm is False
    assert report.llm_narrative is None
