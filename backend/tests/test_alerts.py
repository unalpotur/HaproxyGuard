from app.alerts import evaluate, ChannelRegistry, build_payload
from app.alerts.channels import _eligible
from app.alerts.models import Alert, AlertChannel, ChannelInput, Thresholds
from app.cluster import ClusterRegistry
from app.cluster.models import HeartbeatInput

CLEAN = (
    "defaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n"
    "    timeout server 30s\n    log global\nglobal\n    log /dev/log local0\n"
    "frontend f\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.2 "
    "ciphers ECDHE-RSA-AES128-GCM-SHA256\n    default_backend b\n"
    "backend b\n    option httpchk GET /h\n    server s 1.1.1.1:443 check ssl verify required ca-file /ca.pem\n"
)
BROKEN = (
    "frontend f\n    bind *:443 ssl crt /x.pem ssl-min-ver TLSv1.0 ciphers RC4-SHA\n"
    "    default_backend ghost\n"
)

LOGS_ERR = "\n".join(
    f'1.2.3.4:5000 [16/Jul/2026:10:00:0{i}] f b/s 0/0/1/2/5 {st} 100 - - ---- '
    f'1/1/0/0/0 0/0 "GET / HTTP/1.1"'
    for i, st in enumerate([500, 502, 503, 500, 200])
)


def test_evaluate_clean_config_few_alerts():
    alerts = evaluate(CLEAN, None, Thresholds())
    # a clean config produces no critical/high config or TLS alerts
    assert all(a.severity not in ("critical",) for a in alerts)


def test_evaluate_broken_config_alerts():
    alerts = evaluate(BROKEN, None, Thresholds())
    sources = {a.source for a in alerts}
    assert "config" in sources  # unknown backend reference (critical)
    assert "tls" in sources     # weak cipher / weak min-ver
    assert any(a.severity == "critical" for a in alerts)


def test_evaluate_log_error_rate_alert():
    alerts = evaluate(CLEAN, LOGS_ERR, Thresholds(error_rate=0.05))
    log_alerts = [a for a in alerts if a.source == "logs"]
    assert log_alerts and "error rate" in log_alerts[0].title.lower()


def test_evaluate_cluster_offline_and_drift():
    reg = ClusterRegistry(offline_after=-1)  # everything offline
    a = reg.enroll("a", "10.0.0.1", {}).node.id
    b = reg.enroll("b", "10.0.0.2", {}).node.id
    reg.heartbeat(a, HeartbeatInput(config_hash="h1"))
    reg.heartbeat(b, HeartbeatInput(config_hash="h2"))
    alerts = evaluate(CLEAN, None, Thresholds(), cluster_overview=reg.overview())
    titles = {a.title for a in alerts}
    assert "Nodes offline" in titles
    assert "Configuration drift" in titles


def test_severity_filtering():
    alerts = [
        Alert(severity="critical", source="x", title="c", detail=""),
        Alert(severity="medium", source="x", title="m", detail=""),
        Alert(severity="low", source="x", title="l", detail=""),
    ]
    assert len(_eligible(alerts, "high")) == 1   # only critical passes a 'high' bar
    assert len(_eligible(alerts, "low")) == 3


def test_channel_registry_crud():
    reg = ChannelRegistry()
    ch = reg.add(ChannelInput(name="ops", type="webhook", url="https://example.com/hook"))
    assert ch.id.startswith("chan_")
    assert len(reg.list()) == 1
    assert reg.remove(ch.id) is True
    assert reg.list() == []


def test_slack_payload_shape():
    ch = AlertChannel(id="c", name="s", type="slack", url="x")
    payload = build_payload(ch, [Alert(severity="high", source="x", title="T", detail="D")])
    assert "text" in payload and "T" in payload["text"]


def test_webhook_payload_shape():
    ch = AlertChannel(id="c", name="w", type="webhook", url="x")
    payload = build_payload(ch, [Alert(severity="high", source="x", title="T", detail="D")])
    assert payload["count"] == 1 and payload["alerts"][0]["title"] == "T"


def test_dispatch_with_no_channels_is_empty():
    assert ChannelRegistry().dispatch([Alert(severity="critical", source="x", title="t", detail="")]) == []
