import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .parser.parser import parse_config
from .parser.models import HaproxyConfig
from .analyzer.rules import analyze, Finding
from .autofix import FixEngine, FixProposal, has_fix
from .sslmgr import analyze_pem, scan as ssl_scan, CertificateInfo, SslReport
from . import security as sec
from . import assistant as ai
from . import cluster as cl
from . import alerts as al
from .metrics.client import StatsClientError, StatsSocketClient
from .metrics.collector import MetricsCollector

collector: MetricsCollector | None = None
fix_engine = FixEngine()
registry = cl.ClusterRegistry()
channels = al.ChannelRegistry()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global collector
    stats_addr = os.environ.get("HAPROXY_STATS_ADDR")
    if stats_addr:
        interval = float(os.environ.get("HG_METRICS_INTERVAL", "2"))
        collector = MetricsCollector(StatsSocketClient(stats_addr), interval=interval)
        collector.start()
    yield
    if collector:
        await collector.stop()


app = FastAPI(
    title="HAProxy Guard API",
    version="0.1.0",
    description="Parse, analyze and manage HAProxy configurations.",
    lifespan=lifespan,
)


class ConfigInput(BaseModel):
    content: str


class AnalysisResult(BaseModel):
    findings: list[Finding]
    summary: dict[str, int]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/parse", response_model=HaproxyConfig)
def parse(body: ConfigInput) -> HaproxyConfig:
    return parse_config(body.content)


@app.post("/api/analyze", response_model=AnalysisResult)
def analyze_config(body: ConfigInput) -> AnalysisResult:
    findings = analyze(parse_config(body.content))
    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
        f.fixable = has_fix(f.rule_id)
    return AnalysisResult(findings=findings, summary=summary)


class FixInput(BaseModel):
    content: str
    rule_ids: list[str] | None = None
    run_validation: bool = True


class RollbackInput(BaseModel):
    version_id: str


@app.post("/api/fix/preview", response_model=FixProposal)
def fix_preview(body: FixInput) -> FixProposal:
    """Dry-run: compute the patched config and a unified diff without saving."""
    return fix_engine.dry_run(body.content, body.rule_ids, body.run_validation)


@app.post("/api/fix/apply", response_model=FixProposal)
def fix_apply(body: FixInput) -> FixProposal:
    """Apply fixes and record a rollback point (returns version_id)."""
    return fix_engine.apply(body.content, body.rule_ids, body.run_validation)


@app.post("/api/fix/rollback")
def fix_rollback(body: RollbackInput) -> dict:
    try:
        version = fix_engine.rollback(body.version_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown version_id")
    return {"version_id": version.version_id, "content": version.content,
            "created_at": version.created_at.isoformat()}


class CertInput(BaseModel):
    pem: str


class SslScanInput(BaseModel):
    content: str
    read_files: bool = True


@app.post("/api/ssl/analyze-cert", response_model=list[CertificateInfo])
def ssl_analyze_cert(body: CertInput) -> list[CertificateInfo]:
    """Parse a pasted PEM bundle (chain or cert+key) and report each cert."""
    try:
        return analyze_pem(body.pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid PEM: {exc}")


@app.post("/api/ssl/scan", response_model=SslReport)
def ssl_scan_config(body: SslScanInput) -> SslReport:
    """Scan a config for certificate references, expiry status and cipher grades."""
    return ssl_scan(parse_config(body.content), read_files=body.read_files)


class SecurityGenerateInput(BaseModel):
    preset: str | None = None
    controls: list[sec.ControlRequest] | None = None
    table_size: str = "100k"
    table_expire: str = "30s"


@app.get("/api/security/catalog")
def security_catalog() -> dict:
    """List available security controls and presets."""
    return {
        "controls": [c.model_dump() for c in sec.catalog()],
        "presets": [p.model_dump() for p in sec.PRESETS.values()],
    }


@app.post("/api/security/generate", response_model=sec.GeneratedConfig)
def security_generate(body: SecurityGenerateInput) -> sec.GeneratedConfig:
    """Generate hardening snippets from a preset or an explicit control list."""
    try:
        if body.preset:
            return sec.generate_preset(
                body.preset, table_size=body.table_size, table_expire=body.table_expire)
        if not body.controls:
            raise HTTPException(status_code=400, detail="Provide a preset or controls.")
        return sec.generate(
            body.controls, table_size=body.table_size, table_expire=body.table_expire)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown preset/control: {exc}")


@app.post("/api/security/posture", response_model=sec.SecurityPosture)
def security_posture(body: ConfigInput) -> sec.SecurityPosture:
    """Report which security controls a config already implements."""
    return sec.assess(parse_config(body.content))


class AssistantInput(BaseModel):
    content: str
    logs: str | None = None
    use_llm: bool = True
    include_metrics: bool = True


@app.get("/api/assistant/status")
def assistant_status() -> dict:
    """Whether the LLM-backed narrative is available (API key + SDK present)."""
    return {"llm_available": ai.llm_available()}


@app.post("/api/assistant/analyze", response_model=ai.AssistantReport)
def assistant_analyze(body: AssistantInput) -> ai.AssistantReport:
    """Root-cause analysis, risk score and recommendations for a deployment."""
    metrics = collector.latest if (body.include_metrics and collector) else None
    return ai.analyze_deployment(
        body.content, logs_text=body.logs, metrics=metrics, use_llm=body.use_llm)


# --- Alerting -----------------------------------------------------------

def _evaluate_alerts(body: al.EvaluateInput) -> list[al.Alert]:
    overview = registry.overview() if body.include_cluster else None
    return al.evaluate(body.content, body.logs, body.thresholds,
                       read_certs=body.read_certs, cluster_overview=overview)


@app.post("/api/alerts/evaluate", response_model=list[al.Alert])
def alerts_evaluate(body: al.EvaluateInput) -> list[al.Alert]:
    """Evaluate the deployment and return alerts without notifying anyone."""
    return _evaluate_alerts(body)


@app.post("/api/alerts/dispatch", response_model=al.DispatchResult)
def alerts_dispatch(body: al.EvaluateInput) -> al.DispatchResult:
    """Evaluate and send the alerts to every configured channel."""
    found = _evaluate_alerts(body)
    return al.DispatchResult(alerts=found, results=channels.dispatch(found))


@app.get("/api/alerts/channels", response_model=list[al.AlertChannel])
def alerts_channels() -> list[al.AlertChannel]:
    return channels.list()


@app.post("/api/alerts/channels", response_model=al.AlertChannel)
def alerts_add_channel(body: al.ChannelInput) -> al.AlertChannel:
    return channels.add(body)


@app.delete("/api/alerts/channels/{channel_id}")
def alerts_remove_channel(channel_id: str) -> dict:
    if not channels.remove(channel_id):
        raise HTTPException(status_code=404, detail="Unknown channel")
    return {"removed": channel_id}


# --- Multi-node cluster: control plane (dashboard) ----------------------

@app.post("/api/cluster/nodes", response_model=cl.EnrollResponse)
def cluster_enroll(body: cl.EnrollInput) -> cl.EnrollResponse:
    """Enroll an HAProxy agent; returns a bearer token shown only once."""
    return registry.enroll(body.name, body.address, body.labels)


@app.get("/api/cluster/nodes", response_model=list[cl.Node])
def cluster_nodes() -> list[cl.Node]:
    return registry.list_nodes()


@app.get("/api/cluster/overview", response_model=cl.ClusterOverview)
def cluster_overview() -> cl.ClusterOverview:
    return registry.overview()


@app.get("/api/cluster/nodes/{node_id}", response_model=cl.Node)
def cluster_node(node_id: str) -> cl.Node:
    node = registry.get(node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    return node


@app.delete("/api/cluster/nodes/{node_id}")
def cluster_remove(node_id: str) -> dict:
    if not registry.remove(node_id):
        raise HTTPException(status_code=404, detail="Unknown node")
    return {"removed": node_id}


@app.get("/api/cluster/nodes/{node_id}/deployments", response_model=list[cl.Deployment])
def cluster_deployments(node_id: str) -> list[cl.Deployment]:
    if registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    return registry.deployments(node_id)


@app.post("/api/cluster/deploy", response_model=cl.DeployResult)
def cluster_deploy(body: cl.DeployInput) -> cl.DeployResult:
    """Validate and push a config to nodes (by id list or label selector)."""
    return registry.deploy(body.content, body.node_ids, body.selector, body.validate_config)


@app.post("/api/cluster/nodes/{node_id}/rollback", response_model=cl.Deployment)
def cluster_rollback(node_id: str) -> cl.Deployment:
    if registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    dep = registry.rollback(node_id)
    if dep is None:
        raise HTTPException(status_code=409, detail="No previous version to roll back to")
    return dep


# --- Multi-node cluster: agent plane (token-authenticated) --------------

def _auth_agent(node_id: str, authorization: str | None) -> None:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if not registry.authenticate(node_id, token):
        raise HTTPException(status_code=401, detail="Invalid node token")


@app.post("/api/agent/{node_id}/heartbeat", response_model=cl.HeartbeatResult)
def agent_heartbeat(node_id: str, body: cl.HeartbeatInput,
                    authorization: str | None = Header(default=None)) -> cl.HeartbeatResult:
    """Called by an agent: report status, receive any pending desired config."""
    if registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    _auth_agent(node_id, authorization)
    return registry.heartbeat(node_id, body)


@app.post("/api/topology")
def topology(body: ConfigInput) -> dict:
    """Graph (nodes/edges) for the React Flow topology view."""
    cfg = parse_config(body.content)
    nodes, edges = [], []
    for fe in cfg.frontends + cfg.listens:
        fe_id = f"fe:{fe.name}"
        nodes.append({"id": fe_id, "type": "frontend", "label": fe.name,
                      "binds": [f"{b.address}:{b.port}" for b in fe.binds]})
        targets = {r.backend: (r.condition or "") for r in fe.switching_rules}
        if fe.default_backend:
            targets.setdefault(fe.default_backend, "default")
        for be_name, cond in targets.items():
            edges.append({"source": fe_id, "target": f"be:{be_name}", "label": cond})
    for be in cfg.backends + cfg.listens:
        be_id = f"be:{be.name}"
        nodes.append({"id": be_id, "type": "backend", "label": be.name,
                      "balance": be.balance})
        for s in be.servers:
            srv_id = f"srv:{be.name}/{s.name}"
            nodes.append({"id": srv_id, "type": "server", "label": s.name,
                          "address": f"{s.address}:{s.port}", "check": s.check})
            edges.append({"source": be_id, "target": srv_id, "label": ""})
    return {"nodes": nodes, "edges": edges}


def _require_collector() -> MetricsCollector:
    if collector is None:
        raise HTTPException(
            status_code=503,
            detail="Metrics not configured: set HAPROXY_STATS_ADDR (e.g. 127.0.0.1:9999 or /run/haproxy.sock).",
        )
    return collector


@app.get("/api/metrics/snapshot")
async def metrics_snapshot() -> dict:
    c = _require_collector()
    return c.latest or await c.collect_once()


@app.get("/api/metrics/history")
def metrics_history(limit: int = 300) -> dict:
    c = _require_collector()
    return {"snapshots": list(c.history)[-limit:]}


@app.get("/api/metrics/info")
async def haproxy_info() -> dict:
    c = _require_collector()
    try:
        return await c.client.show_info()
    except StatsClientError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.websocket("/api/ws/metrics")
async def metrics_ws(ws: WebSocket) -> None:
    await ws.accept()
    if collector is None:
        await ws.send_json({"ok": False, "error": "HAPROXY_STATS_ADDR not configured"})
        await ws.close(code=1011)
        return
    queue = collector.subscribe()
    try:
        if collector.latest:
            await ws.send_json(collector.latest)
        while True:
            await ws.send_json(await queue.get())
    except WebSocketDisconnect:
        pass
    finally:
        collector.unsubscribe(queue)
