import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .parser.parser import parse_config
from .parser.models import HaproxyConfig
from .analyzer.rules import analyze, Finding
from .autofix import FixEngine, FixProposal, has_fix
from .sslmgr import analyze_pem, scan as ssl_scan, CertificateInfo, SslReport
from .metrics.client import StatsClientError, StatsSocketClient
from .metrics.collector import MetricsCollector

collector: MetricsCollector | None = None
fix_engine = FixEngine()


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
