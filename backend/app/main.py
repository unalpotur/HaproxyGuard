import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .parser.parser import parse_config
from .parser.models import HaproxyConfig
from .analyzer.rules import analyze, Finding
from .metrics.client import StatsClientError, StatsSocketClient
from .metrics.collector import MetricsCollector

collector: MetricsCollector | None = None


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
    return AnalysisResult(findings=findings, summary=summary)


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
