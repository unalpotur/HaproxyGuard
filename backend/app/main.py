from fastapi import FastAPI
from pydantic import BaseModel

from .parser.parser import parse_config
from .parser.models import HaproxyConfig
from .analyzer.rules import analyze, Finding

app = FastAPI(
    title="HAProxy Guard API",
    version="0.1.0",
    description="Parse, analyze and manage HAProxy configurations.",
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
