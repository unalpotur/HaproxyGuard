import os
import asyncio
import subprocess
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.responses import JSONResponse

from .parser.parser import parse_config
from .parser.models import HaproxyConfig
from .analyzer.rules import analyze, Finding
from .autofix import FixEngine, FixProposal, has_fix
from .sslmgr import analyze_pem, scan as ssl_scan, CertificateInfo, SslReport
from . import security as sec
from . import assistant as ai
from . import cluster as cl
from . import alerts as al
from . import authz
from . import versions as ver
from .metrics.client import StatsClientError, StatsSocketClient
from .metrics.collector import MetricsCollector
from .db import init_db, close_db, AsyncSessionLocal
from .orm import PrincipalRow
from .logging import setup_logging

collector: MetricsCollector | None = None
fix_engine = FixEngine()
registry = cl.ClusterRegistry()
channels = al.ChannelRegistry()
version_store = ver.VersionStore()
principals = authz.PrincipalRegistry()
audit = authz.AuditLog()

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    global collector

    setup_logging()

    # ── startup validation ────────────────────────────────────────────
    _db_url = os.environ.get("DATABASE_URL", "").lower()
    if _db_url and not (_db_url.startswith("postgresql") or _db_url.startswith("sqlite")):
        raise RuntimeError(
            f"DATABASE_URL must be a PostgreSQL or SQLite connection string, "
            f"got: {_db_url[:40]}..."
        )

    _stats_addr = os.environ.get("HAPROXY_STATS_ADDR")
    if _stats_addr and ":" not in _stats_addr:
        raise RuntimeError(
            f"HAPROXY_STATS_ADDR must be host:port, got: {_stats_addr!r}"
        )

    # Initialise DB tables (dev/test helper; prod uses alembic upgrade head).
    await init_db()

    # Bootstrap admin principal from env (idempotent — skipped if already exists).
    _admin_key = os.environ.get("HG_ADMIN_KEY")
    if _admin_key:
        async with AsyncSessionLocal() as db:
            existing = await db.get(PrincipalRow, "admin")
            if existing is None:
                await principals.add_with_token("admin", "admin", _admin_key)

    # Start live metrics collector if stats addr is configured.
    stats_addr = os.environ.get("HAPROXY_STATS_ADDR")
    if stats_addr:
        interval = float(os.environ.get("HG_METRICS_INTERVAL", "2"))
        collector = MetricsCollector(StatsSocketClient(stats_addr), interval=interval)
        collector.start()

    yield

    if collector:
        await collector.stop()
    await close_db()


app = FastAPI(
    title="HAProxy Guard API",
    version="0.1.0",
    description="Parse, analyze and manage HAProxy configurations.",
    lifespan=lifespan,
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Try again later."},
    )


class ConfigInput(BaseModel):
    content: str


class AnalysisResult(BaseModel):
    findings: list[Finding]
    summary: dict[str, int]


async def _ws_auth(token: str | None) -> authz.Principal | None:
    """Authenticate a WebSocket connection via query-param token.

    Open mode (no principals configured) ⇒ anonymous admin.
    Enforcing mode ⇒ must provide a valid token.
    """
    if await principals.is_open():
        return authz.Principal(name="anonymous", role="admin")
    if token is None:
        return None
    return await principals.authenticate(token)


async def current_principal(x_api_key: str | None = Header(default=None)) -> authz.Principal:
    """Resolve the caller. Open mode (no principals configured) ⇒ anonymous admin."""
    if await principals.is_open():
        return authz.Principal(name="anonymous", role="admin")
    p = await principals.authenticate(x_api_key or "")
    if p is None:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")
    return p


async def require(principal: authz.Principal, role: str, action: str, target: str | None = None):
    """Enforce a minimum role, recording the outcome in the audit log."""
    if not authz.has_at_least(principal.role, role):
        await audit.append(principal.name, principal.role, action, target, status="denied",
                           detail=f"requires {role}")
        raise HTTPException(status_code=403, detail=f"Requires '{role}' role")
    await audit.append(principal.name, principal.role, action, target)


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse("/docs")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/local-config")
def local_config() -> dict:
    """Read the host's HAProxy config so it can be analyzed without pasting.

    Also returns any map files referenced inside the config via
    ``map_beg(path, ...)`` or ``map(path, ...)`` directives.
    """
    import re
    path = os.environ.get("HG_LOCAL_CONFIG", "/etc/haproxy/haproxy.cfg")
    try:
        with open(path) as f:
            content = f.read()
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"Cannot read {path}: {exc}")

    # Collect referenced map files (map / map_beg / map_dom / map_end / map_ip ...)
    result: dict = {"path": path, "content": content}
    map_files: dict[str, str] = {}
    base = os.path.dirname(path)
    for m in re.finditer(r'\bmap(?:_\w+)?\s*\(\s*([^,)]+)', content):
        map_path = m.group(1).strip()
        if not os.path.isabs(map_path):
            map_path = os.path.join(base, map_path)
        if os.path.isfile(map_path) and map_path not in map_files:
            try:
                with open(map_path) as mf:
                    map_files[map_path] = mf.read()
            except OSError:
                pass
    if map_files:
        result["map_files"] = map_files
    return result


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
async def fix_apply(body: FixInput) -> FixProposal:
    """Apply fixes and record a rollback point (returns version_id)."""
    return await fix_engine.apply(body.content, body.rule_ids, body.run_validation)


@app.post("/api/fix/rollback")
async def fix_rollback(body: RollbackInput) -> dict:
    try:
        version = await fix_engine.rollback(body.version_id)
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
    try:
        return analyze_pem(body.pem)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid PEM: {exc}")


@app.post("/api/ssl/scan", response_model=SslReport)
def ssl_scan_config(body: SslScanInput) -> SslReport:
    return ssl_scan(parse_config(body.content), read_files=body.read_files)


class SecurityGenerateInput(BaseModel):
    preset: str | None = None
    controls: list[sec.ControlRequest] | None = None
    table_size: str = "100k"
    table_expire: str = "30s"


@app.get("/api/security/catalog")
def security_catalog() -> dict:
    return {
        "controls": [c.model_dump() for c in sec.catalog()],
        "presets": [p.model_dump() for p in sec.PRESETS.values()],
    }


@app.post("/api/security/generate", response_model=sec.GeneratedConfig)
def security_generate(body: SecurityGenerateInput) -> sec.GeneratedConfig:
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
    return sec.assess(parse_config(body.content))


class AssistantInput(BaseModel):
    content: str
    logs: str | None = None
    use_llm: bool = True
    include_metrics: bool = True


@app.get("/api/assistant/status")
def assistant_status() -> dict:
    return {"llm_available": ai.llm_available()}


@app.post("/api/assistant/analyze", response_model=ai.AssistantReport)
def assistant_analyze(body: AssistantInput) -> ai.AssistantReport:
    metrics = collector.latest if (body.include_metrics and collector) else None
    return ai.analyze_deployment(
        body.content, logs_text=body.logs, metrics=metrics, use_llm=body.use_llm)


# --- Config versioning & diff -------------------------------------------

@app.get("/api/versions", response_model=list[ver.ConfigVersion])
async def versions_list(response: Response, limit: int = 50, offset: int = 0) -> list[ver.ConfigVersion]:
    all_versions = await version_store.list()
    total = len(all_versions)
    response.headers["X-Total-Count"] = str(total)
    return all_versions[offset:offset + limit]


@app.post("/api/versions", response_model=ver.ConfigVersion)
async def versions_save(
    body: ver.SaveVersionInput,
    principal: authz.Principal = Depends(current_principal),
) -> ver.ConfigVersion:
    await require(principal, "operator", "versions.save", body.label or None)
    return await version_store.save(body.content, body.label, body.message, principal.name)


@app.get("/api/versions/diff", response_model=ver.DiffResult)
async def versions_diff(a: str, b: str) -> ver.DiffResult:
    try:
        return ver.DiffResult(a=a, b=b, diff=await version_store.diff(a, b))
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown version id")


@app.get("/api/versions/{version_id}", response_model=ver.VersionContent)
async def versions_get(version_id: str) -> ver.VersionContent:
    v = await version_store.get(version_id)
    content = await version_store.content(version_id)
    if v is None or content is None:
        raise HTTPException(status_code=404, detail="Unknown version id")
    return ver.VersionContent(version=v, content=content)


@app.post("/api/versions/{version_id}/restore", response_model=ver.VersionContent)
async def versions_restore(
    version_id: str,
    principal: authz.Principal = Depends(current_principal),
) -> ver.VersionContent:
    await require(principal, "operator", "versions.restore", version_id)
    v = await version_store.restore(version_id, principal.name)
    if v is None:
        raise HTTPException(status_code=404, detail="Unknown version id")
    content = await version_store.content(v.id)
    return ver.VersionContent(version=v, content=content)


# --- Auth & audit (RBAC) ------------------------------------------------

@app.get("/api/auth/whoami", response_model=authz.Principal)
async def whoami(principal: authz.Principal = Depends(current_principal)) -> authz.Principal:
    return principal


@app.get("/api/auth/principals", response_model=list[authz.Principal])
async def list_principals(
    principal: authz.Principal = Depends(current_principal),
) -> list[authz.Principal]:
    await require(principal, "admin", "auth.list_principals")
    return await principals.list()


@app.post("/api/auth/principals", response_model=authz.PrincipalCreated)
@limiter.limit("5/minute")
async def create_principal(
    request: Request,
    body: authz.PrincipalInput,
    principal: authz.Principal = Depends(current_principal),
) -> authz.PrincipalCreated:
    await require(principal, "admin", "auth.create_principal", body.name)
    try:
        return await principals.add(body.name, body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/auth/principals/{name}")
@limiter.limit("5/minute")
async def delete_principal(
    request: Request,
    name: str,
    principal: authz.Principal = Depends(current_principal),
) -> dict:
    await require(principal, "admin", "auth.delete_principal", name)
    if not await principals.remove(name):
        raise HTTPException(status_code=404, detail="Unknown principal")
    return {"removed": name}


@app.get("/api/audit", response_model=list[authz.AuditEntry])
async def get_audit(
    response: Response,
    limit: int = 200,
    offset: int = 0,
    principal: authz.Principal = Depends(current_principal),
) -> list[authz.AuditEntry]:
    await require(principal, "operator", "audit.read")
    entries = await audit.list(limit + offset)
    total = len(entries)
    response.headers["X-Total-Count"] = str(total)
    return entries[offset:offset + limit]


# --- Alerting -----------------------------------------------------------

async def _evaluate_alerts(body: al.EvaluateInput) -> list[al.Alert]:
    overview = await registry.overview() if body.include_cluster else None
    return al.evaluate(body.content, body.logs, body.thresholds,
                       read_certs=body.read_certs, cluster_overview=overview)


@app.post("/api/alerts/evaluate", response_model=list[al.Alert])
async def alerts_evaluate(body: al.EvaluateInput) -> list[al.Alert]:
    return await _evaluate_alerts(body)


@app.post("/api/alerts/dispatch", response_model=al.DispatchResult)
async def alerts_dispatch(
    body: al.EvaluateInput,
    principal: authz.Principal = Depends(current_principal),
) -> al.DispatchResult:
    await require(principal, "operator", "alerts.dispatch")
    found = await _evaluate_alerts(body)
    return al.DispatchResult(alerts=found, results=await channels.dispatch(found))


@app.get("/api/alerts/channels", response_model=list[al.AlertChannel])
async def alerts_channels() -> list[al.AlertChannel]:
    return await channels.list()


@app.post("/api/alerts/channels", response_model=al.AlertChannel)
async def alerts_add_channel(
    body: al.ChannelInput,
    principal: authz.Principal = Depends(current_principal),
) -> al.AlertChannel:
    await require(principal, "operator", "alerts.add_channel", body.name)
    return await channels.add(body)


@app.delete("/api/alerts/channels/{channel_id}")
async def alerts_remove_channel(
    channel_id: str,
    principal: authz.Principal = Depends(current_principal),
) -> dict:
    await require(principal, "operator", "alerts.remove_channel", channel_id)
    if not await channels.remove(channel_id):
        raise HTTPException(status_code=404, detail="Unknown channel")
    return {"removed": channel_id}


# --- Multi-node cluster: control plane ----------------------------------

@app.post("/api/cluster/nodes", response_model=cl.EnrollResponse)
async def cluster_enroll(
    body: cl.EnrollInput,
    principal: authz.Principal = Depends(current_principal),
) -> cl.EnrollResponse:
    await require(principal, "operator", "cluster.enroll", body.name)
    result = await registry.enroll(
        body.name, body.address, body.labels,
        ssh_host=body.ssh_host, ssh_user=body.ssh_user,
        ssh_password=body.ssh_password, auto_deploy=body.auto_deploy, manage_mode=body.manage_mode,
    )
    if body.auto_deploy and body.ssh_host:
        if body.ssh_host in ("localhost", "127.0.0.1", "::1"):
            # localhost: can't SSH into ourselves from Docker
            pass  # deploy_status stays "pending", user runs bootstrap manually
        else:
            asyncio.create_task(_ssh_deploy(
                result.node.id, body.ssh_host, body.ssh_user or "root",
                body.ssh_password or "", result.token, body.manage_mode))
    return result


async def _ssh_deploy(node_id: str, host: str, user: str,
                       password: str, token: str, manage_mode: str = "auto") -> None:
    """Deploy agent + HAProxy to remote node via SSH."""
    await registry.set_deploy_status(node_id, "deploying")
    guard_url = os.environ.get("GUARD_PUBLIC_URL", "http://localhost:7000")
    env = {"SSHPASS": password}

    bootstrap = f'''#!/usr/bin/env bash
set -e
echo "$SUDO_PASS" | sudo -S bash -c '
set -e
mkdir -p /opt/haproxy-guard/certs
curl -sSf "{guard_url}/api/agent/script" -o /opt/haproxy-guard/haproxy_guard_agent.py

# Resolve the management mode: explicit choice, or auto-detect.
MODE="{manage_mode}"
if [ "$MODE" = "auto" ] || [ -z "$MODE" ]; then
  if systemctl cat haproxy >/dev/null 2>&1; then MODE=systemd; else MODE=docker; fi
fi

if [ "$MODE" = "systemd" ]; then
  # Manage the host HAProxy via systemctl; leave its config in place.
  cat > /opt/haproxy-guard/agent.env << AGENTENV
GUARD_URL={guard_url}
NODE_ID={node_id}
NODE_TOKEN={token}
MANAGE_MODE=systemd
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
CERT_DIR=/opt/haproxy-guard/certs
AGENTENV
else
  # Docker mode: run HAProxy in a container with host networking.
  mkdir -p /etc/haproxy
  cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak 2>/dev/null || true
  if [ ! -f /etc/haproxy/haproxy.cfg ]; then
    cat > /etc/haproxy/haproxy.cfg << HACFG
global
    log stdout format raw local0
    stats socket ipv4@0.0.0.0:9999 level admin
    stats timeout 30s
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend web
    bind *:80
    default_backend app
backend app
HACFG
  fi
  cat > /opt/haproxy-guard/agent.env << AGENTENV
GUARD_URL={guard_url}
NODE_ID={node_id}
NODE_TOKEN={token}
MANAGE_MODE=docker
CONTAINER_NAME=haproxy-prod
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
CERT_DIR=/opt/haproxy-guard/certs
AGENTENV
  docker rm -f haproxy-prod 2>/dev/null || true
  docker run -d --name haproxy-prod --network host --restart unless-stopped --user root \
    -v /etc/haproxy:/usr/local/etc/haproxy:ro \
    haproxy:2.9-alpine
fi
cat > /etc/systemd/system/haproxy-guard-agent.service << UNIT
[Unit]
Description=HAProxy Guard agent
After=network-online.target docker.service
[Service]
Type=simple
EnvironmentFile=/opt/haproxy-guard/agent.env
ExecStart=/usr/bin/python3 /opt/haproxy-guard/haproxy_guard_agent.py
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable haproxy-guard-agent
systemctl restart haproxy-guard-agent
'
echo "DEPLOY_OK"
'''

    try:
        proc = await asyncio.create_subprocess_exec(
            "sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", f"{user}@{host}",
            f"SUDO_PASS='{password}' bash -s",
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = await proc.communicate(input=bootstrap.encode())
        if proc.returncode == 0 and b"DEPLOY_OK" in stdout:
            await registry.set_deploy_status(node_id, "deployed")
        else:
            await registry.set_deploy_status(node_id, "failed")
    except Exception:
        await registry.set_deploy_status(node_id, "failed")


@app.get("/api/cluster/nodes", response_model=list[cl.Node])
async def cluster_nodes() -> list[cl.Node]:
    return await registry.list_nodes()


@app.get("/api/cluster/overview", response_model=cl.ClusterOverview)
async def cluster_overview() -> cl.ClusterOverview:
    return await registry.overview()


@app.get("/api/cluster/nodes/{node_id}", response_model=cl.Node)
async def cluster_node(node_id: str) -> cl.Node:
    node = await registry.get(node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    return node


@app.delete("/api/cluster/nodes/{node_id}")
async def cluster_remove(
    node_id: str,
    principal: authz.Principal = Depends(current_principal),
) -> dict:
    await require(principal, "operator", "cluster.remove", node_id)
    if not await registry.remove(node_id):
        raise HTTPException(status_code=404, detail="Unknown node")
    return {"removed": node_id}


@app.get("/api/cluster/nodes/{node_id}/deployments", response_model=list[cl.Deployment])
async def cluster_deployments(node_id: str) -> list[cl.Deployment]:
    if await registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    return await registry.deployments(node_id)


@app.post("/api/cluster/deploy", response_model=cl.DeployResult)
async def cluster_deploy(
    body: cl.DeployInput,
    principal: authz.Principal = Depends(current_principal),
) -> cl.DeployResult:
    await require(principal, "operator", "cluster.deploy",
                  ",".join(body.node_ids) if body.node_ids else str(body.selector))
    return await registry.deploy(body.content, body.node_ids, body.selector,
                                 body.validate_config, body.files)


@app.post("/api/cluster/deploy/check", response_model=cl.DeployCheck)
def cluster_deploy_check(body: cl.DeployCheckInput) -> cl.DeployCheck:
    """Pre-deploy lint: list external files the config needs (certs, maps,
    errorfiles, …) and warn about any we cannot ship to the target."""
    from .cluster.files import extract_file_refs
    refs = extract_file_refs(body.content)
    have = set(body.provided_files)

    def covered(ref: str) -> bool:
        # exact match, or a directory ref for which we hold a file underneath
        return ref in have or any(h.startswith(ref.rstrip("/") + "/") for h in have)

    provided = [r for r in refs if covered(r)]
    missing = [r for r in refs if not covered(r)]

    findings = analyze(parse_config(body.content))
    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    warnings: list[str] = []
    if missing:
        warnings.append(
            "Bu config şu harici dosyalara bağımlı ve elimizde yok: "
            + ", ".join(missing)
            + ". Hedef node'da bu dosyalar yoksa 'haproxy -c' başarısız olur. "
            "Önce kaynak node'dan 'Fetch config' ile çekerseniz dosyalar da gelir."
        )
    if provided:
        warnings.append("Şu dosyalar config ile birlikte gönderilecek: " + ", ".join(provided))
    critical = summary.get("critical", 0) + summary.get("high", 0)
    if critical:
        warnings.append(f"{critical} yüksek/kritik bulgu var — Findings sekmesine bakın.")

    return cl.DeployCheck(file_refs=refs, provided=provided, missing=missing,
                          warnings=warnings, findings_summary=summary)


@app.post("/api/cluster/nodes/{node_id}/rollback", response_model=cl.Deployment)
async def cluster_rollback(
    node_id: str,
    principal: authz.Principal = Depends(current_principal),
) -> cl.Deployment:
    await require(principal, "operator", "cluster.rollback", node_id)
    if await registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    dep = await registry.rollback(node_id)
    if dep is None:
        raise HTTPException(status_code=409, detail="No previous version to roll back to")
    return dep


@app.post("/api/cluster/nodes/{node_id}/action", response_model=dict)
async def cluster_node_action(
    node_id: str,
    body: cl.NodeAction,
    principal: authz.Principal = Depends(current_principal),
) -> dict:
    """Queue an action (restart/stop/start/cert-*) for a node."""
    await require(principal, "operator", "cluster.action", node_id)
    try:
        return await registry.set_action(node_id, body.type, body.params)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown node")


# --- Multi-node cluster: agent plane ------------------------------------

async def _auth_agent(node_id: str, authorization: str | None) -> None:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if not await registry.authenticate(node_id, token):
        raise HTTPException(status_code=401, detail="Invalid node token")


@app.post("/api/agent/{node_id}/heartbeat", response_model=cl.HeartbeatResult)
async def agent_heartbeat(
    node_id: str,
    body: cl.HeartbeatInput,
    authorization: str | None = Header(default=None),
) -> cl.HeartbeatResult:
    if await registry.get(node_id) is None:
        raise HTTPException(status_code=404, detail="Unknown node")
    await _auth_agent(node_id, authorization)
    return await registry.heartbeat(node_id, body)


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
            detail="Metrics not configured: set HAPROXY_STATS_ADDR.",
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
async def metrics_ws(ws: WebSocket, token: str | None = None) -> None:
    principal = await _ws_auth(token)
    if principal is None:
        await ws.accept()
        await ws.send_json({"ok": False, "error": "Authentication required. Pass ?token=... as query parameter."})
        await ws.close(code=4001)
        return

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


@app.get("/api/agent/script")
def agent_script():
    """Serve the agent script for remote download."""
    from fastapi.responses import PlainTextResponse
    script_path = Path("/opt/haproxy-guard/scripts/haproxy_guard_agent.py")
    if script_path.exists():
        return PlainTextResponse(script_path.read_text(), media_type="text/plain")
    return PlainTextResponse("# agent not found", status_code=404)
