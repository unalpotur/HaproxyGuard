"""Models for the Multi-Node Cluster control plane (Phase 9)."""
from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field

NodeStatus = str  # online | offline | pending


class Node(BaseModel):
    id: str
    name: str
    address: str
    labels: dict[str, str] = Field(default_factory=dict)
    status: NodeStatus = "pending"
    enrolled_at: datetime
    last_seen: datetime | None = None
    agent_version: str | None = None
    haproxy_version: str | None = None
    config_hash: str | None = None
    pending_version: int | None = None
    applied_version: int | None = None
    metrics: dict = Field(default_factory=dict)
    deploy_status: str = "pending"  # pending | deploying | deployed | failed
    service_status: str = "unknown"  # running | stopped | unknown
    last_action_result: dict | None = None
    ssh_host: str | None = None


class EnrollInput(BaseModel):
    name: str
    address: str
    labels: dict[str, str] = Field(default_factory=dict)
    ssh_host: str | None = None
    ssh_user: str | None = None
    ssh_password: str | None = None
    auto_deploy: bool = False
    manage_mode: str = "auto"  # auto | systemd | docker


class EnrollResponse(BaseModel):
    node: Node
    token: str  # shown once; the server only stores a hash


class Deployment(BaseModel):
    id: str
    node_id: str
    version: int
    config_hash: str
    status: str  # pending | applied | failed
    created_at: datetime
    message: str = ""
    findings_summary: dict[str, int] = Field(default_factory=dict)


class DeployInput(BaseModel):
    content: str
    node_ids: list[str] | None = None
    selector: dict[str, str] | None = None  # label match, e.g. {"role": "edge"}
    validate_config: bool = True


class DeployResult(BaseModel):
    deployments: list[Deployment] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)  # node ids that failed validation


class HeartbeatInput(BaseModel):
    agent_version: str | None = None
    haproxy_version: str | None = None
    config_version: int | None = None  # version the agent currently runs
    config_hash: str | None = None
    metrics: dict = Field(default_factory=dict)
    last_action: dict | None = None  # result of previous action {type, ok, error|output}
    service_status: str | None = None  # running | stopped


class HeartbeatResult(BaseModel):
    desired_version: int | None = None
    desired_config: str | None = None  # populated only when the agent is behind
    action: dict | None = None  # pending action {type, params} for the agent to execute


class NodeAction(BaseModel):
    """Admin-triggered action for a specific node."""
    type: str  # restart | stop | start | cert-list | cert-upload | cert-delete
    params: dict = Field(default_factory=dict)


class ClusterOverview(BaseModel):
    total: int = 0
    online: int = 0
    offline: int = 0
    pending: int = 0
    pending_deploys: int = 0
    haproxy_versions: dict[str, int] = Field(default_factory=dict)
    agent_versions: dict[str, int] = Field(default_factory=dict)
    distinct_config_hashes: int = 0  # >1 ⇒ configuration drift across the fleet
