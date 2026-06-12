"""In-memory cluster control plane: enrollment, heartbeats, deploys, rollback.

A real deployment would back this with a database and mTLS; here the focus is the
control-plane logic. Agents authenticate with a per-node bearer token — only a
salted hash is stored, and comparison is constant-time. Config distribution is
pull-based: the control plane records the desired config, and each agent fetches
it on its next heartbeat, applies it, and reports back.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from ..autofix.validator import validate
from .models import (
    ClusterOverview, Deployment, DeployResult, EnrollResponse,
    HeartbeatResult, Node,
)

OFFLINE_AFTER_SECONDS = 30.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def config_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


@dataclass
class _NodeRecord:
    node: Node
    token_hash: str
    desired_config: str | None = None
    history: list[tuple[int, str]] = field(default_factory=list)  # (version, content)
    deployments: list[Deployment] = field(default_factory=list)
    _version_counter: int = 0


class ClusterRegistry:
    def __init__(self, offline_after: float = OFFLINE_AFTER_SECONDS) -> None:
        self._nodes: dict[str, _NodeRecord] = {}
        self._offline_after = offline_after

    # -- enrollment -------------------------------------------------------

    def enroll(self, name: str, address: str, labels: dict[str, str]) -> EnrollResponse:
        node_id = "node_" + uuid.uuid4().hex[:10]
        token = secrets.token_urlsafe(32)
        node = Node(id=node_id, name=name, address=address, labels=labels,
                    enrolled_at=_now())
        self._nodes[node_id] = _NodeRecord(node=node, token_hash=_hash_token(token))
        return EnrollResponse(node=self._view(self._nodes[node_id]), token=token)

    def remove(self, node_id: str) -> bool:
        return self._nodes.pop(node_id, None) is not None

    # -- agent plane ------------------------------------------------------

    def authenticate(self, node_id: str, token: str) -> bool:
        rec = self._nodes.get(node_id)
        if rec is None:
            return False
        return hmac.compare_digest(rec.token_hash, _hash_token(token))

    def heartbeat(self, node_id: str, payload) -> HeartbeatResult:
        rec = self._nodes[node_id]
        n = rec.node
        n.last_seen = _now()
        if payload.agent_version is not None:
            n.agent_version = payload.agent_version
        if payload.haproxy_version is not None:
            n.haproxy_version = payload.haproxy_version
        if payload.config_hash is not None:
            n.config_hash = payload.config_hash
        if payload.metrics:
            n.metrics = payload.metrics
        # reconcile deploy state: did the agent converge to the desired version?
        if payload.config_version is not None:
            n.applied_version = payload.config_version
            for d in rec.deployments:
                if d.version == payload.config_version and d.status == "pending":
                    d.status = "applied"

        behind = (
            n.pending_version is not None
            and (n.applied_version is None or n.applied_version < n.pending_version)
        )
        return HeartbeatResult(
            desired_version=n.pending_version,
            desired_config=rec.desired_config if behind else None,
        )

    # -- control plane ----------------------------------------------------

    def list_nodes(self) -> list[Node]:
        return [self._view(r) for r in self._nodes.values()]

    def get(self, node_id: str) -> Node | None:
        rec = self._nodes.get(node_id)
        return self._view(rec) if rec else None

    def deployments(self, node_id: str) -> list[Deployment]:
        rec = self._nodes.get(node_id)
        return list(rec.deployments) if rec else []

    def select(self, node_ids: list[str] | None, selector: dict[str, str] | None) -> list[str]:
        if node_ids:
            return [i for i in node_ids if i in self._nodes]
        if selector:
            return [
                nid for nid, r in self._nodes.items()
                if all(r.node.labels.get(k) == v for k, v in selector.items())
            ]
        return list(self._nodes.keys())

    def deploy(self, content: str, node_ids, selector, validate_config: bool) -> DeployResult:
        result = DeployResult()
        targets = self.select(node_ids, selector)

        validation = validate(content) if validate_config else None
        findings = analyze(parse_config(content))
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        for nid in targets:
            rec = self._nodes[nid]
            if validation is not None and validation.ran and not validation.ok:
                rec.deployments.append(Deployment(
                    id="dep_" + uuid.uuid4().hex[:10], node_id=nid, version=0,
                    config_hash=config_hash(content), status="failed",
                    created_at=_now(), message="validation failed: " + validation.message[:200],
                    findings_summary=summary,
                ))
                result.skipped.append(nid)
                continue
            rec._version_counter += 1
            version = rec._version_counter
            rec.desired_config = content
            rec.history.append((version, content))
            rec.node.pending_version = version
            dep = Deployment(
                id="dep_" + uuid.uuid4().hex[:10], node_id=nid, version=version,
                config_hash=config_hash(content), status="pending", created_at=_now(),
                findings_summary=summary,
            )
            rec.deployments.append(dep)
            result.deployments.append(dep)
        return result

    def rollback(self, node_id: str) -> Deployment | None:
        rec = self._nodes.get(node_id)
        if rec is None or len(rec.history) < 2:
            return None
        rec.history.pop()  # drop current
        version, content = rec.history[-1]
        rec._version_counter += 1
        new_version = rec._version_counter
        rec.desired_config = content
        rec.history.append((new_version, content))
        rec.node.pending_version = new_version
        dep = Deployment(
            id="dep_" + uuid.uuid4().hex[:10], node_id=node_id, version=new_version,
            config_hash=config_hash(content), status="pending", created_at=_now(),
            message=f"rollback to config of version {version}",
        )
        rec.deployments.append(dep)
        return dep

    def overview(self) -> ClusterOverview:
        nodes = self.list_nodes()
        ov = ClusterOverview(total=len(nodes))
        hashes: set[str] = set()
        for n in nodes:
            setattr(ov, n.status, getattr(ov, n.status, 0) + 1)
            if n.pending_version and n.applied_version != n.pending_version:
                ov.pending_deploys += 1
            if n.haproxy_version:
                ov.haproxy_versions[n.haproxy_version] = ov.haproxy_versions.get(n.haproxy_version, 0) + 1
            if n.agent_version:
                ov.agent_versions[n.agent_version] = ov.agent_versions.get(n.agent_version, 0) + 1
            if n.config_hash:
                hashes.add(n.config_hash)
        ov.distinct_config_hashes = len(hashes)
        return ov

    # -- helpers ----------------------------------------------------------

    def _view(self, rec: _NodeRecord) -> Node:
        n = rec.node.model_copy()
        n.status = self._status(n)
        return n

    def _status(self, n: Node) -> str:
        if n.last_seen is None:
            return "pending"
        age = (_now() - n.last_seen).total_seconds()
        return "online" if age <= self._offline_after else "offline"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
