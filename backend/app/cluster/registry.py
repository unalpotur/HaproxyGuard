"""DB-backed cluster control plane: enrollment, heartbeats, deploys, rollback.

Pull-based config distribution: the control plane records the desired config,
each agent fetches it on its next heartbeat, applies it, and reports back.
Node tokens are stored as SHA-256 hashes; comparison is constant-time.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from ..autofix.validator import validate
from ..db import AsyncSessionLocal
from ..orm import ClusterDeploymentRow, ClusterNodeRow
from .models import (
    ClusterOverview, Deployment, DeployResult, EnrollResponse,
    HeartbeatResult, Node,
)

OFFLINE_AFTER_SECONDS = 30.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def config_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _node_status(last_seen: datetime | None, offline_after: float) -> str:
    if last_seen is None:
        return "pending"
    # sqlite returns naive datetimes, make sure it is aware
    ls = last_seen.replace(tzinfo=timezone.utc) if last_seen.tzinfo is None else last_seen
    age = (_now() - ls).total_seconds()
    return "online" if age <= offline_after else "offline"


def _row_to_node(row: ClusterNodeRow, offline_after: float = OFFLINE_AFTER_SECONDS) -> Node:
    return Node(
        id=row.id,
        name=row.name,
        address=row.address,
        labels=row.labels or {},
        status=_node_status(row.last_seen, offline_after),
        enrolled_at=row.enrolled_at.replace(tzinfo=timezone.utc) if getattr(row.enrolled_at, "tzinfo", None) is None else row.enrolled_at,
        last_seen=row.last_seen.replace(tzinfo=timezone.utc) if row.last_seen and getattr(row.last_seen, "tzinfo", None) is None else row.last_seen,
        agent_version=row.agent_version,
        haproxy_version=row.haproxy_version,
        config_hash=row.config_hash,
        pending_version=row.pending_version,
        applied_version=row.applied_version,
        metrics=row.metrics or {},
        deploy_status=row.deploy_status or "pending",
        service_status=row.service_status or "unknown",
        last_action_result=row.last_action_result,
        ssh_host=row.ssh_host,
    )


def _row_to_deployment(row: ClusterDeploymentRow) -> Deployment:
    return Deployment(
        id=row.id,
        node_id=row.node_id,
        version=row.version,
        config_hash=row.config_hash,
        status=row.status,
        created_at=row.created_at.replace(tzinfo=timezone.utc) if getattr(row.created_at, "tzinfo", None) is None else row.created_at,
        message=row.message or "",
        findings_summary=row.findings_summary or {},
    )


class ClusterRegistry:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        offline_after: float = OFFLINE_AFTER_SECONDS,
    ) -> None:
        self._sf = session_factory or AsyncSessionLocal
        self._offline_after = offline_after

    # -- enrollment -------------------------------------------------------

    async def enroll(self, name: str, address: str, labels: dict[str, str],
                     ssh_host: str | None = None, ssh_user: str | None = None,
                     ssh_password: str | None = None, auto_deploy: bool = False, manage_mode: str = "auto") -> EnrollResponse:
        node_id = "node_" + uuid.uuid4().hex[:10]
        token = secrets.token_urlsafe(32)
        async with self._sf() as db:
            row = ClusterNodeRow(
                id=node_id, name=name, address=address,
                labels=labels, enrolled_at=_now(),
                token_hash=_hash_token(token),
                version_counter=0,
                ssh_host=ssh_host,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                deploy_status="deploying" if auto_deploy else "pending",
            )
            db.add(row)
            await db.commit()
        node = _row_to_node(row, self._offline_after)
        return EnrollResponse(node=node, token=token)

    async def remove(self, node_id: str) -> bool:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row is None:
                return False
            await db.delete(row)
            await db.commit()
            return True

    # -- agent plane ------------------------------------------------------

    async def authenticate(self, node_id: str, token: str) -> bool:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row is None:
                return False
            return hmac.compare_digest(row.token_hash, _hash_token(token))

    async def heartbeat(self, node_id: str, payload) -> HeartbeatResult:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row is None:
                raise KeyError(node_id)
            row.last_seen = _now()
            if payload.agent_version is not None:
                row.agent_version = payload.agent_version
            if payload.haproxy_version is not None:
                row.haproxy_version = payload.haproxy_version
            if payload.config_hash is not None:
                row.config_hash = payload.config_hash
            if payload.metrics:
                row.metrics = payload.metrics
            if getattr(payload, "service_status", None):
                row.service_status = payload.service_status
            if getattr(payload, "last_action", None):
                # Stamp the result with a server-side receive time so the UI can
                # tell a fresh action result apart from one left over from an
                # earlier action (the row keeps the last result indefinitely).
                row.last_action_result = {**payload.last_action, "_ts": _now().timestamp()}
            if payload.config_version is not None:
                row.applied_version = payload.config_version
                # mark matching pending deployment as applied
                result = await db.execute(
                    select(ClusterDeploymentRow)
                    .where(ClusterDeploymentRow.node_id == node_id)
                    .where(ClusterDeploymentRow.version == payload.config_version)
                    .where(ClusterDeploymentRow.status == "pending")
                )
                for dep in result.scalars():
                    dep.status = "applied"

            # ── action result: clear pending action ──────────────────
            last_action = getattr(payload, "last_action", None)
            if last_action and row.pending_action:
                # Clear the action now that agent has reported result
                row.pending_action = None

            await db.commit()

            behind = (
                row.pending_version is not None
                and (row.applied_version is None or row.applied_version < row.pending_version)
            )
            return HeartbeatResult(
                desired_version=row.pending_version,
                desired_config=row.desired_config if behind else None,
                desired_files=row.desired_files if behind else None,
                action=row.pending_action,
            )

    # -- control plane ----------------------------------------------------

    async def list_nodes(self) -> list[Node]:
        async with self._sf() as db:
            result = await db.execute(select(ClusterNodeRow).order_by(ClusterNodeRow.name))
            return [_row_to_node(r, self._offline_after) for r in result.scalars()]

    async def get(self, node_id: str) -> Node | None:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            return _row_to_node(row, self._offline_after) if row else None

    async def deployments(self, node_id: str) -> list[Deployment]:
        async with self._sf() as db:
            result = await db.execute(
                select(ClusterDeploymentRow)
                .where(ClusterDeploymentRow.node_id == node_id)
                .order_by(ClusterDeploymentRow.created_at.desc())
            )
            return [_row_to_deployment(r) for r in result.scalars()]

    async def select(
        self,
        node_ids: list[str] | None,
        selector: dict[str, str] | None,
    ) -> list[str]:
        async with self._sf() as db:
            result = await db.execute(select(ClusterNodeRow).order_by(ClusterNodeRow.name))
            rows = list(result.scalars())
        if node_ids:
            known = {r.id for r in rows}
            return [i for i in node_ids if i in known]
        if selector:
            return [
                r.id for r in rows
                if all(r.labels.get(k) == v for k, v in selector.items())
            ]
        return [r.id for r in rows]

    async def deploy(
        self,
        content: str,
        node_ids: list[str] | None,
        selector: dict[str, str] | None,
        validate_config: bool,
        files: dict[str, str] | None = None,
    ) -> DeployResult:
        result = DeployResult()
        targets = await self.select(node_ids, selector)
        files = files or None

        validation = validate(content) if validate_config else None
        findings = analyze(parse_config(content))
        summary: dict[str, int] = {}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        async with self._sf() as db:
            for nid in targets:
                row = await db.get(ClusterNodeRow, nid)
                if row is None:
                    continue
                if validation is not None and validation.ran and not validation.ok:
                    dep_row = ClusterDeploymentRow(
                        id="dep_" + uuid.uuid4().hex[:10], node_id=nid, version=0,
                        config_hash=config_hash(content), status="failed",
                        created_at=_now(),
                        message="validation failed: " + validation.message[:200],
                        findings_summary=summary,
                    )
                    db.add(dep_row)
                    result.skipped.append(nid)
                    continue
                row.version_counter += 1
                version = row.version_counter
                row.desired_config = (content or "").rstrip("\n") + "\n"
                row.desired_files = files
                row.pending_version = version
                dep_row = ClusterDeploymentRow(
                    id="dep_" + uuid.uuid4().hex[:10], node_id=nid, version=version,
                    config_hash=config_hash(content), status="pending",
                    created_at=_now(), findings_summary=summary,
                    config_content=content,
                )
                db.add(dep_row)
                result.deployments.append(_row_to_deployment(dep_row))
            await db.commit()
        return result

    async def rollback(self, node_id: str) -> Deployment | None:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row is None:
                return None
            # find previous successful deployment
            result = await db.execute(
                select(ClusterDeploymentRow)
                .where(ClusterDeploymentRow.node_id == node_id)
                .where(ClusterDeploymentRow.config_content.isnot(None))
                .order_by(ClusterDeploymentRow.created_at.desc())
                .limit(2)
            )
            history = list(result.scalars())
            if len(history) < 2:
                return None
            prev = history[1]
            content = prev.config_content
            row.version_counter += 1
            new_version = row.version_counter
            row.desired_config = (content or "").rstrip("\n") + "\n"
            row.pending_version = new_version
            dep_row = ClusterDeploymentRow(
                id="dep_" + uuid.uuid4().hex[:10], node_id=node_id,
                version=new_version, config_hash=config_hash(content),
                status="pending", created_at=_now(),
                message=f"rollback to config of version {prev.version}",
                config_content=content,
            )
            db.add(dep_row)
            await db.commit()
            return _row_to_deployment(dep_row)

    async def set_action(self, node_id: str, action_type: str, params: dict) -> dict:
        """Queue an action for a node.  Delivered on its next heartbeat."""
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row is None:
                raise KeyError(node_id)
            action = {"type": action_type, "params": params}
            row.pending_action = action
            await db.commit()
            return action

    async def set_deploy_status(self, node_id: str, status: str) -> None:
        async with self._sf() as db:
            row = await db.get(ClusterNodeRow, node_id)
            if row:
                row.deploy_status = status
                await db.commit()

    async def overview(self) -> ClusterOverview:
        nodes = await self.list_nodes()
        ov = ClusterOverview(total=len(nodes))
        hashes: set[str] = set()
        for n in nodes:
            if n.status == "online":
                ov.online += 1
            elif n.status == "offline":
                ov.offline += 1
            else:
                ov.pending += 1
            if n.pending_version and n.applied_version != n.pending_version:
                ov.pending_deploys += 1
            if n.haproxy_version:
                ov.haproxy_versions[n.haproxy_version] = (
                    ov.haproxy_versions.get(n.haproxy_version, 0) + 1
                )
            if n.agent_version:
                ov.agent_versions[n.agent_version] = (
                    ov.agent_versions.get(n.agent_version, 0) + 1
                )
            if n.config_hash:
                hashes.add(n.config_hash)
        ov.distinct_config_hashes = len(hashes)
        return ov
