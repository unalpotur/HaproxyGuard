"""SQLAlchemy 2.x ORM table definitions for HAProxy Guard.

All persistent state lives here. Pydantic models (in the individual module
``models.py`` files) remain unchanged — the ORM rows are mapped to/from them
in the respective Store / Registry classes.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime, ForeignKey, Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Use JSONB on PostgreSQL, plain JSON elsewhere (SQLite/tests).
_JSON = JSONB().with_variant(JSON(), "sqlite")


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# RBAC — principals & tokens
# ---------------------------------------------------------------------------

class PrincipalRow(Base):
    __tablename__ = "principals"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)

    tokens: Mapped[list[TokenRow]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )


class TokenRow(Base):
    __tablename__ = "principal_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    principal_name: Mapped[str] = mapped_column(
        ForeignKey("principals.name", ondelete="CASCADE"), nullable=False
    )

    principal: Mapped[PrincipalRow] = relationship(back_populates="tokens")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(128))
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="ok")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


# ---------------------------------------------------------------------------
# Config versioning (Phase 5.5)
# ---------------------------------------------------------------------------

class ConfigVersionRow(Base):
    """Metadata row — content stored separately to keep list queries light."""
    __tablename__ = "config_versions"

    # seq is the autoincrement PK; external id = f"v{seq}"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(256), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(128), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    content_hash: Mapped[str] = mapped_column(String(32))
    size: Mapped[int] = mapped_column(Integer)
    parent_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)

    content_row: Mapped[ConfigContentRow] = relationship(
        back_populates="version", cascade="all, delete-orphan"
    )


class ConfigContentRow(Base):
    """Large text stored in a separate table."""
    __tablename__ = "config_contents"

    version_seq: Mapped[int] = mapped_column(
        ForeignKey("config_versions.seq", ondelete="CASCADE"), primary_key=True
    )
    content: Mapped[str] = mapped_column(Text)

    version: Mapped[ConfigVersionRow] = relationship(back_populates="content_row")


# ---------------------------------------------------------------------------
# Auto-fix rollback snapshots (Phase 5)
# ---------------------------------------------------------------------------

class FixVersionRow(Base):
    __tablename__ = "fix_versions"

    version_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    content: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------------------
# Alert channels (Phase 9.5)
# ---------------------------------------------------------------------------

class AlertChannelRow(Base):
    __tablename__ = "alert_channels"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(32))   # webhook | slack
    url: Mapped[str] = mapped_column(Text)
    min_severity: Mapped[str] = mapped_column(String(16), default="high")


# ---------------------------------------------------------------------------
# Multi-node cluster (Phase 9)
# ---------------------------------------------------------------------------

class ClusterNodeRow(Base):
    __tablename__ = "cluster_nodes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    address: Mapped[str] = mapped_column(String(256))
    labels: Mapped[dict] = mapped_column(_JSON, default=dict)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    haproxy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pending_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    applied_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metrics: Mapped[dict] = mapped_column(_JSON, default=dict)
    token_hash: Mapped[str] = mapped_column(String(64))
    version_counter: Mapped[int] = mapped_column(Integer, default=0)
    desired_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    # auxiliary files (certs, maps, errorfiles) to write before applying config
    desired_files: Mapped[dict | None] = mapped_column(_JSON, nullable=True)
    pending_action: Mapped[dict | None] = mapped_column(_JSON, nullable=True)
    ssh_host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ssh_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ssh_password: Mapped[str | None] = mapped_column(String(512), nullable=True)
    deploy_status: Mapped[str] = mapped_column(String(32), default="pending")
    service_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_action_result: Mapped[dict | None] = mapped_column(_JSON, nullable=True)

    deployments: Mapped[list[ClusterDeploymentRow]] = relationship(
        back_populates="node", cascade="all, delete-orphan",
        order_by="ClusterDeploymentRow.created_at",
    )


class ClusterDeploymentRow(Base):
    __tablename__ = "cluster_deployments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[str] = mapped_column(
        ForeignKey("cluster_nodes.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer)
    config_hash: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))   # pending | applied | failed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    message: Mapped[str] = mapped_column(Text, default="")
    findings_summary: Mapped[dict] = mapped_column(_JSON, default=dict)
    # stored for rollback; None for failed deployments
    config_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    node: Mapped[ClusterNodeRow] = relationship(back_populates="deployments")
