"""Initial schema — all tables.

Revision ID: 0001
Revises:
Create Date: 2026-06-12
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # principals
    op.create_table(
        "principals",
        sa.Column("name", sa.String(128), primary_key=True),
        sa.Column("role", sa.String(32), nullable=False),
    )

    # principal_tokens
    op.create_table(
        "principal_tokens",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "principal_name",
            sa.String(128),
            sa.ForeignKey("principals.name", ondelete="CASCADE"),
            nullable=False,
        ),
    )

    # audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # config_versions
    op.create_table(
        "config_versions",
        sa.Column("seq", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("label", sa.String(256), nullable=False, server_default=""),
        sa.Column("message", sa.Text, nullable=False, server_default=""),
        sa.Column("author", sa.String(128), nullable=False, server_default="anonymous"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_hash", sa.String(32), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("parent_seq", sa.Integer, nullable=True),
    )

    # config_contents
    op.create_table(
        "config_contents",
        sa.Column(
            "version_seq",
            sa.Integer,
            sa.ForeignKey("config_versions.seq", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("content", sa.Text, nullable=False),
    )

    # fix_versions
    op.create_table(
        "fix_versions",
        sa.Column("version_id", sa.String(32), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("note", sa.Text, nullable=False, server_default=""),
    )

    # alert_channels
    op.create_table(
        "alert_channels",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("min_severity", sa.String(16), nullable=False, server_default="high"),
    )

    # cluster_nodes
    op.create_table(
        "cluster_nodes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("address", sa.String(256), nullable=False),
        sa.Column("labels", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("agent_version", sa.String(64), nullable=True),
        sa.Column("haproxy_version", sa.String(64), nullable=True),
        sa.Column("config_hash", sa.String(32), nullable=True),
        sa.Column("pending_version", sa.Integer, nullable=True),
        sa.Column("applied_version", sa.Integer, nullable=True),
        sa.Column("metrics", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("version_counter", sa.Integer, nullable=False, server_default="0"),
        sa.Column("desired_config", sa.Text, nullable=True),
    )

    # cluster_deployments
    op.create_table(
        "cluster_deployments",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "node_id",
            sa.String(64),
            sa.ForeignKey("cluster_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("config_hash", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("message", sa.Text, nullable=False, server_default=""),
        sa.Column("findings_summary", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("config_content", sa.Text, nullable=True),
    )
    op.create_index("ix_cluster_deployments_node_id", "cluster_deployments", ["node_id"])


def downgrade() -> None:
    op.drop_table("cluster_deployments")
    op.drop_table("cluster_nodes")
    op.drop_table("alert_channels")
    op.drop_table("fix_versions")
    op.drop_table("config_contents")
    op.drop_table("config_versions")
    op.drop_table("audit_log")
    op.drop_table("principal_tokens")
    op.drop_table("principals")
