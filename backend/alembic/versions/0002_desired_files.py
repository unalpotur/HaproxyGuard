"""Add cluster_nodes.desired_files for shipping auxiliary files with a deploy.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-13
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cluster_nodes",
        sa.Column("desired_files", sa.JSON, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cluster_nodes", "desired_files")
