"""Models for RBAC and the audit log."""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field

# viewer (read) < operator (deploy/fix) < admin (manage everyone)
ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


class Principal(BaseModel):
    name: str
    role: str  # viewer | operator | admin


class PrincipalInput(BaseModel):
    name: str
    role: str = "viewer"


class PrincipalCreated(BaseModel):
    principal: Principal
    token: str  # shown once; only a hash is stored


class AuditEntry(BaseModel):
    id: int
    actor: str
    role: str
    action: str
    target: str | None = None
    status: str = "ok"  # ok | denied | error
    detail: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
